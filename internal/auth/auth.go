// Package auth turns a request's bearer token into a principal: an admin
// (trusted backend services), a verified end user, or anonymous.
//
// End-user tokens are JWTs. RS256 tokens are verified against JWKS key sets,
// which covers Firebase Auth in production, Microsoft Entra ID and any OIDC
// provider, plus the keys of Kor's own sign-in bridge. In development the
// verifier can also accept the unsigned tokens the Firebase emulators issue.
//
// Modified in this fork: this package is new.
package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Principal is who a request acts as.
type Principal struct {
	// Admin requests bypass security rules (backend services).
	Admin bool
	// UID and Claims describe a verified end user; both are empty when the
	// request is anonymous.
	UID    string
	Claims map[string]any
}

// Anonymous reports whether the request carries no user identity.
func (p *Principal) Anonymous() bool { return p == nil || (!p.Admin && p.UID == "") }

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request's principal, or nil when none was set.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// Issuer is one accepted token issuer.
type Issuer struct {
	// Issuer is the required iss claim.
	Issuer string
	// Audiences are accepted aud values; empty accepts any.
	Audiences []string
	// JWKSURL is fetched (and cached) for RS256 keys. Keys may be given
	// directly instead.
	JWKSURL string
	Keys    map[string]*rsa.PublicKey
	// UIDClaim names the claim holding the user id (default "sub").
	UIDClaim string
}

// Config configures a Verifier.
type Config struct {
	// Disabled treats every request as admin: Kor's original behaviour.
	Disabled bool
	// AdminTokens are bearer values that act as admin (for example the
	// emulator convention "owner", or a service key).
	AdminTokens []string
	// AllowUnsigned accepts alg "none" tokens (Firebase emulator tokens).
	// Development only.
	AllowUnsigned bool
	Issuers       []*Issuer
}

// Verifier authenticates bearer tokens.
type Verifier struct {
	cfg    Config
	admins map[string]bool

	mu   sync.Mutex
	jwks map[string]*jwksCache
}

type jwksCache struct {
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// NewVerifier returns a verifier for cfg.
func NewVerifier(cfg Config) *Verifier {
	v := &Verifier{cfg: cfg, admins: map[string]bool{}, jwks: map[string]*jwksCache{}}
	for _, t := range cfg.AdminTokens {
		if t != "" {
			v.admins[t] = true
		}
	}
	return v
}

// AddIssuer accepts tokens from another issuer (used by the sign-in bridge
// to trust its own keys).
func (v *Verifier) AddIssuer(iss *Issuer) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cfg.Issuers = append(v.cfg.Issuers, iss)
}

// Enabled reports whether requests are authenticated at all.
func (v *Verifier) Enabled() bool { return v != nil && !v.cfg.Disabled }

// Authenticate maps a bearer token (without the "Bearer " prefix; empty for
// none) to a principal.
func (v *Verifier) Authenticate(ctx context.Context, token string) (*Principal, error) {
	if !v.Enabled() {
		return &Principal{Admin: true}, nil
	}
	if token == "" {
		return &Principal{}, nil
	}
	if v.admins[token] {
		return &Principal{Admin: true}, nil
	}
	claims, err := v.verifyJWT(ctx, token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}
	return &Principal{UID: claims.uid, Claims: claims.all}, nil
}

// BearerToken extracts the token from an Authorization header value.
func BearerToken(header string) string {
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

type verified struct {
	uid string
	all map[string]any
}

func (v *Verifier) verifyJWT(ctx context.Context, token string) (*verified, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	claims := map[string]any{}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	iss, _ := claims["iss"].(string)

	switch header.Alg {
	case "none":
		if !v.cfg.AllowUnsigned {
			return nil, errors.New("unsigned tokens are not accepted")
		}
		// Emulator tooling mints these with fixed 1970 times (iat 0, exp
		// 3600), and the Firebase emulator ignores them; so do we.
		delete(claims, "exp")
		delete(claims, "nbf")
		return checkClaims(claims, nil)
	case "RS256":
		issuer := v.issuer(iss)
		if issuer == nil {
			return nil, fmt.Errorf("issuer %q is not trusted", iss)
		}
		key, err := v.key(ctx, issuer, header.Kid)
		if err != nil {
			return nil, err
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, errors.New("bad signature encoding")
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
			return nil, errors.New("signature does not verify")
		}
		return checkClaims(claims, issuer)
	default:
		return nil, fmt.Errorf("unsupported alg %q", header.Alg)
	}
}

func (v *Verifier) issuer(iss string) *Issuer {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, i := range v.cfg.Issuers {
		if i.Issuer == iss {
			return i
		}
	}
	return nil
}

func checkClaims(claims map[string]any, issuer *Issuer) (*verified, error) {
	now := time.Now().Unix()
	if exp, ok := number(claims["exp"]); ok && now > exp+60 {
		return nil, errors.New("token expired")
	}
	if nbf, ok := number(claims["nbf"]); ok && now+60 < nbf {
		return nil, errors.New("token not yet valid")
	}
	uidClaim := "sub"
	if issuer != nil {
		if len(issuer.Audiences) > 0 && !audienceMatches(claims["aud"], issuer.Audiences) {
			return nil, errors.New("audience not accepted")
		}
		if issuer.UIDClaim != "" {
			uidClaim = issuer.UIDClaim
		}
	}
	uid, _ := claims[uidClaim].(string)
	if uid == "" {
		uid, _ = claims["user_id"].(string)
	}
	if uid == "" {
		return nil, fmt.Errorf("token has no %s claim", uidClaim)
	}
	return &verified{uid: uid, all: claims}, nil
}

func audienceMatches(aud any, accepted []string) bool {
	var got []string
	switch a := aud.(type) {
	case string:
		got = []string{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				got = append(got, s)
			}
		}
	}
	for _, g := range got {
		for _, want := range accepted {
			if g == want {
				return true
			}
		}
	}
	return false
}

func number(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func decodeSegment(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// jwksTTL is how long a fetched key set is trusted before refetching.
const jwksTTL = time.Hour

func (v *Verifier) key(ctx context.Context, iss *Issuer, kid string) (*rsa.PublicKey, error) {
	if k, ok := iss.Keys[kid]; ok {
		return k, nil
	}
	if iss.JWKSURL == "" {
		return nil, fmt.Errorf("no key %q for issuer %q", kid, iss.Issuer)
	}
	v.mu.Lock()
	c := v.jwks[iss.JWKSURL]
	v.mu.Unlock()
	if c == nil || time.Since(c.fetched) > jwksTTL || c.keys[kid] == nil {
		keys, err := fetchJWKS(ctx, iss.JWKSURL)
		if err != nil {
			return nil, err
		}
		c = &jwksCache{keys: keys, fetched: time.Now()}
		v.mu.Lock()
		v.jwks[iss.JWKSURL] = c
		v.mu.Unlock()
	}
	if k := c.keys[kid]; k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("no key %q in %s", kid, iss.JWKSURL)
}

// JWK is one RSA key in a JWKS document.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// PublicKeyToJWK encodes an RSA public key for a JWKS document.
func PublicKeyToJWK(kid string, k *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

func fetchJWKS(ctx context.Context, url string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	var doc struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return keys, nil
}
