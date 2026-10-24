// Package identity is Kor's sign-in bridge: the part of the Firebase Auth REST
// API the Firebase JS SDK calls (email/password and custom-token sign-in,
// token refresh, account lookup), served by Kor so a web app keeps using
// Firebase Auth where no Firebase exists. External identity providers (Entra
// ID, any OIDC issuer) sign in through an exchange endpoint that turns a
// verified provider token into a custom token, which the SDK then redeems
// with signInWithCustomToken.
//
// ID tokens are RS256 JWTs in Firebase's shape, signed with the bridge's key
// and published as JWKS, so Kor's own verifier and any backend that trusts the
// JWKS can check them. Users live in a reserved collection that security rules
// never expose to clients; creating one is an ordinary write, so it reaches
// the change feed (and the auth trigger) like any other.
//
// Modified in this fork: this package is new.
package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/query"
)

// UsersCollection holds the bridge's user records.
const UsersCollection = "__kor_auth_users"

const (
	idTokenTTL     = time.Hour
	customTokenTTL = time.Hour
	customTokenAud = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
	signInPassword = "password"
	signInCustom   = "custom"
)

// Config configures the bridge.
type Config struct {
	// Project is the Firebase project id tokens are issued for.
	Project string
	// Database is the Firestore database holding user records
	// (default "(default)").
	Database string
	// Key signs ID and custom tokens; a fresh one is generated when nil.
	Key *rsa.PrivateKey
	// TrustUnsignedCustomTokens accepts custom tokens without verifying their
	// signature, as the Firebase Auth emulator does (development only).
	TrustUnsignedCustomTokens bool
	// Exchange verifies provider tokens for /kor/v1/auth:exchange; nil
	// disables the endpoint.
	Exchange *auth.Verifier
	Log      *slog.Logger
}

// Bridge serves the Firebase Auth endpoints.
type Bridge struct {
	cfg   Config
	store backend.Backend
	kid   string

	mu      sync.Mutex
	refresh map[string]string // refresh token -> uid
}

// New returns a bridge backed by store.
func New(cfg Config, store backend.Backend) (*Bridge, error) {
	if cfg.Project == "" {
		return nil, errors.New("identity: project is required")
	}
	if cfg.Database == "" {
		cfg.Database = "(default)"
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Key == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		cfg.Key = k
	}
	sum := sha256.Sum256(cfg.Key.PublicKey.N.Bytes())
	return &Bridge{cfg: cfg, store: store, kid: hex.EncodeToString(sum[:8]), refresh: map[string]string{}}, nil
}

// Issuer is the iss claim of the bridge's ID tokens.
func (b *Bridge) Issuer() string { return "https://securetoken.google.com/" + b.cfg.Project }

// TrustedIssuer lets an auth.Verifier accept the bridge's ID tokens.
func (b *Bridge) TrustedIssuer() *auth.Issuer {
	return &auth.Issuer{
		Issuer:    b.Issuer(),
		Audiences: []string{b.cfg.Project},
		Keys:      map[string]*rsa.PublicKey{b.kid: &b.cfg.Key.PublicKey},
	}
}

// Handle serves the bridge's routes and reports whether r was one of them.
func (b *Bridge) Handle(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/identitytoolkit.googleapis.com/v1/accounts:"):
		b.accounts(w, r, strings.TrimPrefix(p, "/identitytoolkit.googleapis.com/v1/accounts:"))
	case p == "/securetoken.googleapis.com/v1/token":
		b.token(w, r)
	case p == "/kor/v1/auth:exchange":
		b.exchange(w, r)
	case p == "/kor/v1/jwks" || p == "/.well-known/jwks.json":
		writeJSON(w, http.StatusOK, map[string]any{"keys": []auth.JWK{auth.PublicKeyToJWK(b.kid, &b.cfg.Key.PublicKey)}})
	default:
		return false
	}
	return true
}

// admin is the context the bridge uses for its own store access.
func admin(ctx context.Context) context.Context {
	return auth.WithPrincipal(ctx, &auth.Principal{Admin: true})
}

type user struct {
	UID          string
	Email        string
	DisplayName  string
	PasswordHash string
	Provider     string
	CreatedAt    time.Time
}

func (b *Bridge) docName(uid string) string {
	return fmt.Sprintf("projects/%s/databases/%s/documents/%s/%s", b.cfg.Project, b.cfg.Database, UsersCollection, uid)
}

func (b *Bridge) getUser(ctx context.Context, uid string) (*user, error) {
	name := b.docName(uid)
	docs, err := b.store.GetDocuments(admin(ctx), []string{name})
	if err != nil {
		return nil, err
	}
	d := docs[name]
	if d == nil {
		return nil, nil
	}
	return userFromDoc(uid, d), nil
}

func userFromDoc(uid string, d *backend.Doc) *user {
	s := func(k string) string { return d.Fields[k].GetStringValue() }
	return &user{UID: uid, Email: s("email"), DisplayName: s("displayName"), PasswordHash: s("passwordHash"),
		Provider: s("provider"), CreatedAt: d.CreateTime}
}

func (b *Bridge) userByEmail(ctx context.Context, email string) (*user, error) {
	parent := fmt.Sprintf("projects/%s/databases/%s/documents", b.cfg.Project, b.cfg.Database)
	q, err := query.Parse(parent, &pb.StructuredQuery{
		From: []*pb.StructuredQuery_CollectionSelector{{CollectionId: UsersCollection}},
		Where: &pb.StructuredQuery_Filter{FilterType: &pb.StructuredQuery_Filter_FieldFilter{FieldFilter: &pb.StructuredQuery_FieldFilter{
			Field: &pb.StructuredQuery_FieldReference{FieldPath: "email"},
			Op:    pb.StructuredQuery_FieldFilter_EQUAL,
			Value: &pb.Value{ValueType: &pb.Value_StringValue{StringValue: strings.ToLower(email)}},
		}}},
	})
	if err != nil {
		return nil, err
	}
	var found *user
	err = b.store.RunQuery(admin(ctx), q, func(d *backend.Doc) error {
		parts := strings.Split(d.Name, "/")
		found = userFromDoc(parts[len(parts)-1], d)
		return backend.ErrStop
	})
	return found, err
}

func (b *Bridge) saveUser(ctx context.Context, u *user, mustCreate bool) error {
	str := func(s string) *pb.Value { return &pb.Value{ValueType: &pb.Value_StringValue{StringValue: s}} }
	fields := map[string]*pb.Value{
		"email":       str(strings.ToLower(u.Email)),
		"displayName": str(u.DisplayName),
		"provider":    str(u.Provider),
		"createdAt":   {ValueType: &pb.Value_TimestampValue{TimestampValue: timestamppb.New(u.CreatedAt)}},
	}
	if u.PasswordHash != "" {
		fields["passwordHash"] = str(u.PasswordHash)
	}
	w := &pb.Write{Operation: &pb.Write_Update{Update: &pb.Document{Name: b.docName(u.UID), Fields: fields}}}
	if mustCreate {
		w.CurrentDocument = &pb.Precondition{ConditionType: &pb.Precondition_Exists{Exists: false}}
	}
	_, _, err := b.store.Commit(admin(ctx), []*pb.Write{w})
	return err
}

func newUID() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 28)
	_, _ = rand.Read(buf)
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}

func (b *Bridge) accounts(w http.ResponseWriter, r *http.Request, op string) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && r.ContentLength != 0 {
		authError(w, http.StatusBadRequest, "INVALID_JSON")
		return
	}
	str := func(k string) string { s, _ := body[k].(string); return s }
	ctx := r.Context()
	switch op {
	case "signUp":
		email, password := strings.ToLower(str("email")), str("password")
		u := &user{UID: newUID(), Email: email, DisplayName: str("displayName"), Provider: signInPassword, CreatedAt: time.Now().UTC()}
		if email == "" || password == "" {
			authError(w, http.StatusBadRequest, "MISSING_EMAIL")
			return
		}
		if existing, err := b.userByEmail(ctx, email); err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		} else if existing != nil {
			authError(w, http.StatusBadRequest, "EMAIL_EXISTS")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		u.PasswordHash = string(hash)
		if err := b.saveUser(ctx, u, true); err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		b.signedIn(w, u, signInPassword, nil, true)
	case "signInWithPassword":
		u, err := b.userByEmail(ctx, str("email"))
		if err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		if u == nil || u.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(str("password"))) != nil {
			authError(w, http.StatusBadRequest, "INVALID_LOGIN_CREDENTIALS")
			return
		}
		b.signedIn(w, u, signInPassword, nil, false)
	case "signInWithCustomToken":
		uid, claims, err := b.verifyCustomToken(str("token"))
		if err != nil {
			b.cfg.Log.Warn("custom token rejected", "err", err)
			authError(w, http.StatusBadRequest, "INVALID_CUSTOM_TOKEN")
			return
		}
		u, err := b.getUser(ctx, uid)
		if err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		isNew := u == nil
		if isNew {
			email, _ := claims["email"].(string)
			u = &user{UID: uid, Email: email, Provider: signInCustom, CreatedAt: time.Now().UTC()}
			if err := b.saveUser(ctx, u, true); err != nil {
				authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
				return
			}
		}
		b.signedIn(w, u, signInCustom, claims, isNew)
	case "lookup":
		uid, err := b.uidFromIDToken(ctx, str("idToken"))
		if err != nil {
			authError(w, http.StatusBadRequest, "INVALID_ID_TOKEN")
			return
		}
		u, err := b.getUser(ctx, uid)
		if err != nil || u == nil {
			authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"kind": "identitytoolkit#GetAccountInfoResponse", "users": []any{userInfo(u)}})
	case "update":
		uid, err := b.uidFromIDToken(ctx, str("idToken"))
		if err != nil {
			authError(w, http.StatusBadRequest, "INVALID_ID_TOKEN")
			return
		}
		u, err := b.getUser(ctx, uid)
		if err != nil || u == nil {
			authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
			return
		}
		if v, ok := body["displayName"].(string); ok {
			u.DisplayName = v
		}
		if v := str("password"); v != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(v), bcrypt.DefaultCost)
			if err != nil {
				authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
				return
			}
			u.PasswordHash = string(hash)
		}
		if err := b.saveUser(ctx, u, false); err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		info := userInfo(u)
		info["kind"] = "identitytoolkit#SetAccountInfoResponse"
		writeJSON(w, http.StatusOK, info)
	case "sendOobCode":
		// No mail goes out from the bridge; the identity provider owns resets.
		writeJSON(w, http.StatusOK, map[string]any{"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": str("email")})
	default:
		authError(w, http.StatusBadRequest, "OPERATION_NOT_ALLOWED")
	}
}

func userInfo(u *user) map[string]any {
	info := map[string]any{
		"localId":       u.UID,
		"email":         u.Email,
		"emailVerified": u.Provider != signInPassword,
		"displayName":   u.DisplayName,
		"createdAt":     fmt.Sprint(u.CreatedAt.UnixMilli()),
		"lastLoginAt":   fmt.Sprint(time.Now().UnixMilli()),
	}
	if u.PasswordHash != "" {
		info["passwordHash"] = "REDACTED"
		info["providerUserInfo"] = []any{map[string]any{"providerId": "password", "email": u.Email, "federatedId": u.Email, "rawId": u.Email}}
	}
	return info
}

// signedIn answers a successful sign-in with an ID token and refresh token.
func (b *Bridge) signedIn(w http.ResponseWriter, u *user, provider string, extra map[string]any, isNew bool) {
	idToken, err := b.idToken(u, provider, extra)
	if err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	refresh := b.newRefresh(u.UID)
	writeJSON(w, http.StatusOK, map[string]any{
		"kind":         "identitytoolkit#VerifyPasswordResponse",
		"localId":      u.UID,
		"email":        u.Email,
		"displayName":  u.DisplayName,
		"idToken":      idToken,
		"refreshToken": refresh,
		"expiresIn":    fmt.Sprint(int(idTokenTTL.Seconds())),
		"registered":   !isNew,
		"isNewUser":    isNew,
	})
}

func (b *Bridge) newRefresh(uid string) string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	tok := base64.RawURLEncoding.EncodeToString(buf)
	b.mu.Lock()
	b.refresh[tok] = uid
	b.mu.Unlock()
	return tok
}

// token serves securetoken's refresh grant.
func (b *Bridge) token(w http.ResponseWriter, r *http.Request) {
	var refreshToken string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			RefreshToken string `json:"refresh_token"`
			RefreshAlt   string `json:"refreshToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		refreshToken = body.RefreshToken + body.RefreshAlt
	} else {
		_ = r.ParseForm()
		refreshToken = r.Form.Get("refresh_token")
	}
	b.mu.Lock()
	uid, ok := b.refresh[refreshToken]
	b.mu.Unlock()
	if !ok {
		authError(w, http.StatusBadRequest, "INVALID_REFRESH_TOKEN")
		return
	}
	u, err := b.getUser(r.Context(), uid)
	if err != nil || u == nil {
		authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
		return
	}
	idToken, err := b.idToken(u, u.Provider, nil)
	if err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": idToken, "id_token": idToken, "expires_in": fmt.Sprint(int(idTokenTTL.Seconds())),
		"token_type": "Bearer", "refresh_token": refreshToken, "user_id": uid, "project_id": b.cfg.Project,
	})
}

// exchange turns a verified provider token (Entra, OIDC) into a custom token.
func (b *Bridge) exchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || b.cfg.Exchange == nil {
		authError(w, http.StatusNotFound, "EXCHANGE_DISABLED")
		return
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IDToken == "" {
		authError(w, http.StatusBadRequest, "MISSING_ID_TOKEN")
		return
	}
	p, err := b.cfg.Exchange.Authenticate(r.Context(), body.IDToken)
	if err != nil || p.Anonymous() {
		authError(w, http.StatusUnauthorized, "INVALID_PROVIDER_TOKEN")
		return
	}
	iss, _ := p.Claims["iss"].(string)
	sum := sha256.Sum256([]byte(iss + "|" + p.UID))
	uid := "oidc_" + hex.EncodeToString(sum[:14])
	claims := map[string]any{"provider_iss": iss, "provider_sub": p.UID}
	for _, k := range []string{"email", "preferred_username", "name", "oid", "tid"} {
		if v, ok := p.Claims[k]; ok {
			claims[k] = v
		}
	}
	if _, ok := claims["email"]; !ok {
		if v, ok := p.Claims["preferred_username"].(string); ok && strings.Contains(v, "@") {
			claims["email"] = v
		}
	}
	tok, err := b.customToken(uid, claims)
	if err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"customToken": tok, "uid": uid})
}

// Tokens.

func (b *Bridge) sign(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": b.kid, "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, b.cfg.Key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (b *Bridge) idToken(u *user, provider string, extra map[string]any) (string, error) {
	now := time.Now().Unix()
	claims := map[string]any{}
	for k, v := range extra {
		claims[k] = v
	}
	identities := map[string]any{}
	if u.Email != "" {
		identities["email"] = []string{u.Email}
		claims["email"] = u.Email
		claims["email_verified"] = provider != signInPassword
	}
	for k, v := range map[string]any{
		"iss": b.Issuer(), "aud": b.cfg.Project, "auth_time": now, "iat": now, "exp": now + int64(idTokenTTL.Seconds()),
		"sub": u.UID, "user_id": u.UID,
		"firebase": map[string]any{"identities": identities, "sign_in_provider": provider},
	} {
		claims[k] = v
	}
	if u.DisplayName != "" {
		claims["name"] = u.DisplayName
	}
	return b.sign(claims)
}

func (b *Bridge) customToken(uid string, claims map[string]any) (string, error) {
	now := time.Now().Unix()
	return b.sign(map[string]any{
		"iss": "kor-identity@" + b.cfg.Project, "sub": "kor-identity@" + b.cfg.Project, "aud": customTokenAud,
		"iat": now, "exp": now + int64(customTokenTTL.Seconds()), "uid": uid, "claims": claims,
	})
}

// verifyCustomToken accepts custom tokens the bridge signed, and any custom
// token when TrustUnsignedCustomTokens is set (as the Firebase Auth emulator
// does, e.g. for tokens a backend minted with its service account).
func (b *Bridge) verifyCustomToken(tok string) (string, map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", nil, errors.New("not a JWT")
	}
	var header struct{ Kid string }
	var claims map[string]any
	if err := decode(parts[0], &header); err != nil {
		return "", nil, err
	}
	if err := decode(parts[1], &claims); err != nil {
		return "", nil, err
	}
	if !b.cfg.TrustUnsignedCustomTokens {
		if header.Kid != b.kid {
			return "", nil, errors.New("custom token not signed by this bridge")
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return "", nil, err
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&b.cfg.Key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			return "", nil, errors.New("bad signature")
		}
		if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
			return "", nil, errors.New("custom token expired")
		}
	}
	uid, _ := claims["uid"].(string)
	if uid == "" {
		return "", nil, errors.New("custom token has no uid")
	}
	extra, _ := claims["claims"].(map[string]any)
	return uid, extra, nil
}

func (b *Bridge) uidFromIDToken(ctx context.Context, tok string) (string, error) {
	v := auth.NewVerifier(auth.Config{Issuers: []*auth.Issuer{b.TrustedIssuer()}})
	p, err := v.Authenticate(ctx, tok)
	if err != nil {
		return "", err
	}
	if p.UID == "" {
		return "", errors.New("no uid")
	}
	return p.UID, nil
}

func decode(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// authError answers in the Firebase Auth error shape the SDK maps to codes.
func authError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{"code": code, "message": message, "errors": []any{map[string]any{"message": message, "reason": "invalid"}}}})
}
