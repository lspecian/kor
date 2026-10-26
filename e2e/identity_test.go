// Modified in this fork: new file.

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/identity"
)

const identityProject = "kor-identity-test"

// startBridge serves the sign-in bridge, with "owner" as the admin token the
// Firebase Admin SDKs send to an Auth emulator.
func startBridge(t *testing.T) (string, *auth.Verifier) {
	t.Helper()
	verifier := auth.NewVerifier(auth.Config{AdminTokens: []string{"owner"}})
	bridge, err := identity.New(identity.Config{Project: identityProject, Admins: verifier}, openBackend(t))
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	verifier.AddIssuer(bridge.TrustedIssuer())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bridge.Handle(w, r) {
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, verifier
}

type authClient struct {
	t    *testing.T
	base string
}

func (c authClient) call(method, path, token string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// admin calls the Admin SDK API; client calls the client SDK API.
func (c authClient) admin(op string, body any) (int, map[string]any) {
	return c.call(http.MethodPost, "/identitytoolkit.googleapis.com/v1/projects/"+identityProject+"/accounts"+op, "owner", body)
}

func (c authClient) client(op string, body any) (int, map[string]any) {
	return c.call(http.MethodPost, "/identitytoolkit.googleapis.com/v1/accounts:"+op+"?key=test", "", body)
}

func (c authClient) refresh(token string) (int, map[string]any) {
	return c.call(http.MethodPost, "/securetoken.googleapis.com/v1/token?key=test", "", map[string]any{"grant_type": "refresh_token", "refresh_token": token})
}

func errMessage(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	s, _ := e["message"].(string)
	return s
}

func tokenClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("token payload: %v", err)
	}
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	return claims
}

func TestIdentityAdminAPI(t *testing.T) {
	base, verifier := startBridge(t)
	c := authClient{t: t, base: base}

	code, created := c.admin("", map[string]any{"localId": "ada", "email": "Ada@Example.com", "password": "first-pass", "displayName": "Ada"})
	if code != 200 || created["localId"] != "ada" {
		t.Fatalf("createUser: %d %v", code, created)
	}
	if code, body := c.admin("", map[string]any{"localId": "ada"}); code != 400 || errMessage(body) != "DUPLICATE_LOCAL_ID" {
		t.Fatalf("duplicate uid: %d %v", code, body)
	}
	if code, body := c.admin("", map[string]any{"email": "ada@example.com"}); code != 400 || errMessage(body) != "EMAIL_EXISTS" {
		t.Fatalf("duplicate email: %d %v", code, body)
	}

	t.Run("lookup by uid and email", func(t *testing.T) {
		for _, q := range []map[string]any{{"localId": []string{"ada"}}, {"email": []string{"ada@example.com"}}} {
			code, body := c.admin(":lookup", q)
			users, _ := body["users"].([]any)
			if code != 200 || len(users) != 1 || users[0].(map[string]any)["displayName"] != "Ada" {
				t.Fatalf("lookup %v: %d %v", q, code, body)
			}
		}
		// The SDKs map a response without users to user-not-found.
		if _, body := c.admin(":lookup", map[string]any{"localId": []string{"nobody"}}); body["users"] != nil {
			t.Fatalf("lookup of a missing user returned %v", body)
		}
	})

	t.Run("only admins reach the admin API", func(t *testing.T) {
		_, signed := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "first-pass"})
		idToken, _ := signed["idToken"].(string)
		for _, tok := range []string{"", idToken} {
			code, _ := c.call(http.MethodPost, "/identitytoolkit.googleapis.com/v1/projects/"+identityProject+"/accounts:lookup", tok, map[string]any{"localId": []string{"ada"}})
			if code != 403 {
				t.Fatalf("non-admin lookup: HTTP %d", code)
			}
		}
	})

	t.Run("custom claims reach new and refreshed ID tokens", func(t *testing.T) {
		_, signed := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "first-pass"})
		if code, body := c.admin(":update", map[string]any{"localId": "ada", "customAttributes": `{"role":"admin","tenant":"t1"}`}); code != 200 {
			t.Fatalf("setCustomUserClaims: %d %v", code, body)
		}
		code, refreshed := c.refresh(signed["refreshToken"].(string))
		if code != 200 {
			t.Fatalf("refresh: %d %v", code, refreshed)
		}
		claims := tokenClaims(t, refreshed["id_token"].(string))
		if claims["role"] != "admin" || claims["tenant"] != "t1" || claims["sub"] != "ada" {
			t.Fatalf("refreshed claims: %v", claims)
		}
		// The Node Admin SDK's revocation check compares auth_time, which
		// Firebase keeps at the sign-in time across refreshes.
		if first := tokenClaims(t, signed["idToken"].(string)); claims["auth_time"] != first["auth_time"] {
			t.Fatalf("auth_time changed on refresh: %v -> %v", first["auth_time"], claims["auth_time"])
		}
		p, err := verifier.Authenticate(context.Background(), refreshed["id_token"].(string))
		if err != nil || p.UID != "ada" || p.Claims["role"] != "admin" {
			t.Fatalf("Kor verifier on refreshed token: %v %v", p, err)
		}
		if code, body := c.admin(":update", map[string]any{"localId": "ada", "customAttributes": `{"sub":"x"}`}); code != 400 || !strings.HasPrefix(errMessage(body), "FORBIDDEN_CLAIM") {
			t.Fatalf("reserved claim accepted: %d %v", code, body)
		}
	})

	t.Run("disabled users cannot sign in or refresh", func(t *testing.T) {
		_, signed := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "first-pass"})
		c.admin(":update", map[string]any{"localId": "ada", "disableUser": true})
		if code, body := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "first-pass"}); code != 400 || errMessage(body) != "USER_DISABLED" {
			t.Fatalf("disabled sign-in: %d %v", code, body)
		}
		if code, body := c.refresh(signed["refreshToken"].(string)); code != 400 || errMessage(body) != "USER_DISABLED" {
			t.Fatalf("disabled refresh: %d %v", code, body)
		}
		c.admin(":update", map[string]any{"localId": "ada", "disableUser": false})
	})

	t.Run("revoking refresh tokens", func(t *testing.T) {
		_, signed := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "first-pass"})
		// revokeRefreshTokens sets validSince to now (seconds); tokens issued
		// in an earlier second are revoked.
		time.Sleep(1100 * time.Millisecond)
		c.admin(":update", map[string]any{"localId": "ada", "validSince": time.Now().Unix()})
		if code, body := c.refresh(signed["refreshToken"].(string)); code != 400 || errMessage(body) != "TOKEN_EXPIRED" {
			t.Fatalf("revoked refresh: %d %v", code, body)
		}
		_, body := c.admin(":lookup", map[string]any{"localId": []string{"ada"}})
		if v := body["users"].([]any)[0].(map[string]any)["validSince"]; v == nil {
			t.Fatalf("lookup lacks validSince (the SDKs' revocation check reads it): %v", body)
		}
		if code, _ := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "first-pass"}); code != 200 {
			t.Fatalf("sign-in after revocation: %d", code)
		}
	})

	t.Run("password reset link", func(t *testing.T) {
		code, body := c.admin(":sendOobCode", map[string]any{"requestType": "PASSWORD_RESET", "email": "ada@example.com", "returnOobLink": true})
		link, _ := body["oobLink"].(string)
		if code != 200 || link == "" {
			t.Fatalf("generatePasswordResetLink: %d %v", code, body)
		}
		u, _ := url.Parse(link)
		oob := u.Query().Get("oobCode")
		if code, body := c.client("resetPassword", map[string]any{"oobCode": oob}); code != 200 || body["email"] != "ada@example.com" {
			t.Fatalf("verifyPasswordResetCode: %d %v", code, body)
		}
		if code, body := c.client("resetPassword", map[string]any{"oobCode": oob, "newPassword": "second-pass"}); code != 200 {
			t.Fatalf("confirmPasswordReset: %d %v", code, body)
		}
		if code, _ := c.client("signInWithPassword", map[string]any{"email": "ada@example.com", "password": "second-pass"}); code != 200 {
			t.Fatalf("sign-in with the new password: %d", code)
		}
		if code, body := c.client("resetPassword", map[string]any{"oobCode": oob, "newPassword": "third-pass"}); code != 400 || errMessage(body) != "INVALID_OOB_CODE" {
			t.Fatalf("reused code: %d %v", code, body)
		}
	})

	t.Run("list users in pages", func(t *testing.T) {
		c.admin("", map[string]any{"localId": "bob", "email": "bob@example.com"})
		c.admin("", map[string]any{"localId": "cy"})
		var seen []string
		token := ""
		for page := 0; page < 5; page++ {
			code, body := c.call(http.MethodGet, "/identitytoolkit.googleapis.com/v1/projects/"+identityProject+"/accounts:batchGet?maxResults=2&nextPageToken="+token, "owner", nil)
			if code != 200 {
				t.Fatalf("listUsers: %d %v", code, body)
			}
			for _, u := range body["users"].([]any) {
				seen = append(seen, u.(map[string]any)["localId"].(string))
			}
			next, _ := body["nextPageToken"].(string)
			if next == "" {
				break
			}
			token = next
		}
		if strings.Join(seen, ",") != "ada,bob,cy" {
			t.Fatalf("listed %v", seen)
		}
	})

	t.Run("delete users", func(t *testing.T) {
		if code, body := c.admin(":delete", map[string]any{"localId": "bob"}); code != 200 {
			t.Fatalf("deleteUser: %d %v", code, body)
		}
		if code, body := c.admin(":delete", map[string]any{"localId": "bob"}); code != 400 || errMessage(body) != "USER_NOT_FOUND" {
			t.Fatalf("deleting a missing user: %d %v", code, body)
		}
		c.admin(":batchDelete", map[string]any{"localIds": []string{"ada", "cy"}, "force": true})
		_, body := c.admin(":lookup", map[string]any{"localId": []string{"ada", "bob", "cy"}})
		if body["users"] != nil {
			t.Fatalf("users left after delete: %v", body)
		}
	})
}

func TestIdentityEmulatorTokens(t *testing.T) {
	verifier := auth.NewVerifier(auth.Config{AdminTokens: []string{"owner"}, AllowUnsigned: true})
	bridge, err := identity.New(identity.Config{Project: identityProject, Admins: verifier, EmulatorTokens: true}, openBackend(t))
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { bridge.Handle(w, r) }))
	t.Cleanup(srv.Close)
	c := authClient{t: t, base: srv.URL}
	c.admin("", map[string]any{"localId": "eve", "email": "eve@example.com", "password": "eve-pass"})
	_, signed := c.client("signInWithPassword", map[string]any{"email": "eve@example.com", "password": "eve-pass"})
	tok, _ := signed["idToken"].(string)
	// The shape the Node Admin SDK's emulator verifier requires: alg none and
	// an empty signature.
	parts := strings.Split(tok, ".")
	var header map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(raw, &header)
	if len(parts) != 3 || parts[2] != "" || header["alg"] != "none" {
		t.Fatalf("not an emulator token: %q", tok)
	}
	p, err := verifier.Authenticate(context.Background(), tok)
	if err != nil || p.UID != "eve" {
		t.Fatalf("Kor with unsigned tokens allowed: %v %v", p, err)
	}
	// The client SDK's own calls with that token: getting the account after
	// sign-in, and updating the profile.
	if code, body := c.client("lookup", map[string]any{"idToken": tok}); code != 200 {
		t.Fatalf("accounts:lookup with an emulator token: %d %v", code, body)
	}
	if code, body := c.client("update", map[string]any{"idToken": tok, "displayName": "Eve"}); code != 200 || body["displayName"] != "Eve" {
		t.Fatalf("accounts:update with an emulator token: %d %v", code, body)
	}
	strict := auth.NewVerifier(auth.Config{Issuers: []*auth.Issuer{bridge.TrustedIssuer()}})
	if _, err := strict.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("a verifier without unsigned tokens accepted an emulator token")
	}
}
