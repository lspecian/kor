// Modified in this fork: this file is new.

package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"golang.org/x/crypto/bcrypt"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/query"
)

const (
	oobTTL           = time.Hour
	maxListPageSize  = 1000
	minPasswordChars = 6
)

// adminAPI serves the user-management API of the Firebase Admin SDKs
// (getUser, getUserByEmail, createUser, updateUser, setCustomUserClaims,
// revokeRefreshTokens, deleteUser(s), listUsers, generate*Link) at
// /identitytoolkit.googleapis.com/v1/projects/{project}/accounts[:op], the
// paths the SDKs use against the Auth emulator.
func (b *Bridge) adminAPI(w http.ResponseWriter, r *http.Request, rest string) {
	project, op, ok := strings.Cut(rest, "/")
	if !ok {
		authError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !b.isAdmin(r) {
		authError(w, http.StatusForbidden, "INSUFFICIENT_PERMISSION")
		return
	}
	if project != b.cfg.Project {
		authError(w, http.StatusBadRequest, "INVALID_PROJECT_ID")
		return
	}
	var body map[string]any
	if r.Method != http.MethodGet {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && r.ContentLength != 0 {
			authError(w, http.StatusBadRequest, "INVALID_JSON")
			return
		}
	}
	ctx := r.Context()
	switch {
	case op == "accounts" && r.Method == http.MethodPost:
		b.adminCreate(w, ctx, body)
	case op == "accounts:lookup":
		var users []any
		for _, uid := range strs(body["localId"]) {
			if u, err := b.getUser(ctx, uid); err == nil && u != nil {
				users = append(users, userInfo(u))
			}
		}
		for _, email := range strs(body["email"]) {
			if u, err := b.userByEmail(ctx, email); err == nil && u != nil {
				users = append(users, userInfo(u))
			}
		}
		resp := map[string]any{"kind": "identitytoolkit#GetAccountInfoResponse"}
		if len(users) > 0 {
			resp["users"] = users
		}
		writeJSON(w, http.StatusOK, resp)
	case op == "accounts:update":
		u, err := b.getUser(ctx, str(body, "localId"))
		if err != nil || u == nil {
			authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
			return
		}
		if code := b.applyUpdate(ctx, u, body); code != "" {
			authError(w, http.StatusBadRequest, code)
			return
		}
		if err := b.saveUser(ctx, u, false); err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		info := userInfo(u)
		info["kind"] = "identitytoolkit#SetAccountInfoResponse"
		writeJSON(w, http.StatusOK, info)
	case op == "accounts:delete":
		uid := str(body, "localId")
		if u, err := b.getUser(ctx, uid); err != nil || u == nil {
			authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
			return
		}
		if err := b.deleteUser(ctx, uid); err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"kind": "identitytoolkit#DeleteAccountResponse"})
	case op == "accounts:batchDelete":
		for _, uid := range strs(body["localIds"]) {
			if err := b.deleteUser(ctx, uid); err != nil {
				authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	case op == "accounts:batchGet" && r.Method == http.MethodGet:
		b.adminList(w, r)
	case op == "accounts:sendOobCode":
		resp, err := b.oobCode(ctx, r, body)
		if err != nil {
			authError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		authError(w, http.StatusNotFound, "OPERATION_NOT_ALLOWED")
	}
}

func (b *Bridge) isAdmin(r *http.Request) bool {
	if b.cfg.Admins == nil {
		return false
	}
	p, err := b.cfg.Admins.Authenticate(r.Context(), auth.BearerToken(r.Header.Get("Authorization")))
	return err == nil && p.Admin
}

func (b *Bridge) adminCreate(w http.ResponseWriter, ctx context.Context, body map[string]any) {
	uid := str(body, "localId")
	if uid == "" {
		uid = newUID()
	} else if len(uid) > 128 {
		authError(w, http.StatusBadRequest, "INVALID_LOCAL_ID")
		return
	} else if existing, err := b.getUser(ctx, uid); err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	} else if existing != nil {
		authError(w, http.StatusBadRequest, "DUPLICATE_LOCAL_ID")
		return
	}
	u := &user{UID: uid, Provider: "admin", CreatedAt: time.Now().UTC()}
	if code := b.applyUpdate(ctx, u, body); code != "" {
		authError(w, http.StatusBadRequest, code)
		return
	}
	if u.PasswordHash != "" {
		u.Provider = signInPassword
	}
	if err := b.saveUser(ctx, u, true); err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	info := userInfo(u)
	info["kind"] = "identitytoolkit#SignupNewUserResponse"
	writeJSON(w, http.StatusOK, info)
}

// applyUpdate applies the fields of a create or update request to u and
// returns an error code, or "" on success.
func (b *Bridge) applyUpdate(ctx context.Context, u *user, body map[string]any) string {
	if v, ok := body["email"].(string); ok {
		v = strings.ToLower(v)
		if v != u.Email && v != "" {
			if !strings.Contains(v, "@") {
				return "INVALID_EMAIL"
			}
			existing, err := b.userByEmail(ctx, v)
			if err != nil {
				return "INTERNAL_ERROR"
			}
			if existing != nil && existing.UID != u.UID {
				return "EMAIL_EXISTS"
			}
		}
		u.Email = v
	}
	if v, ok := body["password"].(string); ok {
		if len(v) < minPasswordChars {
			return "WEAK_PASSWORD : Password should be at least 6 characters"
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(v), bcrypt.DefaultCost)
		if err != nil {
			return "INTERNAL_ERROR"
		}
		u.PasswordHash = string(hash)
	}
	if v, ok := body["displayName"].(string); ok {
		u.DisplayName = v
	}
	if v, ok := body["photoUrl"].(string); ok {
		u.PhotoURL = v
	}
	if v, ok := body["phoneNumber"].(string); ok {
		u.PhoneNumber = v
	}
	if v, ok := body["emailVerified"].(bool); ok {
		u.EmailVerified = v
	}
	// createUser sends "disabled", updateUser "disableUser".
	if v, ok := body["disabled"].(bool); ok {
		u.Disabled = v
	}
	if v, ok := body["disableUser"].(bool); ok {
		u.Disabled = v
	}
	if v, ok := body["customAttributes"].(string); ok {
		var claims map[string]any
		if v != "" && json.Unmarshal([]byte(v), &claims) != nil {
			return "INVALID_CLAIMS"
		}
		for _, reserved := range []string{"iss", "aud", "sub", "iat", "exp", "auth_time", "user_id", "firebase", "nbf", "amr", "at_hash", "cnf", "acr", "azp", "c_hash", "nonce"} {
			if _, ok := claims[reserved]; ok {
				return "FORBIDDEN_CLAIM : " + reserved
			}
		}
		if len(claims) == 0 {
			v = ""
		}
		u.CustomClaims = v
	}
	if v, ok := number(body["validSince"]); ok {
		u.ValidSince = v
	}
	for _, attr := range strs(body["deleteAttribute"]) {
		switch attr {
		case "DISPLAY_NAME":
			u.DisplayName = ""
		case "PHOTO_URL":
			u.PhotoURL = ""
		}
	}
	for _, provider := range strs(body["deleteProvider"]) {
		if provider == "phone" {
			u.PhoneNumber = ""
		}
	}
	return ""
}

func (b *Bridge) deleteUser(ctx context.Context, uid string) error {
	if uid == "" {
		return nil
	}
	if _, _, err := b.store.Commit(admin(ctx), []*pb.Write{{Operation: &pb.Write_Delete{Delete: b.docName(uid)}}}); err != nil {
		return err
	}
	b.mu.Lock()
	for tok, g := range b.refresh {
		if g.uid == uid {
			delete(b.refresh, tok)
		}
	}
	b.mu.Unlock()
	return nil
}

// adminList serves listUsers: pages of users ordered by uid.
func (b *Bridge) adminList(w http.ResponseWriter, r *http.Request) {
	size := maxListPageSize
	if v, err := strconv.Atoi(r.URL.Query().Get("maxResults")); err == nil && v > 0 && v < size {
		size = v
	}
	after := r.URL.Query().Get("nextPageToken")
	parent := fmt.Sprintf("projects/%s/databases/%s/documents", b.cfg.Project, b.cfg.Database)
	q, err := query.Parse(parent, &pb.StructuredQuery{From: []*pb.StructuredQuery_CollectionSelector{{CollectionId: UsersCollection}}})
	if err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	var all []*user
	err = b.store.RunQuery(admin(r.Context()), q, func(d *backend.Doc) error {
		parts := strings.Split(d.Name, "/")
		all = append(all, userFromDoc(parts[len(parts)-1], d))
		return nil
	})
	if err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].UID < all[j].UID })
	users := []any{}
	resp := map[string]any{"kind": "identitytoolkit#DownloadAccountResponse"}
	for _, u := range all {
		if u.UID <= after {
			continue
		}
		if len(users) == size {
			resp["nextPageToken"] = users[len(users)-1].(map[string]any)["localId"]
			break
		}
		users = append(users, userInfo(u))
	}
	resp["users"] = users
	writeJSON(w, http.StatusOK, resp)
}

// oobCode creates an out-of-band code for sendOobCode. Admin callers
// (generatePasswordResetLink, generateEmailVerificationLink) get the link
// back with returnOobLink; for the client SDK the caller logs it.
func (b *Bridge) oobCode(ctx context.Context, r *http.Request, body map[string]any) (map[string]any, error) {
	requestType := str(body, "requestType")
	var u *user
	var err error
	switch requestType {
	case "PASSWORD_RESET":
		u, err = b.userByEmail(ctx, str(body, "email"))
	case "VERIFY_EMAIL":
		if tok := str(body, "idToken"); tok != "" {
			var uid string
			if uid, err = b.uidFromIDToken(ctx, tok); err != nil {
				return nil, errors.New("INVALID_ID_TOKEN")
			}
			u, err = b.getUser(ctx, uid)
		} else {
			u, err = b.userByEmail(ctx, str(body, "email"))
		}
	default:
		return nil, errors.New("OPERATION_NOT_ALLOWED")
	}
	if err != nil {
		return nil, errors.New("INTERNAL_ERROR")
	}
	if u == nil {
		return nil, errors.New("EMAIL_NOT_FOUND")
	}
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	code := base64.RawURLEncoding.EncodeToString(buf)
	b.mu.Lock()
	b.oob[code] = oobGrant{uid: u.UID, requestType: requestType, expires: time.Now().Add(oobTTL)}
	b.mu.Unlock()
	mode := map[string]string{"PASSWORD_RESET": "resetPassword", "VERIFY_EMAIL": "verifyEmail"}[requestType]
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	link := url.URL{Scheme: scheme, Host: r.Host, Path: "/emulator/action", RawQuery: url.Values{
		"mode": {mode}, "oobCode": {code}, "apiKey": {"fake-api-key"}, "lang": {"en"},
	}.Encode()}
	if cont := str(body, "continueUrl"); cont != "" {
		link.RawQuery += "&continueUrl=" + url.QueryEscape(cont)
	}
	return map[string]any{
		"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": u.Email,
		"oobCode": code, "oobLink": link.String(),
	}, nil
}

// takeOob returns the grant of an unexpired code; consume removes it.
func (b *Bridge) takeOob(code, requestType string, consume bool) (oobGrant, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	g, ok := b.oob[code]
	if !ok || g.requestType != requestType || time.Now().After(g.expires) {
		return oobGrant{}, false
	}
	if consume {
		delete(b.oob, code)
	}
	return g, true
}

// resetPassword serves confirmPasswordReset (with newPassword) and
// verifyPasswordResetCode (without).
func (b *Bridge) resetPassword(w http.ResponseWriter, r *http.Request, body map[string]any) {
	newPassword := str(body, "newPassword")
	g, ok := b.takeOob(str(body, "oobCode"), "PASSWORD_RESET", newPassword != "")
	if !ok {
		authError(w, http.StatusBadRequest, "INVALID_OOB_CODE")
		return
	}
	u, err := b.getUser(r.Context(), g.uid)
	if err != nil || u == nil {
		authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
		return
	}
	if newPassword != "" {
		if code := b.applyUpdate(r.Context(), u, map[string]any{"password": newPassword}); code != "" {
			authError(w, http.StatusBadRequest, code)
			return
		}
		if u.Provider != signInPassword && u.Provider != signInCustom {
			u.Provider = signInPassword
		}
		if err := b.saveUser(r.Context(), u, false); err != nil {
			authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": "identitytoolkit#ResetPasswordResponse", "email": u.Email, "requestType": "PASSWORD_RESET"})
}

// applyEmailVerification serves applyActionCode for a VERIFY_EMAIL code.
func (b *Bridge) applyEmailVerification(w http.ResponseWriter, r *http.Request, code string) {
	g, ok := b.takeOob(code, "VERIFY_EMAIL", true)
	if !ok {
		authError(w, http.StatusBadRequest, "INVALID_OOB_CODE")
		return
	}
	u, err := b.getUser(r.Context(), g.uid)
	if err != nil || u == nil {
		authError(w, http.StatusBadRequest, "USER_NOT_FOUND")
		return
	}
	u.EmailVerified = true
	if err := b.saveUser(r.Context(), u, false); err != nil {
		authError(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": "identitytoolkit#SetAccountInfoResponse", "email": u.Email, "emailVerified": true})
}

func str(body map[string]any, k string) string {
	s, _ := body[k].(string)
	return s
}

// strs reads a string or a list of strings.
func strs(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// number reads an integer sent as a JSON number or string.
func number(v any) (int64, bool) {
	switch v := v.(type) {
	case float64:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	}
	return 0, false
}
