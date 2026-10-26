// Modified in this fork: new file.

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
)

const testDB = "projects/p/databases/(default)/documents/"

func str(s string) *pb.Value { return &pb.Value{ValueType: &pb.Value_StringValue{StringValue: s}} }

func lookupFrom(docs map[string]*Doc) Lookup {
	return func(name string) (*Doc, error) { return docs[name], nil }
}

// A ruleset in the style real apps write: role lookups through get(),
// per-user documents keyed by a hash of the caller's email, and updates
// limited to some keys with diff().affectedKeys().hasOnly().
const sampleRules = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    function profile() { return get(/databases/$(database)/documents/profiles/$(request.auth.uid)).data; }
    function isEditor() { return signedIn() && profile().role in ['editor', 'owner']; }
    function emailKey() { return hashing.sha256(request.auth.token.email.lower()).toHexString().lower(); }

    match /settings/{service}/members/{key} {
      allow read: if signedIn() && key == emailKey();
      allow update: if signedIn() && key == emailKey()
        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['preferences', 'updated_at']);
    }
    match /articles/{id} {
      allow read: if signedIn();
      allow write: if isEditor();
    }
  }
}`

func sample(t *testing.T) *Ruleset {
	t.Helper()
	rs, err := Parse(sampleRules)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rs
}

func caller(uid, email string) *Auth {
	return &Auth{UID: uid, Token: map[string]any{"email": email, "firebase": map[string]any{"sign_in_provider": "password"}}}
}

func TestUpdateLimitedToSomeKeys(t *testing.T) {
	rs := sample(t)
	sum := sha256.Sum256([]byte("ada@example.com"))
	name := testDB + "settings/mail/members/" + hex.EncodeToString(sum[:])
	before := &Doc{Name: name, Fields: map[string]*pb.Value{"preferences": str("x")}}
	req := &Request{
		Method: "update", Name: name, Resource: before, Time: time.Now(),
		NewResource: &Doc{Name: name, Fields: map[string]*pb.Value{"preferences": str("x"), "status": str("verified")}},
		Auth:        caller("ada", "Ada@Example.com"),
		Lookup:      lookupFrom(nil),
	}
	if ok, err := rs.Allowed(req); err != nil || ok {
		t.Fatalf("adding status: allowed=%v err=%v, want denied", ok, err)
	}
	req.NewResource = &Doc{Name: name, Fields: map[string]*pb.Value{"preferences": str("y")}}
	if ok, err := rs.Allowed(req); err != nil || !ok {
		t.Fatalf("changing preferences only: allowed=%v err=%v, want allowed", ok, err)
	}
	req.Auth = caller("bob", "bob@example.com")
	if ok, _ := rs.Allowed(req); ok {
		t.Fatal("another user's settings: allowed, want denied")
	}
}

func TestRoleLookupThroughGet(t *testing.T) {
	rs := sample(t)
	name := testDB + "articles/a1"
	profiles := map[string]*Doc{
		testDB + "profiles/ed":  {Name: testDB + "profiles/ed", Fields: map[string]*pb.Value{"role": str("editor")}},
		testDB + "profiles/rea": {Name: testDB + "profiles/rea", Fields: map[string]*pb.Value{"role": str("reader")}},
	}
	write := func(uid string) bool {
		ok, _ := rs.Allowed(&Request{
			Method: "create", Name: name, Time: time.Now(),
			NewResource: &Doc{Name: name, Fields: map[string]*pb.Value{"title": str("t")}},
			Auth:        caller(uid, uid+"@example.com"), Lookup: lookupFrom(profiles),
		})
		return ok
	}
	if !write("ed") {
		t.Fatal("editor create: denied, want allowed")
	}
	if write("rea") {
		t.Fatal("reader create: allowed, want denied")
	}
	if write("nobody") {
		t.Fatal("caller without a profile: allowed, want denied")
	}
	if ok, _ := rs.Allowed(&Request{Method: "get", Name: name, Time: time.Now(), Lookup: lookupFrom(profiles)}); ok {
		t.Fatal("anonymous read: allowed, want denied")
	}
}
