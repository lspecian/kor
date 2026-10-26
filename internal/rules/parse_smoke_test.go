// Modified in this fork: new file.

package rules

import (
	"os"
	"testing"
)

// TestParseRulesFile parses the rules file KOR_RULES_FILE names, when it is
// set.
func TestParseRulesFile(t *testing.T) {
	path := os.Getenv("KOR_RULES_FILE")
	if path == "" {
		t.Skip("set KOR_RULES_FILE to a firestore.rules file")
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(string(src)); err != nil {
		t.Fatalf("parse: %v", err)
	}
}
