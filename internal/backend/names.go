// Modified in this fork: moved here from package store so every backend shares it.

package backend

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DocPath is a parsed document resource name.
type DocPath struct {
	Name         string // full resource name
	ParentPath   string // resource name of the parent (database root or parent document)
	CollectionID string
	DocID        string
}

// ParseDocumentName validates and splits a document resource name of the form
// projects/{p}/databases/{d}/documents/{coll}/{doc}(/{coll}/{doc})*.
func ParseDocumentName(name string) (DocPath, error) {
	segs := strings.Split(name, "/")
	if len(segs) < 7 || segs[0] != "projects" || segs[2] != "databases" || segs[4] != "documents" {
		return DocPath{}, status.Errorf(codes.InvalidArgument, "invalid document name %q", name)
	}
	rel := segs[5:]
	if len(rel)%2 != 0 {
		return DocPath{}, status.Errorf(codes.InvalidArgument, "document name %q refers to a collection", name)
	}
	for _, s := range rel {
		if s == "" {
			return DocPath{}, status.Errorf(codes.InvalidArgument, "document name %q has empty segment", name)
		}
	}
	parent := strings.Join(segs[:len(segs)-2], "/")
	return DocPath{
		Name:         name,
		ParentPath:   parent,
		CollectionID: segs[len(segs)-2],
		DocID:        segs[len(segs)-1],
	}, nil
}
