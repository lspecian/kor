// Modified in this fork: new file.

package backend

import (
	"context"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/protobuf/proto"
)

// Clearer is implemented by backends that can delete every document of a
// database at once: the Firebase emulator's "clear data" endpoint, used by
// test suites between runs. Development only.
type Clearer interface {
	ClearDatabase(ctx context.Context, database string) error
}

// CloneFields deep-copies a document's fields, so applying writes to the copy
// leaves the stored version (a commit's "before" state) untouched.
func CloneFields(fields map[string]*pb.Value) map[string]*pb.Value {
	out := make(map[string]*pb.Value, len(fields))
	for k, v := range fields {
		out[k] = proto.Clone(v).(*pb.Value)
	}
	return out
}
