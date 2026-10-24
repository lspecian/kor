// Modified in this fork: new file.

package backend

import "context"

// CommitCheck approves one document change inside a commit. before is the
// stored document (nil when absent); after is the result of the commit's
// writes (nil when the commit deletes it). Returning an error aborts the
// whole commit. Security rules use it to check writes against the exact
// state a commit will store.
type CommitCheck func(ctx context.Context, name string, before, after *Doc) error

type checkKey struct{}

// WithCommitCheck returns ctx carrying a check that backends run on every
// document a commit changes, before anything is stored.
func WithCommitCheck(ctx context.Context, c CommitCheck) context.Context {
	return context.WithValue(ctx, checkKey{}, c)
}

// RunCommitCheck runs the check carried by ctx, if any.
func RunCommitCheck(ctx context.Context, name string, before, after *Doc) error {
	if c, ok := ctx.Value(checkKey{}).(CommitCheck); ok && c != nil {
		return c(ctx, name, before, after)
	}
	return nil
}
