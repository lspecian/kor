// Modified in this fork: new file.

package backend

import "context"

// Clearer is implemented by backends that can delete every document of a
// database at once: the Firebase emulator's "clear data" endpoint, used by
// test suites between runs. Development only.
type Clearer interface {
	ClearDatabase(ctx context.Context, database string) error
}
