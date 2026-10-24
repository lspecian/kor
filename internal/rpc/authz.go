// Modified in this fork: new file.

package rpc

import (
	"context"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/query"
	"github.com/omelas-tech/kor/internal/rules"
)

// Security rules apply to end-user requests. Admin principals (backend
// services) bypass them, as the Firebase Admin SDK does, and a request with
// no principal at all (authentication not configured) keeps upstream Kor's
// behaviour of full access.

type rulesRegistry struct {
	mu         sync.RWMutex
	byProject  map[string]*rules.Ruleset
	defaultSet *rules.Ruleset
}

// SetDefaultRules applies a rules file to every project without its own.
func (s *Server) SetDefaultRules(src string) error {
	rs, err := rules.Parse(src)
	if err != nil {
		return err
	}
	s.rules.mu.Lock()
	s.rules.defaultSet = rs
	s.rules.mu.Unlock()
	return nil
}

// SetProjectRules replaces the rules of one project (the emulator's
// "load rules" endpoint).
func (s *Server) SetProjectRules(project, src string) error {
	rs, err := rules.Parse(src)
	if err != nil {
		return err
	}
	s.rules.mu.Lock()
	if s.rules.byProject == nil {
		s.rules.byProject = map[string]*rules.Ruleset{}
	}
	s.rules.byProject[project] = rs
	s.rules.mu.Unlock()
	return nil
}

func (s *Server) rulesFor(name string) *rules.Ruleset {
	project := ""
	if parts := strings.SplitN(name, "/", 3); len(parts) >= 2 {
		project = parts[1]
	}
	s.rules.mu.RLock()
	defer s.rules.mu.RUnlock()
	if rs := s.rules.byProject[project]; rs != nil {
		return rs
	}
	return s.rules.defaultSet
}

// enforced reports whether ctx is an end-user request rules must check.
func enforced(ctx context.Context) (*auth.Principal, bool) {
	p := auth.FromContext(ctx)
	if p == nil || p.Admin {
		return nil, false
	}
	return p, true
}

var errDenied = status.Error(codes.PermissionDenied, "Missing or insufficient permissions.")

// allowed checks one access. before is the stored document; after is the
// written document for create/update.
func (s *Server) allowed(ctx context.Context, p *auth.Principal, method, name string, before, after *backend.Doc) error {
	rs := s.rulesFor(name)
	if rs == nil {
		return errDenied
	}
	req := &rules.Request{
		Method:      method,
		Name:        name,
		Resource:    rulesDoc(before),
		NewResource: rulesDoc(after),
		Time:        time.Now().UTC(),
		Lookup: func(n string) (*rules.Doc, error) {
			docs, err := s.store.GetDocuments(ctx, []string{n})
			if err != nil {
				return nil, err
			}
			return rulesDoc(docs[n]), nil
		},
	}
	if !p.Anonymous() {
		req.Auth = &rules.Auth{UID: p.UID, Token: p.Claims}
	}
	ok, err := rs.Allowed(req)
	if err != nil || !ok {
		return errDenied
	}
	return nil
}

func rulesDoc(d *backend.Doc) *rules.Doc {
	if d == nil {
		return nil
	}
	return &rules.Doc{Name: d.Name, Fields: d.Fields}
}

// checkGet authorizes reading named documents (missing ones too).
func (s *Server) checkGet(ctx context.Context, names []string, docs map[string]*backend.Doc) error {
	p, on := enforced(ctx)
	if !on {
		return nil
	}
	for _, name := range names {
		if err := s.allowed(ctx, p, "get", name, docs[name], nil); err != nil {
			return err
		}
	}
	return nil
}

// checkList authorizes a query by checking every document it returns. That
// never returns a document the rules deny; unlike Firestore's static
// analysis, a query whose results all pass is allowed.
func (s *Server) checkList(ctx context.Context, docs []*backend.Doc) error {
	p, on := enforced(ctx)
	if !on {
		return nil
	}
	for _, d := range docs {
		if err := s.allowed(ctx, p, "list", d.Name, d, nil); err != nil {
			return err
		}
	}
	return nil
}

// checkQuery runs a query only to authorize it (aggregations).
func (s *Server) checkQuery(ctx context.Context, q *query.Query) error {
	if _, on := enforced(ctx); !on {
		return nil
	}
	if err := s.checkQueryRule(ctx, q); err != nil {
		return err
	}
	var docs []*backend.Doc
	if err := s.store.RunQuery(ctx, q, func(d *backend.Doc) error { docs = append(docs, d); return nil }); err != nil {
		return err
	}
	return s.checkList(ctx, docs)
}

// withWriteChecks makes the backend check every document a commit changes.
func (s *Server) withWriteChecks(ctx context.Context) context.Context {
	p, on := enforced(ctx)
	if !on {
		return ctx
	}
	return backend.WithCommitCheck(ctx, func(ctx context.Context, name string, before, after *backend.Doc) error {
		method := "update"
		switch {
		case before == nil && after != nil:
			method = "create"
		case after == nil:
			method = "delete"
		}
		return s.allowed(ctx, p, method, name, before, after)
	})
}

// adminOnly rejects end users from calls rules do not cover.
func adminOnly(ctx context.Context) error {
	if _, on := enforced(ctx); on {
		return errDenied
	}
	return nil
}

// checkQueryRule evaluates a query's list rule against a stand-in document
// built from the query's equality filters, the way Firestore requires a
// query to be safe for every document it could return: a rule that cannot
// hold (for example a caller who is not a member) denies even an empty
// result, and a rule keyed on a filtered field (user_email == me) allows a
// properly constrained query.
func (s *Server) checkQueryRule(ctx context.Context, q *query.Query) error {
	p, on := enforced(ctx)
	if !on {
		return nil
	}
	fields := map[string]*pb.Value{}
	collectEqualities(q.Where, fields)
	name := q.Parent + "/" + q.CollectionID + "/__kor_query__"
	return s.allowed(ctx, p, "list", name, &backend.Doc{Name: name, Fields: fields}, nil)
}

// collectEqualities records field == value filters of an AND-only filter tree.
func collectEqualities(f *pb.StructuredQuery_Filter, into map[string]*pb.Value) {
	if f == nil {
		return
	}
	switch t := f.GetFilterType().(type) {
	case *pb.StructuredQuery_Filter_CompositeFilter:
		if t.CompositeFilter.GetOp() != pb.StructuredQuery_CompositeFilter_AND {
			return
		}
		for _, sub := range t.CompositeFilter.GetFilters() {
			collectEqualities(sub, into)
		}
	case *pb.StructuredQuery_Filter_FieldFilter:
		ff := t.FieldFilter
		if ff.GetOp() != pb.StructuredQuery_FieldFilter_EQUAL {
			return
		}
		setPath(into, strings.Split(ff.GetField().GetFieldPath(), "."), ff.GetValue())
	}
}

func setPath(m map[string]*pb.Value, path []string, v *pb.Value) {
	if len(path) == 1 {
		m[path[0]] = v
		return
	}
	child, ok := m[path[0]]
	if !ok || child.GetMapValue() == nil {
		child = &pb.Value{ValueType: &pb.Value_MapValue{MapValue: &pb.MapValue{Fields: map[string]*pb.Value{}}}}
		m[path[0]] = child
	}
	setPath(child.GetMapValue().Fields, path[1:], v)
}
