// Modified in this fork: new file.

package rpc

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/query"
)

// Live updates (the Listen RPC).
//
// Each stream keeps, per target, the documents it last reported. The backend's
// change feed only says which documents changed; when a change touches a
// target's collection (or one of its documents), the target is re-evaluated
// with the same query engine as RunQuery and only the difference is sent. That
// keeps limit windows, cursors and deletions exact without a separate
// incremental matcher. After each round the stream sends a global NO_CHANGE
// with a read time, which is what makes the SDKs raise a snapshot.

// hub fans the backend's change feed out to every open Listen stream. The
// feed runs only while at least one stream is open.
type hub struct {
	feed backend.ChangeFeed

	mu    sync.Mutex
	subs  map[*subscriber]struct{}
	stop  context.CancelFunc
	ready chan struct{} // closed once the running feed has fixed its position
}

type subscriber struct {
	mu      sync.Mutex
	pending []backend.Change
	resync  bool // re-evaluate every target: the feed restarted and may have a gap
	notify  chan struct{}
}

func newHub(feed backend.ChangeFeed) *hub {
	return &hub{feed: feed, subs: map[*subscriber]struct{}{}}
}

// readyTimeout bounds how long a new stream waits for the feed to start.
const readyTimeout = 10 * time.Second

// subscribe registers a stream and returns once the feed is positioned, so
// any commit after subscribe returns reaches the subscriber.
func (h *hub) subscribe(ctx context.Context) (*subscriber, error) {
	sub := &subscriber{notify: make(chan struct{}, 1)}
	h.mu.Lock()
	h.subs[sub] = struct{}{}
	if h.stop == nil {
		runCtx, cancel := context.WithCancel(context.Background())
		h.stop = cancel
		h.ready = make(chan struct{})
		go h.run(runCtx, h.ready)
	}
	ready := h.ready
	h.mu.Unlock()

	select {
	case <-ready:
		return sub, nil
	case <-ctx.Done():
		h.unsubscribe(sub)
		return nil, ctx.Err()
	case <-time.After(readyTimeout):
		h.unsubscribe(sub)
		return nil, status.Error(codes.Unavailable, "kor: change feed did not start")
	}
}

func (h *hub) unsubscribe(sub *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, sub)
	if len(h.subs) == 0 && h.stop != nil {
		h.stop()
		h.stop = nil
	}
}

// run reads the feed until ctx ends, restarting it after errors. After a
// restart every subscriber re-evaluates all its targets, since changes made
// while the feed was down were not delivered.
func (h *hub) run(ctx context.Context, ready chan struct{}) {
	var once sync.Once
	signal := func() { once.Do(func() { close(ready) }) }
	defer signal()
	for restarted := false; ; restarted = true {
		if restarted {
			h.resyncAll()
		}
		err := h.feed.WatchChanges(ctx, signal, h.publish)
		if ctx.Err() != nil {
			return
		}
		slog.Warn("change feed stopped; restarting", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (h *hub) publish(changes []backend.Change) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		sub.mu.Lock()
		sub.pending = append(sub.pending, changes...)
		sub.mu.Unlock()
		sub.wake()
	}
}

func (h *hub) resyncAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		sub.mu.Lock()
		sub.resync = true
		sub.mu.Unlock()
		sub.wake()
	}
}

func (s *subscriber) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *subscriber) drain() ([]backend.Change, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, resync := s.pending, s.resync
	s.pending, s.resync = nil, false
	return out, resync
}

// target is one listened-to query or document set.
type target struct {
	id      int32
	query   *query.Query    // nil for a documents target
	names   map[string]bool // documents target
	results map[string]*backend.Doc
}

// relevant reports whether a batch of changes can affect the target.
func (t *target) relevant(collections, names map[string]bool) bool {
	if t.query != nil {
		return collections[t.query.CollectionID]
	}
	for name := range t.names {
		if names[name] {
			return true
		}
	}
	return false
}

// Listen streams live updates for queries and documents over gRPC.
func (s *Server) Listen(stream pb.Firestore_ListenServer) error {
	ctx := stream.Context()
	reqs := make(chan *pb.ListenRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case reqs <- req:
			case <-ctx.Done():
				return
			}
		}
	}()
	err := s.ServeListen(ctx, reqs, recvErr, stream.Send)
	if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
		return nil
	}
	return err
}

// ServeListen runs one Listen session on any transport: requests arrive on
// reqs, responses go out through send, and a value on done (or ctx ending)
// closes the session. gRPC and WebChannel both use it.
func (s *Server) ServeListen(ctx context.Context, reqs <-chan *pb.ListenRequest, done <-chan error, send func(*pb.ListenResponse) error) error {
	if s.hub == nil {
		return status.Error(codes.Unimplemented, "kor: this storage backend has no change feed")
	}
	sub, err := s.hub.subscribe(ctx)
	if err != nil {
		return err
	}
	defer s.hub.unsubscribe(sub)

	l := &listener{server: s, send: send, targets: map[int32]*target{}}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			return err
		case req := <-reqs:
			if err := l.handle(ctx, req); err != nil {
				return err
			}
		case <-sub.notify:
			changes, resync := sub.drain()
			if err := l.onChanges(ctx, changes, resync); err != nil {
				return err
			}
		}
	}
}

type listener struct {
	server  *Server
	send    func(*pb.ListenResponse) error
	targets map[int32]*target
}

func (l *listener) handle(ctx context.Context, req *pb.ListenRequest) error {
	if id := req.GetRemoveTarget(); id != 0 {
		delete(l.targets, id)
		return l.targetChange(pb.TargetChange_REMOVE, []int32{id}, nil)
	}
	tgt := req.GetAddTarget()
	if tgt == nil {
		return nil
	}
	t := &target{id: tgt.GetTargetId()}
	switch tt := tgt.GetTargetType().(type) {
	case *pb.Target_Query:
		q, err := query.Parse(tt.Query.GetParent(), tt.Query.GetStructuredQuery())
		if err != nil {
			return l.reject(t.id, err)
		}
		t.query = q
	case *pb.Target_Documents:
		t.names = map[string]bool{}
		for _, name := range tt.Documents.GetDocuments() {
			if _, err := backend.ParseDocumentName(name); err != nil {
				return l.reject(t.id, err)
			}
			t.names[name] = true
		}
	default:
		return l.reject(t.id, status.Error(codes.InvalidArgument, "kor: target has no query or documents"))
	}

	if err := l.targetChange(pb.TargetChange_ADD, []int32{t.id}, nil); err != nil {
		return err
	}
	if tgt.GetResumeToken() != nil || tgt.GetReadTime() != nil {
		// We do not replay history: tell the client to drop what it holds
		// for this target, then send the current state in full.
		if err := l.targetChange(pb.TargetChange_RESET, []int32{t.id}, nil); err != nil {
			return err
		}
	}
	results, err := l.evaluate(ctx, t)
	if status.Code(err) == codes.PermissionDenied {
		return l.reject(t.id, err)
	}
	if err != nil {
		return err
	}
	for _, doc := range results {
		if err := l.sendDoc(doc, t.id); err != nil {
			return err
		}
	}
	t.results = results
	readTime := now()
	if err := l.targetChange(pb.TargetChange_CURRENT, []int32{t.id}, readTime); err != nil {
		return err
	}
	if err := l.targetChange(pb.TargetChange_NO_CHANGE, nil, readTime); err != nil {
		return err
	}
	if tgt.GetOnce() {
		return l.targetChange(pb.TargetChange_REMOVE, []int32{t.id}, nil)
	}
	l.targets[t.id] = t
	return nil
}

// onChanges re-evaluates every target a batch of changes can affect (all of
// them when resync is set) and sends the differences, then a global NO_CHANGE
// so the SDKs raise a snapshot.
func (l *listener) onChanges(ctx context.Context, changes []backend.Change, resync bool) error {
	if (len(changes) == 0 && !resync) || len(l.targets) == 0 {
		return nil
	}
	collections := map[string]bool{}
	names := map[string]bool{}
	deleted := map[string]bool{}
	for _, c := range changes {
		collections[c.CollectionID] = true
		names[c.Name] = true
		deleted[c.Name] = c.Delete
	}
	sent := false
	for _, t := range l.targets {
		if !resync && !t.relevant(collections, names) {
			continue
		}
		next, err := l.evaluate(ctx, t)
		if status.Code(err) == codes.PermissionDenied {
			delete(l.targets, t.id)
			if err := l.reject(t.id, err); err != nil {
				return err
			}
			sent = true
			continue
		}
		if err != nil {
			return err
		}
		for name, doc := range next {
			if prev, ok := t.results[name]; ok && prev.UpdateTime.Equal(doc.UpdateTime) {
				continue
			}
			if err := l.sendDoc(doc, t.id); err != nil {
				return err
			}
			sent = true
		}
		for name := range t.results {
			if _, ok := next[name]; ok {
				continue
			}
			if err := l.sendGone(name, t.id, deleted[name]); err != nil {
				return err
			}
			sent = true
		}
		t.results = next
	}
	if !sent {
		return nil
	}
	return l.targetChange(pb.TargetChange_NO_CHANGE, nil, now())
}

// evaluate returns the documents a target currently holds, by name.
func (l *listener) evaluate(ctx context.Context, t *target) (map[string]*backend.Doc, error) {
	out := map[string]*backend.Doc{}
	if t.query != nil {
		var docs []*backend.Doc
		if err := l.server.store.RunQuery(ctx, t.query, func(doc *backend.Doc) error {
			docs = append(docs, doc)
			return nil
		}); err != nil {
			return nil, err
		}
		if err := l.server.checkQueryRule(ctx, t.query); err != nil {
			return nil, err
		}
		if err := l.server.checkList(ctx, docs); err != nil {
			return nil, err
		}
		for _, d := range docs {
			out[d.Name] = d
		}
		return out, nil
	}
	names := make([]string, 0, len(t.names))
	for name := range t.names {
		names = append(names, name)
	}
	docs, err := l.server.store.GetDocuments(ctx, names)
	if err != nil {
		return nil, err
	}
	if err := l.server.checkGet(ctx, names, docs); err != nil {
		return nil, err
	}
	return docs, nil
}

func (l *listener) sendDoc(doc *backend.Doc, targetID int32) error {
	d, err := docProto(doc)
	if err != nil {
		return err
	}
	return l.send(&pb.ListenResponse{ResponseType: &pb.ListenResponse_DocumentChange{
		DocumentChange: &pb.DocumentChange{Document: d, TargetIds: []int32{targetID}},
	}})
}

// sendGone reports a document that left a target: deleted, or no longer
// matching its query.
func (l *listener) sendGone(name string, targetID int32, deleted bool) error {
	if deleted {
		return l.send(&pb.ListenResponse{ResponseType: &pb.ListenResponse_DocumentDelete{
			DocumentDelete: &pb.DocumentDelete{Document: name, RemovedTargetIds: []int32{targetID}, ReadTime: now()},
		}})
	}
	return l.send(&pb.ListenResponse{ResponseType: &pb.ListenResponse_DocumentRemove{
		DocumentRemove: &pb.DocumentRemove{Document: name, RemovedTargetIds: []int32{targetID}, ReadTime: now()},
	}})
}

func (l *listener) targetChange(kind pb.TargetChange_TargetChangeType, ids []int32, readTime *timestamppb.Timestamp) error {
	tc := &pb.TargetChange{TargetChangeType: kind, TargetIds: ids}
	if readTime != nil {
		tc.ReadTime = readTime
		tc.ResumeToken = resumeToken(readTime)
	}
	return l.send(&pb.ListenResponse{ResponseType: &pb.ListenResponse_TargetChange{TargetChange: tc}})
}

// reject removes a target the server cannot serve, carrying the reason.
func (l *listener) reject(id int32, err error) error {
	return l.send(&pb.ListenResponse{ResponseType: &pb.ListenResponse_TargetChange{TargetChange: &pb.TargetChange{
		TargetChangeType: pb.TargetChange_REMOVE,
		TargetIds:        []int32{id},
		Cause:            statusProto(err),
	}}})
}

func now() *timestamppb.Timestamp {
	return timestamppb.New(time.Now().UTC().Truncate(time.Microsecond))
}

// resumeToken encodes a read time. Kor resets a resumed target rather than
// replaying history, so the token only needs to be non-empty and opaque.
func resumeToken(ts *timestamppb.Timestamp) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(ts.AsTime().UnixNano()))
	return b
}
