// Modified in this fork: new file.

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/rpc"
)

// WebChannel (BrowserChannel version 8) is how the Firestore web SDK carries
// its Listen and Write streams over plain HTTP:
//
//	POST .../channel?VER=8&RID=n        open a session; the body carries reqN___data__
//	GET  .../channel?SID=s&RID=rpc&AID=a back channel: length-prefixed message arrays
//	POST .../channel?SID=s&RID=n&AID=a  forward channel: more requests, acks up to AID
//	*    .../channel?SID=s&TYPE=terminate close the session
//
// Server messages are numbered arrays; the client acknowledges them (AID) on
// later requests, and a reconnecting back channel resumes after the last
// acknowledged one. With CI=1 the client has detected a buffering proxy and
// the back channel answers once and closes (long polling).

const (
	keepAliveEvery = 15 * time.Second
	sessionIdle    = 2 * time.Minute
	replayWindow   = 2000
)

type channelServer struct {
	web *Server

	mu       sync.Mutex
	sessions map[string]*channelSession
	done     chan struct{}
}

type entry struct {
	id      int
	payload json.RawMessage
}

type channelSession struct {
	id   string
	kind string // Listen | Write

	mu       sync.Mutex
	queue    []entry
	nextID   int
	acked    int
	sentUpTo int
	nextReq  int
	back     *backChannel
	closed   bool
	lastSeen time.Time

	ctx    context.Context
	cancel context.CancelFunc

	listenReqs chan *pb.ListenRequest
	write      *rpc.WriteSession
}

type backChannel struct {
	wake     chan struct{}
	gone     chan struct{}
	buffered bool
}

func newChannelServer(web *Server) *channelServer {
	c := &channelServer{web: web, sessions: map[string]*channelSession{}, done: make(chan struct{})}
	go c.housekeeping()
	return c
}

func (c *channelServer) stop() {
	close(c.done)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		s.close()
	}
	c.sessions = map[string]*channelSession{}
}

func (c *channelServer) housekeeping() {
	t := time.NewTicker(keepAliveEvery)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		c.mu.Lock()
		for id, s := range c.sessions {
			s.mu.Lock()
			attached, idle := s.back != nil, time.Since(s.lastSeen) > sessionIdle
			s.mu.Unlock()
			switch {
			case attached:
				s.push(json.RawMessage(`"noop"`))
			case idle:
				s.close()
				delete(c.sessions, id)
			}
		}
		c.mu.Unlock()
	}
}

func (c *channelServer) session(id string) *channelSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[id]
}

func (c *channelServer) handle(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/google.firestore.v1.Firestore/"), "/channel")
	if kind != "Listen" && kind != "Write" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown channel "+kind)
		return
	}
	q := r.URL.Query()
	sid := q.Get("SID")

	if q.Get("TYPE") == "terminate" {
		if s := c.session(sid); s != nil {
			s.close()
			c.mu.Lock()
			delete(c.sessions, sid)
			c.mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodGet {
		s := c.session(sid)
		if s == nil || s.isClosed() {
			unknownSID(w)
			return
		}
		aid, _ := strconv.Atoi(q.Get("AID"))
		s.serveBackChannel(w, r, aid, q.Get("CI") == "1" || q.Get("TYPE") == "html")
		return
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "cannot read body")
		return
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "bad form body")
		return
	}

	if sid == "" {
		s, err := c.open(kind, form)
		if err != nil {
			writeStatusError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("X-HTTP-Session-Id", s.id[:8])
		w.WriteHeader(http.StatusOK)
		created, _ := json.Marshal([]any{[]any{0, []any{"c", s.id, "", 8, 12, 30000}}})
		_, _ = w.Write(frame(created))
		s.process(form)
		return
	}

	s := c.session(sid)
	if s == nil || s.isClosed() {
		unknownSID(w)
		return
	}
	if aid, err := strconv.Atoi(q.Get("AID")); err == nil {
		s.ack(aid)
	}
	s.process(form)
	s.mu.Lock()
	backPresent := 0
	if s.back != nil {
		backPresent = 1
	}
	outstanding := 0
	for _, e := range s.queue {
		outstanding += len(e.payload)
	}
	body, _ := json.Marshal([]int{backPresent, s.nextID - 1, outstanding})
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(frame(body))
}

func unknownSID(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = io.WriteString(w, "Unknown SID")
}

// open starts a session. The SDK sends its headers (Authorization among them)
// inside the first request's form, not as HTTP headers.
func (c *channelServer) open(kind string, form url.Values) (*channelSession, error) {
	headers := parseHeaderBlock(form.Get("headers"))
	ctx, err := c.web.principal(context.Background(), auth.BearerToken(headers["authorization"]))
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	ctx, cancel := context.WithCancel(ctx)
	s := &channelSession{
		id:       base64.RawURLEncoding.EncodeToString(idBytes),
		kind:     kind,
		nextID:   1,
		lastSeen: time.Now(),
		ctx:      ctx,
		cancel:   cancel,
	}
	if kind == "Listen" {
		s.listenReqs = make(chan *pb.ListenRequest, 64)
		go func() {
			err := c.web.rpc.ServeListen(ctx, s.listenReqs, nil, func(resp *pb.ListenResponse) error {
				b, err := marshal.Marshal(resp)
				if err != nil {
					return err
				}
				s.push(b)
				return nil
			})
			if err != nil && ctx.Err() == nil {
				s.fail(err)
			}
		}()
	} else {
		s.write = c.web.rpc.NewWriteSession()
	}
	c.mu.Lock()
	c.sessions[s.id] = s
	c.mu.Unlock()
	return s, nil
}

func parseHeaderBlock(block string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(block, "\r\n") {
		if i := strings.Index(line, ":"); i > 0 {
			out[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	return out
}

// process handles the requests in a forward-channel form, skipping any the
// client retransmitted.
func (s *channelSession) process(form url.Values) {
	count, _ := strconv.Atoi(form.Get("count"))
	ofs, _ := strconv.Atoi(form.Get("ofs"))
	for i := 0; i < count; i++ {
		s.mu.Lock()
		s.lastSeen = time.Now()
		idx := ofs + i
		if idx < s.nextReq {
			s.mu.Unlock()
			continue
		}
		s.nextReq = idx + 1
		s.mu.Unlock()
		raw := form.Get(fmt.Sprintf("req%d___data__", i))
		if raw == "" {
			continue
		}
		if err := s.handleMessage([]byte(raw)); err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *channelSession) handleMessage(raw []byte) error {
	if s.kind == "Listen" {
		req := &pb.ListenRequest{}
		if err := unmarshal.Unmarshal(raw, req); err != nil {
			return status.Errorf(codes.InvalidArgument, "bad Listen request: %v", err)
		}
		select {
		case s.listenReqs <- req:
			return nil
		case <-s.ctx.Done():
			return status.Error(codes.Canceled, "session closed")
		}
	}
	req := &pb.WriteRequest{}
	if err := unmarshal.Unmarshal(raw, req); err != nil {
		return status.Errorf(codes.InvalidArgument, "bad Write request: %v", err)
	}
	resp, err := s.write.Handle(s.ctx, req)
	if err != nil {
		return err
	}
	b, err := marshal.Marshal(resp)
	if err != nil {
		return err
	}
	s.push(b)
	return nil
}

// fail sends the error the SDK turns into a stream close, then closes.
func (s *channelSession) fail(err error) {
	st, _ := status.FromError(err)
	httpCode, name := httpStatus(st.Code())
	b, _ := json.Marshal(errorBody(httpCode, name, st.Message()))
	s.push(b)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	time.AfterFunc(2*time.Second, s.close)
}

func (s *channelSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *channelSession) close() {
	s.mu.Lock()
	s.closed = true
	back := s.back
	s.back = nil
	s.mu.Unlock()
	s.cancel()
	if back != nil {
		close(back.gone)
	}
}

func (s *channelSession) ack(aid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if aid > s.acked {
		s.acked = aid
	}
	s.prune()
}

func (s *channelSession) prune() {
	i := 0
	for i < len(s.queue) && s.queue[i].id <= s.acked {
		i++
	}
	s.queue = s.queue[i:]
	if len(s.queue) > replayWindow {
		s.queue = s.queue[len(s.queue)-replayWindow/2:]
	}
}

// push queues one message and wakes the back channel.
func (s *channelSession) push(payload json.RawMessage) {
	s.mu.Lock()
	s.queue = append(s.queue, entry{id: s.nextID, payload: payload})
	s.nextID++
	back := s.back
	s.mu.Unlock()
	if back != nil {
		select {
		case back.wake <- struct{}{}:
		default:
		}
	}
}

// serveBackChannel streams queued and future messages until the client goes
// away, another back channel replaces this one, or the session closes.
func (s *channelSession) serveBackChannel(w http.ResponseWriter, r *http.Request, aid int, buffered bool) {
	flusher, _ := w.(http.Flusher)
	bc := &backChannel{wake: make(chan struct{}, 1), gone: make(chan struct{}), buffered: buffered}
	s.mu.Lock()
	if old := s.back; old != nil {
		close(old.gone)
	}
	if aid > s.acked {
		s.acked = aid
	}
	s.prune()
	s.sentUpTo = s.acked
	s.back = bc
	s.lastSeen = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.back == bc {
			s.back = nil
		}
		s.lastSeen = time.Now()
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if flusher != nil {
		flusher.Flush()
	}
	for {
		if wrote := s.flushTo(w, flusher); wrote && buffered {
			return
		}
		select {
		case <-bc.wake:
		case <-bc.gone:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *channelSession) flushTo(w io.Writer, flusher http.Flusher) bool {
	s.mu.Lock()
	var pending []entry
	for _, e := range s.queue {
		if e.id > s.sentUpTo {
			pending = append(pending, e)
		}
	}
	if len(pending) == 0 {
		s.mu.Unlock()
		return false
	}
	s.sentUpTo = pending[len(pending)-1].id
	s.mu.Unlock()

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, e := range pending {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, "[%d,[", e.id)
		buf.Write(e.payload)
		buf.WriteString("]]")
	}
	buf.WriteByte(']')
	if _, err := w.Write(frame(buf.Bytes())); err != nil {
		return false
	}
	if flusher != nil {
		flusher.Flush()
	}
	return true
}

// frame length-prefixes a payload. The client counts JavaScript string
// characters (UTF-16 code units), so non-ASCII characters are escaped first
// and the byte length then equals the character length.
func frame(payload []byte) []byte {
	ascii := asciiJSON(payload)
	out := make([]byte, 0, len(ascii)+8)
	out = strconv.AppendInt(out, int64(len(ascii)), 10)
	out = append(out, '\n')
	return append(out, ascii...)
}

func asciiJSON(b []byte) []byte {
	ascii := true
	for _, c := range b {
		if c >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return b
	}
	var buf bytes.Buffer
	for _, r := range string(b) {
		if r < 0x80 {
			buf.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&buf, `\u%04x`, u)
		}
	}
	return buf.Bytes()
}
