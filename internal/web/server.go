// Package web serves Kor over HTTP: the Firestore REST API, the WebChannel
// transport the Firestore web SDK uses for its Listen and Write streams, a few
// Firebase-emulator endpoints for local development, and gRPC itself over
// cleartext HTTP/2, so one port serves every Firestore SDK (as the emulator
// does).
//
// Modified in this fork: this package is new.
package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/rpc"
)

// Options configures the HTTP surface.
type Options struct {
	// Emulator enables the development-only endpoints the Firebase tools
	// call: loading security rules and clearing a database.
	Emulator bool
	// LoadRules replaces the security rules of a project (emulator endpoint).
	LoadRules func(project, source string) error
	// ClearDatabase deletes every document of a database (emulator endpoint).
	ClearDatabase func(ctx context.Context, database string) error
	// Extra handles routes owned by other packages (sign-in bridge, events);
	// it returns false when the route is not its own.
	Extra []func(w http.ResponseWriter, r *http.Request) bool
	// Events serves /kor/v1/events when it implements backend.EventLog.
	Events any
	Log    *slog.Logger
}

// Server is the HTTP front of a Kor service.
type Server struct {
	rpc      *rpc.Server
	grpc     *grpc.Server
	verifier *auth.Verifier
	opts     Options
	channels *channelServer
}

// New returns the HTTP server. Close it to end WebChannel sessions.
func New(rpcSrv *rpc.Server, grpcSrv *grpc.Server, v *auth.Verifier, opts Options) *Server {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	s := &Server{rpc: rpcSrv, grpc: grpcSrv, verifier: v, opts: opts}
	s.channels = newChannelServer(s)
	return s
}

// Close ends every WebChannel session.
func (s *Server) Close() { s.channels.stop() }

// Handler serves gRPC (HTTP/2 with content-type application/grpc) and every
// HTTP route on the same listener.
func (s *Server) Handler() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			s.grpc.ServeHTTP(w, r)
			return
		}
		s.serveHTTP(w, r)
	})
	return h2c.NewHandler(h, &http2.Server{})
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	cors(w, r)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	for _, extra := range s.opts.Extra {
		if extra(w, r) {
			return
		}
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/google.firestore.v1.Firestore/") && strings.HasSuffix(p, "/channel"):
		s.channels.handle(w, r)
	case strings.HasPrefix(p, "/v1/projects/") || strings.HasPrefix(p, "/v1beta1/projects/"):
		s.serveREST(w, r)
	case s.opts.Emulator && strings.HasPrefix(p, "/emulator/v1/projects/"):
		s.serveEmulator(w, r)
	case p == "/kor/v1/events" && r.Method == http.MethodGet:
		s.serveEvents(w, r)
	case p == "/" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "Ok\n")
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "no route for "+r.Method+" "+p)
	}
}

// cors lets web apps call Kor from their own origin. Credentials are
// allowed, so the origin is echoed rather than wildcarded.
func cors(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	if origin := r.Header.Get("Origin"); origin != "" {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
	} else {
		h.Set("Access-Control-Allow-Origin", "*")
	}
	if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
		h.Set("Access-Control-Allow-Headers", req)
	}
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	h.Set("Access-Control-Expose-Headers", "X-HTTP-Session-Id")
	h.Set("Access-Control-Max-Age", "3600")
}

// principal authenticates a request's bearer token into its context.
func (s *Server) principal(ctx context.Context, token string) (context.Context, error) {
	p, err := s.verifier.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	return auth.WithPrincipal(ctx, p), nil
}

func (s *Server) serveEmulator(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/emulator/v1/projects/")
	switch {
	case r.Method == http.MethodPut && strings.HasSuffix(rest, ":securityRules"):
		project := strings.TrimSuffix(rest, ":securityRules")
		var body struct {
			Rules struct {
				Files []struct {
					Content string `json:"content"`
				} `json:"files"`
			} `json:"rules"`
		}
		if err := decodeJSON(r, &body); err != nil || len(body.Rules.Files) == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "expected {rules: {files: [{content}]}}")
			return
		}
		if s.opts.LoadRules == nil {
			writeError(w, http.StatusNotImplemented, "UNIMPLEMENTED", "security rules are not enabled on this server")
			return
		}
		if err := s.opts.LoadRules(project, body.Rules.Files[0].Content); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	case r.Method == http.MethodDelete && strings.HasSuffix(rest, "/documents"):
		database := "projects/" + strings.TrimSuffix(rest, "/documents")
		if s.opts.ClearDatabase == nil {
			writeError(w, http.StatusNotImplemented, "UNIMPLEMENTED", "this backend cannot be cleared")
			return
		}
		if err := s.opts.ClearDatabase(r.Context(), database); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{})
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown emulator route")
	}
}
