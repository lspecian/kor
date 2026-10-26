// Modified in this fork: new file.

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/omelas-tech/kor/internal/auth"
)

var (
	marshal   = protojson.MarshalOptions{}
	unmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}
)

// serveREST maps the Firestore v1 REST surface onto the RPC server, so REST
// and gRPC share behaviour (and security rules).
func (s *Server) serveREST(w http.ResponseWriter, r *http.Request) {
	resource, err := url.PathUnescape(strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/v1beta1/"), "/v1/"))
	if err != nil || !strings.Contains(resource, "/documents") {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "not a documents resource")
		return
	}
	ctx, err := s.principal(r.Context(), auth.BearerToken(r.Header.Get("Authorization")))
	if err != nil {
		writeStatusError(w, err)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "cannot read body")
		return
	}
	out, err := s.routeREST(ctx, r, resource, body)
	if err != nil {
		writeStatusError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (s *Server) routeREST(ctx context.Context, r *http.Request, resource string, body []byte) ([]byte, error) {
	target, action := resource, ""
	if i := strings.LastIndex(resource, ":"); i > strings.LastIndex(resource, "/") {
		target, action = resource[:i], resource[i+1:]
	}
	database := strings.SplitN(target, "/documents", 2)[0]
	parse := func(m proto.Message) error {
		if len(bytes.TrimSpace(body)) == 0 {
			return nil
		}
		if err := unmarshal.Unmarshal(body, m); err != nil {
			return status.Errorf(codes.InvalidArgument, "bad request body: %v", err)
		}
		return nil
	}

	switch action {
	case "commit":
		req := &pb.CommitRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Database = database
		return one(s.rpc.Commit(ctx, req))
	case "beginTransaction":
		req := &pb.BeginTransactionRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Database = database
		return one(s.rpc.BeginTransaction(ctx, req))
	case "rollback":
		req := &pb.RollbackRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Database = database
		return one(s.rpc.Rollback(ctx, req))
	case "batchGet":
		req := &pb.BatchGetDocumentsRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Database = database
		st := &collect[*pb.BatchGetDocumentsResponse]{ctx: ctx}
		if err := s.rpc.BatchGetDocuments(req, st); err != nil {
			return nil, err
		}
		return many(st.out)
	case "runQuery":
		req := &pb.RunQueryRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Parent = target
		st := &collect[*pb.RunQueryResponse]{ctx: ctx}
		if err := s.rpc.RunQuery(req, st); err != nil {
			return nil, err
		}
		return many(st.out)
	case "runAggregationQuery":
		req := &pb.RunAggregationQueryRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Parent = target
		st := &collect[*pb.RunAggregationQueryResponse]{ctx: ctx}
		if err := s.rpc.RunAggregationQuery(req, st); err != nil {
			return nil, err
		}
		return many(st.out)
	case "listCollectionIds":
		req := &pb.ListCollectionIdsRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Parent = target
		return one(s.rpc.ListCollectionIds(ctx, req))
	case "batchWrite":
		req := &pb.BatchWriteRequest{}
		if err := parse(req); err != nil {
			return nil, err
		}
		req.Database = database
		return one(s.rpc.BatchWrite(ctx, req))
	case "":
	default:
		return nil, status.Errorf(codes.Unimplemented, "kor: REST action %q is not implemented", action)
	}

	rel := strings.TrimPrefix(strings.SplitN(target, "/documents", 2)[1], "/")
	segs := []string{}
	if rel != "" {
		segs = strings.Split(rel, "/")
	}
	isDoc := len(segs) > 0 && len(segs)%2 == 0
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && isDoc:
		return one(s.rpc.GetDocument(ctx, &pb.GetDocumentRequest{Name: target}))
	case r.Method == http.MethodGet && len(segs) > 0:
		parent := database + "/documents"
		if len(segs) > 1 {
			parent += "/" + strings.Join(segs[:len(segs)-1], "/")
		}
		st := &collect[*pb.RunQueryResponse]{ctx: ctx}
		err := s.rpc.RunQuery(&pb.RunQueryRequest{Parent: parent, QueryType: &pb.RunQueryRequest_StructuredQuery{
			StructuredQuery: &pb.StructuredQuery{From: []*pb.StructuredQuery_CollectionSelector{{CollectionId: segs[len(segs)-1]}}},
		}}, st)
		if err != nil {
			return nil, err
		}
		resp := &pb.ListDocumentsResponse{}
		for _, row := range st.out {
			if row.GetDocument() != nil {
				resp.Documents = append(resp.Documents, row.GetDocument())
			}
		}
		return marshal.Marshal(resp)
	case (r.Method == http.MethodPatch && isDoc) || (r.Method == http.MethodPost && !isDoc && len(segs) > 0):
		doc := &pb.Document{}
		if err := parse(doc); err != nil {
			return nil, err
		}
		write := &pb.Write{}
		if isDoc {
			doc.Name = target
			if mask := q["updateMask.fieldPaths"]; len(mask) > 0 {
				write.UpdateMask = &pb.DocumentMask{FieldPaths: mask}
			}
			if v := q.Get("currentDocument.exists"); v != "" {
				write.CurrentDocument = &pb.Precondition{ConditionType: &pb.Precondition_Exists{Exists: v == "true"}}
			}
		} else {
			id := q.Get("documentId")
			if id == "" {
				id = newDocID()
			}
			doc.Name = target + "/" + id
			write.CurrentDocument = &pb.Precondition{ConditionType: &pb.Precondition_Exists{Exists: false}}
		}
		write.Operation = &pb.Write_Update{Update: doc}
		if _, err := s.rpc.Commit(ctx, &pb.CommitRequest{Database: database, Writes: []*pb.Write{write}}); err != nil {
			return nil, err
		}
		return one(s.rpc.GetDocument(ctx, &pb.GetDocumentRequest{Name: doc.Name}))
	case r.Method == http.MethodDelete && isDoc:
		_, err := s.rpc.Commit(ctx, &pb.CommitRequest{Database: database, Writes: []*pb.Write{{Operation: &pb.Write_Delete{Delete: target}}}})
		if err != nil {
			return nil, err
		}
		return []byte("{}"), nil
	}
	return nil, status.Errorf(codes.InvalidArgument, "kor: unsupported request %s %s", r.Method, resource)
}

// collect is a server stream that gathers responses for a REST reply.
type collect[T any] struct {
	grpc.ServerStream
	ctx context.Context
	out []T
}

func (c *collect[T]) Send(m T) error           { c.out = append(c.out, m); return nil }
func (c *collect[T]) Context() context.Context { return c.ctx }

func one[T proto.Message](m T, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return marshal.Marshal(m)
}

func many[T proto.Message](ms []T) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, m := range ms {
		if i > 0 {
			buf.WriteByte(',')
		}
		b, err := marshal.Marshal(m)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// errorBody is the Google API error shape the Firebase SDKs parse.
func errorBody(httpCode int, statusName, msg string) map[string]any {
	return map[string]any{"error": map[string]any{"code": httpCode, "message": msg, "status": statusName}}
}

func writeError(w http.ResponseWriter, httpCode int, statusName, msg string) {
	writeJSON(w, httpCode, errorBody(httpCode, statusName, msg))
}

func writeStatusError(w http.ResponseWriter, err error) {
	st, _ := status.FromError(err)
	httpCode, name := httpStatus(st.Code())
	writeError(w, httpCode, name, st.Message())
}

// httpStatus maps a gRPC code to the HTTP status and status name Google APIs use.
func httpStatus(c codes.Code) (int, string) {
	switch c {
	case codes.OK:
		return 200, "OK"
	case codes.Canceled:
		return 499, "CANCELLED"
	case codes.InvalidArgument:
		return 400, "INVALID_ARGUMENT"
	case codes.DeadlineExceeded:
		return 504, "DEADLINE_EXCEEDED"
	case codes.NotFound:
		return 404, "NOT_FOUND"
	case codes.AlreadyExists:
		return 409, "ALREADY_EXISTS"
	case codes.PermissionDenied:
		return 403, "PERMISSION_DENIED"
	case codes.ResourceExhausted:
		return 429, "RESOURCE_EXHAUSTED"
	case codes.FailedPrecondition:
		return 400, "FAILED_PRECONDITION"
	case codes.Aborted:
		return 409, "ABORTED"
	case codes.OutOfRange:
		return 400, "OUT_OF_RANGE"
	case codes.Unimplemented:
		return 501, "UNIMPLEMENTED"
	case codes.Unavailable:
		return 503, "UNAVAILABLE"
	case codes.Unauthenticated:
		return 401, "UNAUTHENTICATED"
	default:
		return 500, "INTERNAL"
	}
}

func newDocID() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
