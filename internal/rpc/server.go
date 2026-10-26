// Package rpc implements the google.firestore.v1.Firestore gRPC service on
// top of a storage backend. Firestore SDKs connect to it via
// FIRESTORE_EMULATOR_HOST or a custom host setting — no application changes.
//
// Modified in this fork: the service depends on backend.Backend instead of the
// PostgreSQL store, and no longer queries the database directly.
package rpc

import (
	"context"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/query"
)

// Server implements pb.FirestoreServer.
type Server struct {
	pb.UnimplementedFirestoreServer
	store backend.Backend
	hub   *hub // nil when the backend has no change feed
	rules rulesRegistry
}

// New returns a Firestore service backed by b. Live updates are served when b
// also implements backend.ChangeFeed.
func New(b backend.Backend) *Server {
	s := &Server{store: b}
	if feed, ok := b.(backend.ChangeFeed); ok {
		s.hub = newHub(feed)
	}
	return s
}

// Register attaches the service to a gRPC server.
func (s *Server) Register(g *grpc.Server) {
	pb.RegisterFirestoreServer(g, s)
}

// Commit applies writes atomically, optionally as a transaction commit with
// read-version verification.
func (s *Server) Commit(ctx context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	var (
		results    []*pb.WriteResult
		commitTime time.Time
		err        error
	)
	ctx = s.withWriteChecks(ctx)
	if txn := req.GetTransaction(); len(txn) > 0 {
		results, commitTime, err = s.store.CommitTxn(ctx, txn, req.GetWrites())
	} else {
		results, commitTime, err = s.store.Commit(ctx, req.GetWrites())
	}
	if err != nil {
		return nil, err
	}
	return &pb.CommitResponse{
		WriteResults: results,
		CommitTime:   timestamppb.New(commitTime),
	}, nil
}

// BeginTransaction starts an optimistic transaction.
func (s *Server) BeginTransaction(ctx context.Context, req *pb.BeginTransactionRequest) (*pb.BeginTransactionResponse, error) {
	return &pb.BeginTransactionResponse{Transaction: s.store.BeginTxn()}, nil
}

// Rollback discards a transaction.
func (s *Server) Rollback(ctx context.Context, req *pb.RollbackRequest) (*emptypb.Empty, error) {
	s.store.RollbackTxn(req.GetTransaction())
	return &emptypb.Empty{}, nil
}

// RunQuery executes a structured query and streams results.
func (s *Server) RunQuery(req *pb.RunQueryRequest, stream pb.Firestore_RunQueryServer) error {
	if req.GetTransaction() != nil || req.GetNewTransaction() != nil || req.GetReadTime() != nil {
		// Point-read transactions only, by design — see internal/store/txn.go.
		return status.Error(codes.Unimplemented, "kor: queries inside transactions are not supported")
	}
	q, err := query.Parse(req.GetParent(), req.GetStructuredQuery())
	if err != nil {
		return err
	}
	readTime := timestamppb.New(time.Now().UTC().Truncate(time.Microsecond))
	var docs []*backend.Doc
	if err := s.store.RunQuery(stream.Context(), q, func(doc *backend.Doc) error {
		docs = append(docs, doc)
		return nil
	}); err != nil {
		return err
	}
	if err := s.checkQueryRule(stream.Context(), q); err != nil {
		return err
	}
	if err := s.checkList(stream.Context(), docs); err != nil {
		return err
	}
	sent := 0
	for _, doc := range docs {
		d, err := docProto(doc)
		if err != nil {
			return err
		}
		d.Fields = q.ApplyProjection(d.Fields)
		sent++
		if err := stream.Send(&pb.RunQueryResponse{Document: d, ReadTime: readTime}); err != nil {
			return err
		}
	}
	if sent == 0 {
		// Empty result: a document-less response carries the read time.
		return stream.Send(&pb.RunQueryResponse{ReadTime: readTime})
	}
	return nil
}

// RunAggregationQuery supports count() (with up_to); sum/avg return
// UNIMPLEMENTED until a consumer exists.
func (s *Server) RunAggregationQuery(req *pb.RunAggregationQueryRequest, stream pb.Firestore_RunAggregationQueryServer) error {
	if req.GetTransaction() != nil || req.GetNewTransaction() != nil || req.GetReadTime() != nil {
		return status.Error(codes.Unimplemented, "kor: aggregations inside transactions are not supported")
	}
	saq := req.GetStructuredAggregationQuery()
	q, err := query.Parse(req.GetParent(), saq.GetStructuredQuery())
	if err != nil {
		return err
	}
	var upTo int64
	aliases := make([]string, 0, len(saq.GetAggregations()))
	for _, agg := range saq.GetAggregations() {
		c, ok := agg.GetOperator().(*pb.StructuredAggregationQuery_Aggregation_Count_)
		if !ok {
			return status.Error(codes.Unimplemented, "kor: only count() aggregations are implemented")
		}
		aliases = append(aliases, agg.GetAlias())
		if v := c.Count.GetUpTo(); v != nil {
			if upTo == 0 || v.GetValue() > upTo {
				upTo = v.GetValue()
			}
		}
	}
	if err := s.checkQuery(stream.Context(), q); err != nil {
		return err
	}
	n, err := s.store.RunCount(stream.Context(), q, upTo)
	if err != nil {
		return err
	}
	fields := map[string]*pb.Value{}
	for _, alias := range aliases {
		fields[alias] = &pb.Value{ValueType: &pb.Value_IntegerValue{IntegerValue: n}}
	}
	return stream.Send(&pb.RunAggregationQueryResponse{
		Result:   &pb.AggregationResult{AggregateFields: fields},
		ReadTime: timestamppb.New(time.Now().UTC().Truncate(time.Microsecond)),
	})
}

// BatchWrite applies writes non-atomically, returning a status per write.
// This is what BulkWriter uses; partial failure is expected and reported
// per-entry rather than failing the RPC.
func (s *Server) BatchWrite(ctx context.Context, req *pb.BatchWriteRequest) (*pb.BatchWriteResponse, error) {
	resp := &pb.BatchWriteResponse{}
	ctx = s.withWriteChecks(ctx)
	for _, w := range req.GetWrites() {
		results, _, err := s.store.Commit(ctx, []*pb.Write{w})
		if err != nil {
			resp.WriteResults = append(resp.WriteResults, &pb.WriteResult{})
			resp.Status = append(resp.Status, statusProto(err))
			continue
		}
		resp.WriteResults = append(resp.WriteResults, results[0])
		resp.Status = append(resp.Status, statusProto(nil))
	}
	return resp, nil
}

// GetDocument returns a single document (REST-oriented; server SDKs use
// BatchGetDocuments).
func (s *Server) GetDocument(ctx context.Context, req *pb.GetDocumentRequest) (*pb.Document, error) {
	if req.GetReadTime() != nil {
		return nil, status.Error(codes.Unimplemented, "kor: read-time reads not implemented yet")
	}
	if txn := req.GetTransaction(); len(txn) > 0 {
		if err := s.store.LockTxnReads(ctx, txn, []string{req.GetName()}); err != nil {
			return nil, err
		}
	}
	docs, err := s.store.GetDocuments(ctx, []string{req.GetName()})
	if err != nil {
		return nil, err
	}
	if err := s.checkGet(ctx, []string{req.GetName()}, docs); err != nil {
		return nil, err
	}
	doc, ok := docs[req.GetName()]
	if txn := req.GetTransaction(); len(txn) > 0 {
		var readAt time.Time // zero records "missing at read time"
		if ok {
			readAt = doc.UpdateTime
		}
		if err := s.store.RecordTxnReads(txn, map[string]time.Time{req.GetName(): readAt}); err != nil {
			return nil, err
		}
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "document not found: %s", req.GetName())
	}
	return docProto(doc)
}

// BatchGetDocuments streams found/missing results for the requested names,
// recording read versions when a transaction is attached.
func (s *Server) BatchGetDocuments(req *pb.BatchGetDocumentsRequest, stream pb.Firestore_BatchGetDocumentsServer) error {
	if req.GetReadTime() != nil {
		return status.Error(codes.Unimplemented, "kor: read-time reads not implemented yet")
	}
	txnID := req.GetTransaction()
	var newTxn []byte
	if req.GetNewTransaction() != nil {
		newTxn = s.store.BeginTxn()
		txnID = newTxn
	}
	if len(txnID) > 0 {
		if err := s.store.LockTxnReads(stream.Context(), txnID, req.GetDocuments()); err != nil {
			return err
		}
	}

	docs, err := s.store.GetDocuments(stream.Context(), req.GetDocuments())
	if err != nil {
		return err
	}
	if err := s.checkGet(stream.Context(), req.GetDocuments(), docs); err != nil {
		return err
	}

	if len(txnID) > 0 {
		reads := make(map[string]time.Time, len(req.GetDocuments()))
		for _, name := range req.GetDocuments() {
			var readAt time.Time // zero = missing at read time
			if doc, ok := docs[name]; ok {
				readAt = doc.UpdateTime
			}
			reads[name] = readAt
		}
		if err := s.store.RecordTxnReads(txnID, reads); err != nil {
			return err
		}
	}

	readTime := timestamppb.New(time.Now().UTC().Truncate(time.Microsecond))
	first := true
	for _, name := range req.GetDocuments() {
		resp := &pb.BatchGetDocumentsResponse{ReadTime: readTime}
		if first {
			resp.Transaction = newTxn
			first = false
		}
		if doc, ok := docs[name]; ok {
			d, err := docProto(doc)
			if err != nil {
				return err
			}
			resp.Result = &pb.BatchGetDocumentsResponse_Found{Found: d}
		} else {
			resp.Result = &pb.BatchGetDocumentsResponse_Missing{Missing: name}
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

// ListCollectionIds lists the collection ids under a parent, from the
// registry maintained on write.
func (s *Server) ListCollectionIds(ctx context.Context, req *pb.ListCollectionIdsRequest) (*pb.ListCollectionIdsResponse, error) {
	if err := adminOnly(ctx); err != nil {
		return nil, err
	}
	ids, err := s.store.ListCollectionIDs(ctx, req.GetParent())
	if err != nil {
		return nil, err
	}
	return &pb.ListCollectionIdsResponse{CollectionIds: ids}, nil
}

func docProto(doc *backend.Doc) (*pb.Document, error) {
	fields := doc.Fields
	if fields == nil {
		fields = map[string]*pb.Value{}
	}
	return &pb.Document{
		Name:       doc.Name,
		Fields:     fields,
		CreateTime: timestamppb.New(doc.CreateTime),
		UpdateTime: timestamppb.New(doc.UpdateTime),
	}, nil
}

func statusProto(err error) *rpcstatus.Status {
	if err == nil {
		return &rpcstatus.Status{Code: int32(codes.OK)}
	}
	st, _ := status.FromError(err)
	return st.Proto()
}
