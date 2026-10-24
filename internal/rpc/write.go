// Modified in this fork: new file.

package rpc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WriteSession serves one Write stream, the transport the Firestore web SDK
// uses for its writes. The first request is a handshake answered with a
// stream id and token; every later request commits its writes atomically and
// is answered with the results and the next token.
type WriteSession struct {
	server     *Server
	streamID   string
	counter    uint64
	handshaken bool
}

// NewWriteSession starts a Write stream session.
func (s *Server) NewWriteSession() *WriteSession {
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	return &WriteSession{server: s, streamID: hex.EncodeToString(id)}
}

func (w *WriteSession) token() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, w.counter)
	w.counter++
	return b
}

// Handle answers one Write request. An error ends the stream.
func (w *WriteSession) Handle(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
	if !w.handshaken {
		w.handshaken = true
		if len(req.GetWrites()) == 0 {
			return &pb.WriteResponse{StreamId: w.streamID, StreamToken: w.token()}, nil
		}
	}
	if len(req.GetWrites()) == 0 {
		return &pb.WriteResponse{StreamToken: w.token()}, nil
	}
	resp, err := w.server.Commit(ctx, &pb.CommitRequest{Database: req.GetDatabase(), Writes: req.GetWrites()})
	if err != nil {
		return nil, err
	}
	return &pb.WriteResponse{
		StreamToken:  w.token(),
		WriteResults: resp.GetWriteResults(),
		CommitTime:   orNow(resp.GetCommitTime()),
	}, nil
}

func orNow(ts *timestamppb.Timestamp) *timestamppb.Timestamp {
	if ts != nil {
		return ts
	}
	return now()
}

// Write serves the Write stream over gRPC.
func (s *Server) Write(stream pb.Firestore_WriteServer) error {
	ws := s.NewWriteSession()
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
			return nil
		}
		if err != nil {
			return err
		}
		resp, err := ws.Handle(stream.Context(), req)
		if err != nil {
			return err
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}
