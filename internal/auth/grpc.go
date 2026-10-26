// Modified in this fork: new file.

package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func tokenFromMetadata(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		if t := BearerToken(v); t != "" {
			return t
		}
	}
	return ""
}

// UnaryInterceptor authenticates each unary call into its context.
func UnaryInterceptor(v *Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		p, err := v.Authenticate(ctx, tokenFromMetadata(ctx))
		if err != nil {
			return nil, err
		}
		return next(WithPrincipal(ctx, p), req)
	}
}

// StreamInterceptor authenticates each stream into its context.
func StreamInterceptor(v *Verifier) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		p, err := v.Authenticate(ss.Context(), tokenFromMetadata(ss.Context()))
		if err != nil {
			return err
		}
		return next(srv, &principalStream{ServerStream: ss, ctx: WithPrincipal(ss.Context(), p)})
	}
}

type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }
