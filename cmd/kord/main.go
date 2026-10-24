// kord is the Kor server daemon: a Firestore wire-protocol-compatible
// document database backed by PostgreSQL.
//
// Point any Firestore SDK at it:
//
//	FIRESTORE_EMULATOR_HOST=localhost:6565 ./your-app
package main

// Modified in this fork: -backend selects PostgreSQL or Cosmos DB storage.

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/cosmos"
	"github.com/omelas-tech/kor/internal/rpc"
	"github.com/omelas-tech/kor/internal/store"
)

// indexReloadInterval trades staleness for load. Index changes are rare and
// administrative, so a few seconds of lag costs nothing, while the query itself
// is one small read against a table with a handful of rows.
const indexReloadInterval = 30 * time.Second

func main() {
	listen := flag.String("listen", envOr("KORD_LISTEN", "127.0.0.1:6565"), "address to serve gRPC on")
	backendName := flag.String("backend", envOr("KORD_BACKEND", "postgres"), "storage backend: postgres|cosmos")
	dsn := flag.String("pg-dsn", os.Getenv("KORD_PG_DSN"), "PostgreSQL DSN (required for -backend postgres)")
	cosmosEndpoint := flag.String("cosmos-endpoint", os.Getenv("KORD_COSMOS_ENDPOINT"), "Cosmos DB account endpoint (-backend cosmos)")
	cosmosDatabase := flag.String("cosmos-database", envOr("KORD_COSMOS_DATABASE", "kor"), "Cosmos DB database")
	cosmosContainer := flag.String("cosmos-container", envOr("KORD_COSMOS_CONTAINER", "documents"), "Cosmos DB container, partitioned on /customer_id")
	customerID := flag.String("customer-id", os.Getenv("KORD_CUSTOMER_ID"), "partition value for every document (-backend cosmos)")
	cosmosCreate := flag.Bool("cosmos-create", envOr("KORD_COSMOS_CREATE", "") != "", "create the Cosmos database and container if missing (local use)")
	logLevel := flag.String("log", envOr("KORD_LOG", "info"), "log level: debug|info|warn|error")
	metricsAddr := flag.String("metrics", envOr("KORD_METRICS", "127.0.0.1:6566"), "Prometheus /metrics address (empty = disabled)")
	allowPublic := flag.Bool("i-know-this-is-unauthenticated", envOr("KORD_ALLOW_PUBLIC_BIND", "") != "",
		"permit binding a non-loopback address. kord has NO authentication: any client that can reach the port has full read/write on every document.")
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	switch *backendName {
	case "postgres":
		if *dsn == "" {
			log.Error("missing -pg-dsn / KORD_PG_DSN")
			os.Exit(2)
		}
	case "cosmos":
		if *cosmosEndpoint == "" || os.Getenv("KORD_COSMOS_KEY") == "" || *customerID == "" {
			log.Error("-backend cosmos needs -cosmos-endpoint, KORD_COSMOS_KEY and -customer-id")
			os.Exit(2)
		}
	default:
		log.Error("unknown -backend", "backend", *backendName)
		os.Exit(2)
	}

	// Refuse a non-loopback bind unless the operator opted in explicitly.
	//
	// kord has no authentication, so reachability IS authorization: anyone who
	// can open a TCP connection gets full read/write on every document, with no
	// identity and no per-collection rules. That makes the listen address a
	// security control, not a config value — and a one-character edit
	// ("127.0.0.1" -> "0.0.0.0") the difference between a private database and
	// a public one. Documentation cannot catch that; refusing to boot can.
	//
	// The opt-out is deliberately unpleasant to type, and names the risk rather
	// than the mechanism, so nobody sets it without reading what it means.
	if !*allowPublic {
		if err := requireLoopback(*listen); err != nil {
			log.Error("refusing to start", "addr", *listen, "err", err,
				"remedy", "bind 127.0.0.1, put kord behind a private network, or pass -i-know-this-is-unauthenticated")
			os.Exit(2)
		}
	} else if host, _, e := net.SplitHostPort(*listen); e == nil && !isLoopbackHost(host) {
		log.Warn("SERVING UNAUTHENTICATED ON A NON-LOOPBACK ADDRESS — every client that can reach this port has full read/write on all data",
			"addr", *listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var be backend.Backend
	switch *backendName {
	case "cosmos":
		cs, err := cosmos.Open(ctx, cosmos.Config{
			Endpoint:        *cosmosEndpoint,
			Key:             os.Getenv("KORD_COSMOS_KEY"),
			Database:        *cosmosDatabase,
			Container:       *cosmosContainer,
			CustomerID:      *customerID,
			CreateIfMissing: *cosmosCreate,
		})
		if err != nil {
			log.Error("open cosmos backend", "err", err)
			os.Exit(1)
		}
		defer cs.Close()
		be = cs
		log.Info("backend", "kind", "cosmos", "database", *cosmosDatabase, "container", *cosmosContainer)
	default:
		st, err := store.Open(ctx, *dsn)
		if err != nil {
			log.Error("open store", "err", err)
			os.Exit(1)
		}
		defer st.Close()
		be = st
		startIndexLoader(ctx, log, st)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "addr", *listen, "err", err)
		os.Exit(1)
	}

	g := grpc.NewServer(
		grpc.UnaryInterceptor(rpc.UnaryLogging(log)),
		grpc.StreamInterceptor(rpc.StreamLogging(log)),
	)
	rpc.New(be).Register(g)
	rpc.StartStatsReporter(ctx, log, time.Minute)
	if *metricsAddr != "" {
		metricsSrv := rpc.ServeMetrics(*metricsAddr)
		defer metricsSrv.Close()
		log.Info("metrics listening", "addr", *metricsAddr)
	}

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		g.GracefulStop()
	}()

	log.Info("kord serving", "addr", lis.Addr().String())
	if err := g.Serve(lis); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// requireLoopback rejects any listen address reachable from off-host.
//
// The unspecified addresses (0.0.0.0, ::, and an empty host as in ":6565") are
// the dangerous ones: they bind every interface including the public one, and
// they are exactly what someone reaches for when a container or a private
// network makes loopback inconvenient.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("cannot parse listen address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("listen address %q binds every interface; use 127.0.0.1", addr)
	}
	if isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("listen host %q is not loopback and kord has no authentication", host)
}

// isLoopbackHost reports whether host resolves only to loopback. A hostname
// that resolves anywhere else is treated as non-loopback.
func isLoopbackHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	if host == "localhost" {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// startIndexLoader loads composite index definitions from Postgres and keeps
// reloading them, so the CLI can register and backfill indexes against a
// running server. Reloading on a ticker rather than only at boot means
// enabling an index does not require a restart, and a backfill finishing
// elsewhere takes effect on its own. A failure to load is logged, not fatal:
// indexes are an optimisation, and the general query path serves every query
// correctly without them.
func startIndexLoader(ctx context.Context, log *slog.Logger, st *store.Store) {
	if n, err := st.LoadIndexes(ctx); err != nil {
		log.Warn("loading composite indexes", "err", err, "ready", n)
	} else if n > 0 {
		log.Info("composite indexes loaded", "ready", n)
	}
	go func() {
		t := time.NewTicker(indexReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := st.LoadIndexes(ctx); err != nil {
					log.Warn("reloading composite indexes", "err", err)
				}
			}
		}
	}()
}
