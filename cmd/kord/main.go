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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/backend"
	"github.com/omelas-tech/kor/internal/cosmos"
	"github.com/omelas-tech/kor/internal/identity"
	"github.com/omelas-tech/kor/internal/rpc"
	"github.com/omelas-tech/kor/internal/store"
	"github.com/omelas-tech/kor/internal/web"
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
	authOn := flag.Bool("auth", envOr("KORD_AUTH", "") != "", "authenticate requests (off: every request is admin, as upstream Kor)")
	adminTokens := flag.String("admin-tokens", os.Getenv("KORD_ADMIN_TOKENS"), "comma-separated bearer values that act as admin (backend services)")
	allowUnsigned := flag.Bool("allow-unsigned-tokens", envOr("KORD_ALLOW_UNSIGNED_TOKENS", "") != "", "accept unsigned Firebase-emulator tokens (development only)")
	firebaseProject := flag.String("firebase-project", os.Getenv("KORD_FIREBASE_PROJECT"), "accept Firebase Auth ID tokens for this project")
	oidcIssuer := flag.String("oidc-issuer", os.Getenv("KORD_OIDC_ISSUER"), "accept tokens from this OIDC issuer (e.g. Entra)")
	oidcAudience := flag.String("oidc-audience", os.Getenv("KORD_OIDC_AUDIENCE"), "required audience for -oidc-issuer tokens")
	oidcJWKS := flag.String("oidc-jwks", os.Getenv("KORD_OIDC_JWKS"), "JWKS URL for -oidc-issuer")
	identityProject := flag.String("identity-project", os.Getenv("KORD_IDENTITY_PROJECT"), "serve the Firebase Auth sign-in bridge for this project")
	identityKey := flag.String("identity-key", os.Getenv("KORD_IDENTITY_KEY"), "PEM file holding the bridge's signing key (created if missing)")
	trustCustomTokens := flag.Bool("identity-trust-unsigned-custom-tokens", envOr("KORD_IDENTITY_TRUST_UNSIGNED_CUSTOM_TOKENS", "") != "", "accept custom tokens without verifying them, as the Auth emulator does (development only)")
	emulatorTokens := flag.Bool("identity-emulator-tokens", envOr("KORD_IDENTITY_EMULATOR_TOKENS", "") != "", "issue unsigned ID tokens like the Firebase Auth emulator, for Admin SDKs in emulator mode (development only; needs -allow-unsigned-tokens)")
	extraListen := flag.String("extra-listen", os.Getenv("KORD_EXTRA_LISTEN"), "comma-separated extra addresses serving the same endpoints (e.g. the Auth emulator port)")
	rulesFile := flag.String("rules", os.Getenv("KORD_RULES"), "Firestore security rules file applied to end-user requests (needs -auth)")
	emulatorMode := flag.Bool("emulator", envOr("KORD_EMULATOR", "") != "", "serve the Firebase-emulator development endpoints (load rules, clear data)")
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

	verifier := auth.NewVerifier(authConfig(!*authOn, *adminTokens, *allowUnsigned, *firebaseProject, *oidcIssuer, *oidcAudience, *oidcJWKS))
	if verifier.Enabled() {
		log.Info("authentication on", "firebase_project", *firebaseProject, "oidc_issuer", *oidcIssuer, "unsigned_tokens", *allowUnsigned)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "addr", *listen, "err", err)
		os.Exit(1)
	}

	g := grpc.NewServer(
		grpc.ChainUnaryInterceptor(rpc.UnaryLogging(log), auth.UnaryInterceptor(verifier)),
		grpc.ChainStreamInterceptor(rpc.StreamLogging(log), auth.StreamInterceptor(verifier)),
	)
	rpcSrv := rpc.New(be)
	rpcSrv.Register(g)
	if *rulesFile != "" {
		src, err := os.ReadFile(*rulesFile)
		if err != nil {
			log.Error("read rules", "file", *rulesFile, "err", err)
			os.Exit(2)
		}
		if err := rpcSrv.SetDefaultRules(string(src)); err != nil {
			log.Error("parse rules", "file", *rulesFile, "err", err)
			os.Exit(2)
		}
		log.Info("security rules loaded", "file", *rulesFile)
	}
	opts := web.Options{Emulator: *emulatorMode, Log: log, LoadRules: rpcSrv.SetProjectRules, Events: be}
	if *identityProject != "" {
		key, err := loadOrCreateKey(*identityKey)
		if err != nil {
			log.Error("identity key", "file", *identityKey, "err", err)
			os.Exit(2)
		}
		if *emulatorTokens && !*allowUnsigned {
			log.Error("-identity-emulator-tokens needs -allow-unsigned-tokens, or Kor would refuse its own tokens")
			os.Exit(2)
		}
		var exchange *auth.Verifier
		if *oidcIssuer != "" {
			exchange = auth.NewVerifier(authConfig(false, "", false, "", *oidcIssuer, *oidcAudience, *oidcJWKS))
		}
		bridge, err := identity.New(identity.Config{
			Project: *identityProject, Key: key, TrustUnsignedCustomTokens: *trustCustomTokens, Exchange: exchange,
			EmulatorTokens: *emulatorTokens, Admins: verifier, Log: log,
		}, be)
		if err != nil {
			log.Error("identity bridge", "err", err)
			os.Exit(2)
		}
		verifier.AddIssuer(bridge.TrustedIssuer())
		opts.Extra = append(opts.Extra, bridge.Handle)
		log.Info("sign-in bridge on", "project", *identityProject, "exchange", exchange != nil)
	}
	if clearer, ok := be.(backend.Clearer); ok {
		opts.ClearDatabase = clearer.ClearDatabase
	}
	webSrv := web.New(rpcSrv, g, verifier, opts)
	defer webSrv.Close()
	rpc.StartStatsReporter(ctx, log, time.Minute)
	if *metricsAddr != "" {
		metricsSrv := rpc.ServeMetrics(*metricsAddr)
		defer metricsSrv.Close()
		log.Info("metrics listening", "addr", *metricsAddr)
	}

	// One listener serves gRPC (HTTP/2) and the HTTP surface (REST,
	// WebChannel), like the Firebase emulator, so every SDK uses one address.
	httpSrv := &http.Server{Handler: webSrv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	for _, addr := range strings.Split(*extraListen, ",") {
		if addr = strings.TrimSpace(addr); addr == "" {
			continue
		}
		if !*allowPublic {
			if err := requireLoopback(addr); err != nil {
				log.Error("refusing extra listener", "addr", addr, "err", err)
				os.Exit(2)
			}
		}
		extra, err := net.Listen("tcp", addr)
		if err != nil {
			log.Error("listen", "addr", addr, "err", err)
			os.Exit(1)
		}
		go func() { _ = httpSrv.Serve(extra) }()
		log.Info("kord also serving", "addr", extra.Addr().String())
	}
	log.Info("kord serving", "addr", lis.Addr().String(), "transports", "grpc,rest,webchannel")
	if err := httpSrv.Serve(lis); err != nil && err != http.ErrServerClosed {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// authConfig builds the verifier settings from flags.
func authConfig(disabled bool, adminTokens string, allowUnsigned bool, firebaseProject, oidcIssuer, oidcAudience, oidcJWKS string) auth.Config {
	cfg := auth.Config{Disabled: disabled, AllowUnsigned: allowUnsigned}
	for _, t := range strings.Split(adminTokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			cfg.AdminTokens = append(cfg.AdminTokens, t)
		}
	}
	if firebaseProject != "" {
		cfg.Issuers = append(cfg.Issuers, &auth.Issuer{
			Issuer:    "https://securetoken.google.com/" + firebaseProject,
			Audiences: []string{firebaseProject},
			JWKSURL:   "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
		})
	}
	if oidcIssuer != "" {
		iss := &auth.Issuer{Issuer: oidcIssuer, JWKSURL: oidcJWKS}
		if oidcAudience != "" {
			iss.Audiences = []string{oidcAudience}
		}
		cfg.Issuers = append(cfg.Issuers, iss)
	}
	return cfg
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

// loadOrCreateKey reads an RSA key from a PEM file, creating the file when it
// does not exist; an empty path returns a fresh key that lives with the
// process.
func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s: no PEM block", path)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
