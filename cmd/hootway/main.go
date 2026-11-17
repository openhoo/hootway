// Command hootway runs the Hootway credential-injecting API gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openhoo/hootway/internal/gateway"
)

var (
	version = "dev"
	commit  = "unknown"
)

const usage = `Hootway gives agents scoped virtual keys instead of real API credentials.

Usage:
  hootway serve [-config FILE] [-listen ADDR] [-admin-listen ADDR]
                                        Run the gateway (and optional web console)
  hootway check [-config FILE]          Validate configuration and resolve secrets
  hootway key new                       Generate a virtual key and its config hash
  hootway key hash                      Hash a virtual key read from stdin
  hootway admin token                   Generate a web console admin token and its hash
  hootway proxy ca [-cert FILE] [-key FILE] [-days N]
                                        Create a CA for https proxy mode
  hootway version                       Print version and commit
  hootway help                          Show this help

Environment:
  HOOTWAY_CONFIG       default for -config (otherwise hootway.json)
  HOOTWAY_ADMIN_TOKEN  web console token (instead of admin.token_sha256)
  HOOTWAY_PUBLIC_URL   gateway URL shown in console snippets

Exit status: 0 success, 1 runtime or configuration error, 2 usage error.
`

// shutdownTimeout bounds how long in-flight requests may finish after
// SIGINT/SIGTERM. A second signal exits immediately.
const shutdownTimeout = 15 * time.Second

// usageError marks command-line mistakes so they exit with status 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func main() {
	err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "hootway:", err)
	if _, ok := err.(usageError); ok { // returned unwrapped; avoids errors.As reflection
		os.Exit(2)
	}
	os.Exit(1)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return usageError{"missing command"}
	}
	switch args[0] {
	case "serve", "check":
		return serveOrCheck(args[0], args[1:], stdout, stderr)
	case "key":
		if len(args) != 2 {
			return usageError{"usage: hootway key new|hash"}
		}
		sub := ""
		if len(args) > 1 {
			sub = args[1]
		}
		switch sub {
		case "new":
			key, hash, err := gateway.GenerateKey()
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "key:    %s\nsha256: %s\n", key, hash)
			fmt.Fprintln(stderr, "Give the key to the agent; store only the sha256 in hootway.json.")
			return nil
		case "hash":
			data, err := io.ReadAll(io.LimitReader(stdin, 4097))
			if err != nil {
				return err
			}
			if len(data) > 4096 {
				return usageError{"key on stdin exceeds 4096 bytes"}
			}
			key := strings.TrimRight(string(data), "\r\n")
			if key == "" {
				return usageError{"no key on stdin (try: printf '%s' \"$KEY\" | hootway key hash)"}
			}
			fmt.Fprintln(stdout, gateway.HashKey(key))
			return nil
		}
		return usageError{"usage: hootway key new|hash"}
	case "admin":
		if len(args) != 2 || args[1] != "token" {
			return usageError{"usage: hootway admin token"}
		}
		token, hash, err := gateway.GenerateAdminToken()
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "token:  %s\nsha256: %s\n", token, hash)
		fmt.Fprintln(stderr, "Sign in to the console with the token; store only the sha256 in admin.token_sha256.")
		return nil
	case "proxy":
		if len(args) < 2 || args[1] != "ca" {
			return usageError{"usage: hootway proxy ca [-cert FILE] [-key FILE] [-days N]"}
		}
		return proxyCA(args[2:], stdout, stderr)
	case "version", "-v", "--version":
		if len(args) != 1 {
			return usageError{"usage: hootway version"}
		}
		fmt.Fprintf(stdout, "hootway %s (%s)\n", version, commit)
		return nil
	case "help", "-h", "-help", "--help":
		if len(args) != 1 {
			return usageError{"usage: hootway help"}
		}
		fmt.Fprint(stdout, usage)
		return nil
	}
	fmt.Fprint(stderr, usage)
	return usageError{"unknown command (see: hootway help)"}
}

func serveOrCheck(cmd string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hootway "+cmd, flag.ContinueOnError)
	var flagOutput strings.Builder
	fs.SetOutput(&flagOutput)
	path := fs.String("config", envOr("HOOTWAY_CONFIG", "hootway.json"), "configuration `file` (env HOOTWAY_CONFIG)")
	listen := fs.String("listen", "", "override the gateway listen `address`")
	adminListen := fs.String("admin-listen", "", "enable the web console on this `address`")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, flagOutput.String())
			return nil
		}
		return usageError{"invalid options (see: hootway " + cmd + " -h)"}
	}
	if fs.NArg() > 0 {
		return usageError{"unexpected positional argument"}
	}
	cfg, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	settings, err := effectiveListeners(cfg, *listen, *adminListen)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	gw, err := gateway.New(cfg, gateway.Options{Logger: logger, Lenient: cmd == "serve" && settings.admin != ""})
	if err != nil {
		return err
	}
	defer gw.Close()
	if cmd == "check" {
		fmt.Fprintf(stdout, "configuration ok: %d upstreams, %d keys\n", len(cfg.Upstreams), len(cfg.Keys))
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveGateway(ctx, gw, *path, settings, logger)
}

func serveGateway(ctx context.Context, gw *gateway.Gateway, path string, settings listenerSettings, logger *slog.Logger) error {
	servers := []*http.Server{newServer(settings.gateway, gw)}
	var onBound func(net.Addr) error
	if settings.admin != "" {
		admin := newServer(settings.admin, nil)
		servers = append(servers, admin)
		onBound = func(addr net.Addr) error {
			publicURL := settings.publicURL
			if publicURL == "" {
				var err error
				publicURL, err = advertisedGatewayURL(addr.String(), "")
				if err != nil {
					return err
				}
			}
			admin.Handler = gateway.NewAdmin(gw, path, settings.tokenHash, publicURL)
			return nil
		}
	}
	return serve(ctx, servers, logger, onBound)
}

type listenerSettings struct{ gateway, admin, tokenHash, publicURL string }

// Both check and serve validate the same effective settings. Flags affect
// this invocation only; console edits persist the original file's listeners.
func effectiveListeners(cfg *gateway.Config, listen, adminListen string) (listenerSettings, error) {
	s := listenerSettings{gateway: cfg.Listen}
	if cfg.Admin != nil {
		s.admin, s.tokenHash = cfg.Admin.Listen, cfg.Admin.TokenSHA256
	}
	if listen != "" {
		s.gateway = listen
	}
	if adminListen != "" {
		s.admin = adminListen
	}
	validate := func(addr string) (string, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port == "" {
			return "", errors.New("must include a host and port")
		}
		n, err := net.LookupPort("tcp", port)
		if err != nil {
			return "", errors.New("invalid TCP port")
		}
		return net.JoinHostPort(host, fmt.Sprint(n)), nil
	}
	gwAddr, err := validate(s.gateway)
	if err != nil {
		return s, fmt.Errorf("listen: %w", err)
	}
	if s.admin == "" {
		return s, nil
	}
	adminAddr, err := validate(s.admin)
	if err != nil {
		return s, fmt.Errorf("admin.listen: %w", err)
	}
	if adminAddr == gwAddr && !strings.HasSuffix(gwAddr, ":0") {
		return s, errors.New("admin.listen must differ from listen so agents cannot reach the console")
	}
	if t := os.Getenv("HOOTWAY_ADMIN_TOKEN"); t != "" {
		s.tokenHash = gateway.HashKey(t)
	}
	if s.tokenHash == "" {
		return s, errors.New("the web console needs admin.token_sha256 or HOOTWAY_ADMIN_TOKEN (see: hootway admin token)")
	}
	s.publicURL, err = advertisedGatewayURL(gwAddr, os.Getenv("HOOTWAY_PUBLIC_URL"))
	return s, err
}

// advertisedGatewayURL turns wildcard bind addresses into usable local examples.
// A remote sandbox needs HOOTWAY_PUBLIC_URL set to an address it can reach.
func advertisedGatewayURL(listen, publicURL string) (string, error) {
	if publicURL == "" {
		host, port, err := net.SplitHostPort(listen)
		if err != nil {
			return "", errors.New("listen must include a host and port for console examples")
		}
		portNumber, err := net.LookupPort("tcp", port)
		if err != nil {
			return "", errors.New("listen has an invalid port for console examples")
		}
		if portNumber == 0 {
			return "", nil // the caller resolves the assigned port after binding
		}
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		} else if host == "::" {
			host = "::1"
		}
		publicURL = (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, fmt.Sprint(portNumber))}).String()
	}
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || !gateway.ValidEndpointHost(u) || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(publicURL, "#") {
		return "", errors.New("HOOTWAY_PUBLIC_URL must be an http(s) URL with a valid host and port, without credentials, query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// serve binds every listener before announcing readiness, so address errors
// surface immediately, then runs until ctx is cancelled or a server fails.
func serve(ctx context.Context, servers []*http.Server, logger *slog.Logger, onBound func(net.Addr) error) error {
	listeners := make([]net.Listener, 0, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return err
		}
		defer ln.Close() // also closes earlier listeners if the next bind or setup fails
		listeners = append(listeners, ln)
	}
	if onBound != nil {
		if err := onBound(listeners[0].Addr()); err != nil {
			return err
		}
	}
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	logger.Info("hootway listening", "addr", listeners[0].Addr().String(), "version", version)
	if len(listeners) > 1 {
		logger.Info("web console enabled", "addr", listeners[1].Addr().String())
	}
	var runErr error
	select {
	case runErr = <-errc:
	case <-ctx.Done():
		logger.Info("shutting down", "timeout", shutdownTimeout.String())
	}
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	// A second interrupt during the drain aborts it.
	force := make(chan os.Signal, 1)
	signal.Notify(force, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(force)
	go func() {
		select {
		case <-force:
			cancel()
		case <-shutdown.Done():
		}
	}()
	// Hijacked proxy connections are outside http.Server's drain. Seal and
	// drain the gateway's inner HTTPS servers alongside the outer listeners,
	// sharing the same deadline and second-signal cancellation.
	drained := make(chan error, 2*len(servers))
	count := 0
	for _, srv := range servers {
		count++
		go func() {
			err := srv.Shutdown(shutdown)
			if err != nil {
				srv.Close()
			}
			drained <- err
		}()
		if h, ok := srv.Handler.(interface{ Shutdown(context.Context) error }); ok {
			count++
			go func() { drained <- h.Shutdown(shutdown) }()
		}
	}
	for i := 0; i < count; i++ {
		if err := <-drained; err != nil && runErr == nil {
			runErr = fmt.Errorf("shutdown: %w", err)
		}
	}
	if errors.Is(runErr, http.ErrServerClosed) {
		return nil
	}
	return runErr
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func proxyCA(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hootway proxy ca", flag.ContinueOnError)
	var flagOutput strings.Builder
	fs.SetOutput(&flagOutput)
	cert := fs.String("cert", "hootway-ca.pem", "CA certificate `file` to create (give it to agent sandboxes)")
	key := fs.String("key", "hootway-ca-key.pem", "CA private key `file` to create (0600; keep it on the gateway)")
	days := fs.Int("days", 365, "validity in `days`")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, flagOutput.String())
			return nil
		}
		return usageError{"invalid options (see: hootway proxy ca -h)"}
	}
	// Bound before converting to a nanosecond duration so large values cannot
	// wrap and create an already-expired certificate.
	const maxCADays = int((1<<63 - 1) / (24 * time.Hour))
	if fs.NArg() > 0 || *days < 1 || *days > maxCADays {
		return usageError{fmt.Sprintf("usage: hootway proxy ca [-cert FILE] [-key FILE] [-days N] (days: 1-%d)", maxCADays)}
	}
	if err := gateway.GenerateProxyCA(*cert, *key, time.Duration(*days)*24*time.Hour); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "certificate: %s\nkey:         %s\n", *cert, *key)
	fmt.Fprintln(stderr, `Set "proxy": {"ca_cert_file": …, "ca_key_file": …} in hootway.json and trust the certificate in agent sandboxes.`)
	return nil
}
