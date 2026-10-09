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
			data, err := io.ReadAll(io.LimitReader(stdin, 4096))
			if err != nil {
				return err
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
		if len(args) < 2 || args[1] != "token" {
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
		fmt.Fprintf(stdout, "hootway %s (%s)\n", version, commit)
		return nil
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	fmt.Fprint(stderr, usage)
	return usageError{fmt.Sprintf("unknown command %q", args[0])}
}

func serveOrCheck(cmd string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hootway "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", envOr("HOOTWAY_CONFIG", "hootway.json"), "configuration `file` (env HOOTWAY_CONFIG)")
	listen := fs.String("listen", "", "override the gateway listen `address`")
	adminListen := fs.String("admin-listen", "", "enable the web console on this `address`")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return usageError{fmt.Sprintf("unexpected argument %q", fs.Arg(0))}
	}
	cfg, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *adminListen != "" {
		if cfg.Admin == nil {
			cfg.Admin = &gateway.Admin{}
		}
		cfg.Admin.Listen = *adminListen
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	adminEnabled := cfg.Admin != nil && cmd == "serve"
	gw, err := gateway.New(cfg, gateway.Options{Logger: logger, Lenient: adminEnabled})
	if err != nil {
		return err
	}
	if cmd == "check" {
		fmt.Fprintf(stdout, "configuration ok: %d upstreams, %d keys\n", len(cfg.Upstreams), len(cfg.Keys))
		return nil
	}
	servers := []*http.Server{newServer(cfg.Listen, gw)}
	if adminEnabled {
		hash := cfg.Admin.TokenSHA256
		if t := os.Getenv("HOOTWAY_ADMIN_TOKEN"); t != "" {
			hash = gateway.HashKey(t)
		}
		if hash == "" {
			return errors.New("the web console needs admin.token_sha256 or HOOTWAY_ADMIN_TOKEN (see: hootway admin token)")
		}
		if cfg.Admin.Listen == cfg.Listen {
			return errors.New("admin.listen must differ from listen so agents cannot reach the console")
		}
		gwURL := envOr("HOOTWAY_PUBLIC_URL", "http://"+cfg.Listen)
		servers = append(servers, newServer(cfg.Admin.Listen, gateway.NewAdmin(gw, *path, hash, gwURL)))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, servers, logger)
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
func serve(ctx context.Context, servers []*http.Server, logger *slog.Logger) error {
	listeners := make([]net.Listener, 0, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
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
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil {
			srv.Close()
			if runErr == nil {
				runErr = fmt.Errorf("shutdown: %w", err)
			}
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
	fs.SetOutput(stderr)
	cert := fs.String("cert", "hootway-ca.pem", "CA certificate `file` to create (give it to agent sandboxes)")
	key := fs.String("key", "hootway-ca-key.pem", "CA private key `file` to create (0600; keep it on the gateway)")
	days := fs.Int("days", 365, "validity in `days`")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usageError{err.Error()}
	}
	if fs.NArg() > 0 || *days < 1 {
		return usageError{"usage: hootway proxy ca [-cert FILE] [-key FILE] [-days N]"}
	}
	if err := gateway.GenerateProxyCA(*cert, *key, time.Duration(*days)*24*time.Hour); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "certificate: %s\nkey:         %s\n", *cert, *key)
	fmt.Fprintln(stderr, `Set "proxy": {"ca_cert_file": …, "ca_key_file": …} in hootway.json and trust the certificate in agent sandboxes.`)
	return nil
}
