// Command hootway runs the Hootway credential-injecting API gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
  hootway serve  -config hootway.json   Run the gateway
  hootway check  -config hootway.json   Validate configuration and resolve secrets
  hootway key new                       Generate a virtual key and its config hash
  hootway key hash                      Hash a virtual key read from stdin
  hootway admin token                   Generate a web console admin token and its hash
  hootway version
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hootway:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("missing command")
	}
	switch args[0] {
	case "serve", "check":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("config", envOr("HOOTWAY_CONFIG", "hootway.json"), "configuration file")
		listen := fs.String("listen", "", "override listen address")
		adminListen := fs.String("admin-listen", "", "enable the web console on this address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
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
		adminEnabled := cfg.Admin != nil && args[0] == "serve"
		gw, err := gateway.New(cfg, gateway.Options{Logger: logger, Lenient: adminEnabled})
		if err != nil {
			return err
		}
		if args[0] == "check" {
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
			logger.Info("web console enabled", "addr", cfg.Admin.Listen)
		}
		return serve(servers, logger)
	case "key":
		if len(args) < 2 {
			return errors.New("usage: hootway key new|hash")
		}
		switch args[1] {
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
			key := string(data)
			for len(key) > 0 && (key[len(key)-1] == '\n' || key[len(key)-1] == '\r') {
				key = key[:len(key)-1]
			}
			if key == "" {
				return errors.New("no key on stdin")
			}
			fmt.Fprintln(stdout, gateway.HashKey(key))
			return nil
		}
		return fmt.Errorf("unknown key command %q", args[1])
	case "admin":
		if len(args) < 2 || args[1] != "token" {
			return errors.New("usage: hootway admin token")
		}
		token, hash, err := gateway.GenerateAdminToken()
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "token:  %s\nsha256: %s\n", token, hash)
		fmt.Fprintln(stderr, "Sign in to the console with the token; store only the sha256 in admin.token_sha256.")
		return nil
	case "version", "--version":
		fmt.Fprintf(stdout, "hootway %s (%s)\n", version, commit)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", args[0])
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func serve(servers []*http.Server, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { errc <- srv.ListenAndServe() }()
	}
	logger.Info("hootway listening", "addr", servers[0].Addr, "version", version)
	var runErr error
	select {
	case runErr = <-errc:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
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
