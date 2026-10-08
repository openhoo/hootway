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

var version = "dev"

const usage = `Hootway gives agents scoped virtual keys instead of real API credentials.

Usage:
  hootway serve  -config hootway.json   Run the gateway
  hootway check  -config hootway.json   Validate configuration and resolve secrets
  hootway key new                       Generate a virtual key and its config hash
  hootway key hash                      Hash a virtual key read from stdin
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
		logger := slog.New(slog.NewJSONHandler(stderr, nil))
		gw, err := gateway.New(cfg, gateway.Options{Logger: logger})
		if err != nil {
			return err
		}
		if args[0] == "check" {
			fmt.Fprintf(stdout, "configuration ok: %d upstreams, %d keys\n", len(cfg.Upstreams), len(cfg.Keys))
			return nil
		}
		return serve(cfg.Listen, gw, logger)
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
	case "version", "--version":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", args[0])
}

func serve(addr string, h http.Handler, logger *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("hootway listening", "addr", addr, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
