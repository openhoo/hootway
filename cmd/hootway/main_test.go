package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hootway/internal/gateway"
)

func TestKeyHashDoesNotSilentlyTruncate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"key", "hash"}, strings.NewReader(strings.Repeat("k", 4097)), &stdout, &stderr)
	if _, ok := err.(usageError); !ok || stdout.Len() != 0 {
		t.Fatalf("oversized key must fail without printing a hash: err=%v, output bytes=%d", err, stdout.Len())
	}
	stdout.Reset()
	key := "hw_example"
	if err := run([]string{"key", "hash"}, strings.NewReader(key+"\r\n"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != gateway.HashKey(key)+"\n" {
		t.Fatal("normal stdin hash changed")
	}
}

func TestSimpleCommandsRejectExtraArguments(t *testing.T) {
	for _, args := range [][]string{
		{"key", "new", "unexpected"}, {"key", "hash", "unexpected"},
		{"admin", "token", "unexpected"}, {"version", "unexpected"}, {"help", "unexpected"},
	} {
		t.Run(strings.Join(args[:len(args)-1], "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(args, strings.NewReader("hw_example"), &stdout, &stderr)
			if _, ok := err.(usageError); !ok || stdout.Len() != 0 {
				t.Fatalf("unexpected argument must fail before creating output: err=%v, output bytes=%d", err, stdout.Len())
			}
		})
	}
}

func TestProxyCARejectsOverflowBeforeWritingFiles(t *testing.T) {
	dir := t.TempDir()
	err := run([]string{"proxy", "ca", "-cert", filepath.Join(dir, "ca.pem"), "-key", filepath.Join(dir, "key.pem"), "-days", "106752"}, strings.NewReader(""), io.Discard, io.Discard)
	if _, ok := err.(usageError); !ok {
		t.Fatalf("overflow must be a usage error: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("invalid validity wrote certificate files")
	}
}

func TestServeReportsBindFailureAndReleasesEarlierListeners(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := first.Addr().String()
	first.Close()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	servers := []*http.Server{newServer(addr, http.NotFoundHandler()), newServer(busy.Addr().String(), http.NotFoundHandler())}
	if err := serve(context.Background(), servers, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("second listener bind must fail")
	}
	check, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("first listener was leaked: %v", err)
	}
	check.Close()
}

func TestServeDrainsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := newServer("127.0.0.1:0", http.NotFoundHandler())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, []*http.Server{srv}, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled server did not shut down")
	}
}

type drainingHandler struct {
	started chan struct{}
	release chan struct{}
}

func (h *drainingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (h *drainingHandler) Shutdown(ctx context.Context) error {
	close(h.started)
	select {
	case <-h.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestServeWaitsForHandlerConnectionsToDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &drainingHandler{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, []*http.Server{newServer("127.0.0.1:0", h)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	cancel()
	select {
	case <-h.started:
	case <-time.After(3 * time.Second):
		t.Fatal("handler shutdown was not called")
	}
	select {
	case <-done:
		t.Fatal("serve returned before handler connections drained")
	default:
	}
	close(h.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not finish after handler drained")
	}
}
