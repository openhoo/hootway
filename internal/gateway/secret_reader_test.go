package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSecretReaderBoundsCredentials(t *testing.T) {
	for name, value := range map[string]string{
		"oversize":              strings.Repeat("x", maxSecretLen+1),
		"oversize with newline": strings.Repeat("x", maxSecretLen+1) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "operator-secret")
			if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSecret("", file, nil); err == nil {
				t.Fatal("accepted oversized file credential")
			}
			if _, err := readSecret("S", "", func(string) string { return value }); err == nil {
				t.Fatal("accepted oversized environment credential")
			}
		})
	}
	for _, ending := range []string{"", "\n", "\r\n"} {
		file := filepath.Join(t.TempDir(), "operator-secret")
		value := strings.Repeat("x", maxSecretLen)
		if err := os.WriteFile(file, []byte(value+ending), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := readSecret("", file, nil); err != nil || got != value {
			t.Fatalf("boundary credential ending %q: %v", ending, err)
		}
	}
}

func TestSecretReaderPreservesOperatorPathsAndAliases(t *testing.T) {
	file := filepath.Join(t.TempDir(), "operator-secret")
	if err := os.WriteFile(file, []byte("synthetic\r\n\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{file, rel} {
		if got, err := readSecret("", name, nil); err != nil || got != "synthetic" {
			t.Fatalf("operator path %q: %v", name, err)
		}
	}
	alias := filepath.Join(t.TempDir(), "credential-alias")
	if err := os.Symlink(file, alias); err != nil {
		t.Skip("symlink creation unavailable")
	}
	if got, err := readSecret("", alias, nil); err != nil || got != "synthetic" {
		t.Fatalf("operator alias: %v", err)
	}
}

func TestSecretReaderRejectsDevicesAndDirectories(t *testing.T) {
	paths := []string{t.TempDir()}
	if runtime.GOOS != "windows" {
		paths = append(paths, os.DevNull)
	}
	for _, file := range paths {
		if _, err := readSecret("", file, nil); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("nonregular source %q: %v", file, err)
		}
	}
}

func TestSecretReaderRejectsFIFOBeforeBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix FIFO fixture")
	}
	file := filepath.Join(t.TempDir(), "fifo")
	if err := exec.Command("mkfifo", file).Run(); err != nil {
		t.Skip("mkfifo unavailable")
	}
	result := make(chan error, 1)
	go func() { _, err := readSecret("", file, nil); result <- err }()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO source: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("credential reader blocked opening a FIFO")
	}
}
