package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIUsageErrorsDoNotReflectArguments(t *testing.T) {
	const sensitive = "hw_private_cli_fixture"
	for name, args := range map[string][]string{
		"command":      {sensitive},
		"serve option": {"serve", "-" + sensitive},
		"check option": {"check", "-" + sensitive},
		"CA option":    {"proxy", "ca", "-" + sensitive},
		"CA lifetime":  {"proxy", "ca", "-days", sensitive},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			err := run(args, strings.NewReader(""), &out, &errOut)
			if _, ok := err.(usageError); !ok {
				t.Fatal("invalid arguments did not produce a usage error")
			}
			if strings.Contains(err.Error(), sensitive) || strings.Contains(errOut.String(), sensitive) || strings.Contains(out.String(), sensitive) {
				t.Fatal("usage error reflected a sensitive argument")
			}
		})
	}
}

func TestCommandHelpStillShowsOptions(t *testing.T) {
	for _, command := range [][]string{{"serve"}, {"check"}, {"proxy", "ca"}} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := append(append([]string(nil), command...), "-h")
			if err := run(args, strings.NewReader(""), &out, &errOut); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(errOut.String(), "Usage of hootway "+strings.Join(command, " ")) || !strings.Contains(errOut.String(), "file") {
				t.Fatal("command help no longer shows usage and options")
			}
		})
	}
}

func TestAdvertisedGatewayURL(t *testing.T) {
	for listen, want := range map[string]string{
		":8787": "http://127.0.0.1:8787", "0.0.0.0:8787": "http://127.0.0.1:8787",
		"[::]:8787": "http://[::1]:8787", "localhost:8787": "http://localhost:8787",
		"[::1]:8787":     "http://[::1]:8787",
		"localhost:http": "http://localhost:80",
	} {
		got, err := advertisedGatewayURL(listen, "")
		if err != nil || got != want {
			t.Fatalf("listen %q: got %q, err %v", listen, got, err)
		}
	}
	got, err := advertisedGatewayURL(":8787", "https://gateway.example/hootway/")
	if err != nil || got != "https://gateway.example/hootway" {
		t.Fatal("explicit public base URL did not override the local example")
	}
	for _, bad := range []string{"http://:8787", "https://user:hw_private@example.com", "javascript:alert(1)", "https://example.com/?key=hw_private", "https://example.com/#hw_private", "http://example.com:99999"} {
		if _, err := advertisedGatewayURL(":8787", bad); err == nil || strings.Contains(err.Error(), "hw_private") {
			t.Fatal("invalid advertised URL was accepted or reflected a credential")
		}
	}
}
