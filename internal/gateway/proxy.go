package gateway

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Proxy mode lets agents keep the upstreams' real URLs and point HTTP_PROXY /
// HTTPS_PROXY at Hootway instead. Every proxied request goes through the same
// key check, grant matching, rate limit and credential injection as a
// gateway request. Hootway never acts as an open proxy: only origins (and base
// paths) of configured upstreams are reachable, and CONNECT tunnels are
// terminated by Hootway itself with a certificate from the configured CA, so
// no opaque traffic ever passes through.

var (
	errNotUpstream    = encodeError("not_an_upstream", "the proxy only serves the origins of configured upstreams")
	errProxyTLSOff    = encodeError("proxy_https_unavailable", "https proxying needs proxy.ca_cert_file and proxy.ca_key_file on the gateway")
	errProxyBadTarget = encodeError("bad_target", "the proxy target is not a valid host:port")
	errProxyDisabled  = encodeError("proxy_disabled", "proxy mode is not enabled on this gateway")
	errProxyBusy      = encodeError("proxy_busy", "the gateway's intercepted tunnel limit is reached; retry later")
)

const maxProxyTunnels = 256

func originKey(scheme, host string) string {
	host = strings.ToLower(host)
	if _, _, err := net.SplitHostPort(host); err != nil {
		port := "443"
		if scheme == "http" {
			port = "80"
		}
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return scheme + "://" + host
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// matchOrigin maps a real upstream URL to the upstream name and the
// upstream-relative path. The longest matching base path wins.
func (st *runtimeState) matchOrigin(scheme, host, escapedPath string) (name, rest string, ok bool) {
	p := orRoot(escapedPath)
	for _, rt := range st.origins[originKey(scheme, host)] {
		if p == rt.escBase || rt.escBase == "" {
			return rt.up.Name, orRoot(p[len(rt.escBase):]), true
		}
		if strings.HasPrefix(p, rt.escBase+"/") {
			return rt.up.Name, p[len(rt.escBase):], true
		}
	}
	return "", "", false
}

// proxyKey extracts a virtual key from Proxy-Authorization: the password of
// Basic credentials (any username), or a Bearer token.
func proxyKey(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok {
		return ""
	}
	switch strings.ToLower(scheme) {
	case "bearer":
		return strings.TrimSpace(token)
	case "basic":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
		if err != nil {
			return ""
		}
		_, pass, _ := strings.Cut(string(raw), ":")
		return pass
	}
	return ""
}

// serveProxied handles a proxy request for scheme://host. tunnelKey is the key
// that authenticated the CONNECT tunnel; otherwise the key comes from
// Proxy-Authorization or the usual request headers.
func (g *Gateway) serveProxied(rs *reqState, r *http.Request, scheme, host string, tunnelKey *runtimeKey) {
	if g.closed.Load() {
		rs.info.outcome = "shutting_down"
		writeStaticError(&rs.rec, http.StatusServiceUnavailable, errShuttingDown)
		return
	}
	st := g.state.Load()
	rs.state = st
	if st.cfg.Proxy == nil {
		rs.info.outcome = "proxy_disabled"
		writeStaticError(&rs.rec, http.StatusMethodNotAllowed, errProxyDisabled)
		return
	}
	if r.URL.User != nil || r.URL.Opaque != "" || r.URL.Fragment != "" ||
		(scheme != "http" && scheme != "https") {
		rs.info.outcome = "bad_path"
		writeStaticError(&rs.rec, http.StatusBadRequest, errProxyBadTarget)
		return
	}
	rs.info.proxied = true
	shown := strings.ToLower(host)
	if h, port, err := net.SplitHostPort(shown); err == nil && (scheme == "https" && port == "443" || scheme == "http" && port == "80") {
		shown = h
		if strings.Contains(h, ":") {
			shown = "[" + h + "]"
		}
	}
	rs.ev.Path = scheme + "://" + shown + r.URL.EscapedPath()
	k := tunnelKey
	if k == nil {
		presented := proxyKey(r)
		inline := presented == ""
		if inline {
			presented = extractKey(r)
		}
		// Challenge for proxy credentials only when none were sent at all, so
		// clients that send the key as their normal API token keep working.
		if k = g.authenticate(rs, st, presented, !inline || presented == ""); k == nil {
			return
		}
	} else {
		rs.ev.Key = k.ID
		if k = g.stillValid(st, k); k == nil {
			rs.info.outcome = "invalid_key"
			writeStaticError(&rs.rec, http.StatusProxyAuthRequired, errInvalidKey)
			return
		}
	}
	path := orRoot(r.URL.EscapedPath())
	if checkPath(path) != nil {
		rs.info.outcome = "bad_path"
		writeStaticError(&rs.rec, http.StatusBadRequest, errBadPath)
		return
	}
	if checkQuery(r.URL.RawQuery) != nil {
		rs.info.outcome = "bad_query"
		writeStaticError(&rs.rec, http.StatusBadRequest, errBadQuery)
		return
	}
	name, rest, ok := st.matchOrigin(scheme, host, path)
	if !ok {
		rs.info.outcome = "forbidden"
		writeStaticError(&rs.rec, http.StatusForbidden, errNotUpstream)
		return
	}
	g.forward(rs, r, st, k, name, rest)
}

// stillValid rechecks a tunnel's key against the active configuration on
// every request, so disabling, expiring, rotating or narrowing a key also
// applies to open tunnels. It returns the current key, or nil.
func (g *Gateway) stillValid(st *runtimeState, k *runtimeKey) *runtimeKey {
	cur := st.keys[k.hash]
	if cur == nil || cur.ID != k.ID || cur.Disabled || (cur.ExpiresAt != nil && !g.now().Before(*cur.ExpiresAt)) {
		return nil
	}
	return cur
}

// serveConnect terminates a CONNECT tunnel to a configured https upstream
// with a certificate from the proxy CA and serves the requests inside it.
func (g *Gateway) serveConnect(w http.ResponseWriter, r *http.Request) {
	st := g.state.Load()
	rs := &reqState{rec: statusRecorder{ResponseWriter: w, status: http.StatusOK}, start: g.now()}
	rs.state = st
	rs.ev = Event{Method: r.Method, Path: r.Host, Proxy: true}
	recorded := false
	record := func() {
		if !recorded {
			recorded = true
			g.finish(r, rs)
		}
	}
	defer record()
	if st.cfg.Proxy == nil {
		rs.info.outcome = "bad_path"
		writeStaticError(&rs.rec, http.StatusMethodNotAllowed, errProxyDisabled)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil || host == "" {
		rs.info.outcome = "bad_path"
		writeStaticError(&rs.rec, http.StatusBadRequest, errProxyBadTarget)
		return
	}
	// Tunnels are only opened for a valid key (default deny); every request
	// inside is checked again against the then-active configuration.
	tunnelKeyValue := proxyKey(r)
	k := g.authenticate(rs, st, tunnelKeyValue, true)
	if k == nil {
		return
	}
	routes := st.origins[originKey("https", r.Host)]
	granted := false
	for _, rt := range routes {
		for _, grant := range k.grants {
			if grant.upstream == rt.up.Name {
				granted = true
				break
			}
		}
	}
	if len(routes) == 0 || !granted {
		rs.info.outcome = "forbidden"
		writeStaticError(&rs.rec, http.StatusForbidden, errNotUpstream)
		return
	}
	rs.ev.Upstream = routes[0].up.Name
	if st.ca == nil {
		rs.info.outcome = "upstream_unconfigured"
		writeStaticError(&rs.rec, http.StatusServiceUnavailable, errProxyTLSOff)
		return
	}
	g.connMu.Lock()
	full := len(g.tunnels) >= maxProxyTunnels
	g.connMu.Unlock()
	if full {
		rs.info.outcome = "proxy_busy"
		rs.rec.Header().Set("Retry-After", "1")
		writeStaticError(&rs.rec, http.StatusServiceUnavailable, errProxyBusy)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		rs.info.outcome = "upstream_error"
		writeStaticError(&rs.rec, http.StatusInternalServerError, encodeError("internal", "connection cannot be tunnelled"))
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		rs.rec.status = http.StatusInternalServerError
		rs.info.outcome = "upstream_error"
		return
	}
	g.connMu.Lock()
	if g.closed.Load() || len(g.tunnels) >= maxProxyTunnels {
		body, outcome := errProxyBusy, "proxy_busy"
		if g.closed.Load() {
			body, outcome = errShuttingDown, "shutting_down"
		}
		g.connMu.Unlock()
		_, _ = fmt.Fprintf(brw, "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nRetry-After: 1\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = brw.Write(body)
		_ = brw.Flush()
		_ = conn.Close()
		rs.rec.status = http.StatusServiceUnavailable
		rs.info.outcome = outcome
		return
	}
	if g.tunnels == nil {
		g.tunnels = make(map[net.Conn]*http.Server)
	}
	g.tunnels[conn] = nil
	g.connMu.Unlock()
	defer func() {
		_ = conn.Close()
		g.connMu.Lock()
		delete(g.tunnels, conn)
		g.connMu.Unlock()
	}()
	rs.info.outcome = "tunnel"
	rs.rec.status = http.StatusOK
	record()
	if _, err := brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || brw.Flush() != nil {
		conn.Close()
		return
	}
	var c net.Conn = conn
	if n := brw.Reader.Buffered(); n > 0 {
		c = &bufferedConn{Conn: conn, r: brw.Reader}
	}
	authority := strings.ToLower(r.Host)
	tlsConn := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, host) {
				return nil, errors.New("TLS server name differs from CONNECT target")
			}
			ca := g.state.Load().ca
			if ca == nil {
				return nil, errors.New("proxy CA removed")
			}
			return ca.leaf(host, g.now())
		},
	})
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, ir *http.Request) {
			rs := &reqState{rec: statusRecorder{ResponseWriter: w, status: http.StatusOK}, start: g.now()}
			rs.state = g.state.Load()
			rs.info.presentedKey = tunnelKeyValue
			if ir.Host != "" && originKey("https", ir.Host) != originKey("https", authority) ||
				ir.URL.IsAbs() && (ir.URL.Scheme != "https" || originKey("https", ir.URL.Host) != originKey("https", authority)) {
				rs.ev = Event{Method: ir.Method, Proxy: true}
				rs.info.outcome = "bad_path"
				writeStaticError(&rs.rec, http.StatusBadRequest, errProxyBadTarget)
				g.finish(ir, rs)
				return
			}
			ir.URL.Scheme, ir.URL.Host, ir.Host = "https", authority, authority
			rs.ev = Event{Method: ir.Method, Path: ir.URL.EscapedPath(), Proxy: true}
			defer g.finish(ir, rs)
			if ir.Method == http.MethodConnect {
				rs.info.outcome = "bad_path"
				writeStaticError(&rs.rec, http.StatusMethodNotAllowed, errProxyBadTarget)
				return
			}
			g.serveProxied(rs, ir, "https", authority, k)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	l := newOneConnListener(tlsConn)
	connectionDone := make(chan struct{})
	var doneOnce sync.Once
	inner.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			l.Close()
			doneOnce.Do(func() { close(connectionDone) })
		}
	}
	g.connMu.Lock()
	if g.closed.Load() {
		g.connMu.Unlock()
		_ = conn.Close()
		return
	}
	g.tunnels[conn] = inner
	g.connMu.Unlock()
	_ = inner.Serve(l)
	// Serve returns as soon as Shutdown closes the listener, while an active
	// HTTP request may still be running. Keep the hijacked connection alive
	// until that request drains or Close forcibly interrupts it.
	l.mu.Lock()
	accepted := l.conn == nil
	l.mu.Unlock()
	if accepted {
		<-connectionDone
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// oneConnListener hands out a single connection and then blocks until it is
// closed, so an http.Server can serve one tunnelled connection.
type oneConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tunnel" }
func (dummyAddr) String() string  { return "tunnel" }

// proxyCA issues short-lived leaf certificates for intercepted upstream hosts.
type proxyCA struct {
	cert    *x509.Certificate
	signer  crypto.Signer
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

const leafValidity = 7 * 24 * time.Hour

func loadProxyCA(certFile, keyFile string) (*proxyCA, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("the proxy CA certificate is not a CA with certificate-signing usage")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("the proxy CA certificate is not currently valid")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported CA key type")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &proxyCA{cert: cert, signer: signer, leafKey: leafKey, cache: map[string]*tls.Certificate{}}, nil
}

func (ca *proxyCA) leaf(host string, now time.Time) (*tls.Certificate, error) {
	host = strings.ToLower(strings.Trim(host, "[]"))
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c := ca.cache[host]; c != nil && now.Add(time.Hour).Before(c.Leaf.NotAfter) {
		return c, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafValidity)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &ca.leafKey.PublicKey, ca.signer)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: ca.leafKey, Leaf: leaf}
	ca.cache[host] = c
	return c, nil
}

// GenerateProxyCA writes a new ECDSA P-256 CA certificate and key for proxy
// mode. The key file is created 0600 and never overwritten.
func GenerateProxyCA(certFile, keyFile string, validity time.Duration) error {
	if validity <= 0 {
		return errors.New("proxy CA validity must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Hootway proxy CA", Organization: []string{"Hootway"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		kf.Close()
		os.Remove(keyFile)
		return err
	}
	if err := kf.Close(); err != nil {
		os.Remove(keyFile)
		return err
	}
	cf, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		os.Remove(keyFile)
		return err
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		cf.Close()
		os.Remove(certFile)
		os.Remove(keyFile)
		return err
	}
	if err := cf.Close(); err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return err
	}
	return nil
}
