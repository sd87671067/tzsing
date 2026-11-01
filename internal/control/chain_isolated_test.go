package control

import (
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestIsolatedMultiProtocolDetourExit(t *testing.T) {
	if os.Getenv("TZSING_ISOLATED_NETNS") != "1" {
		t.Skip("isolated network namespace required")
	}
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Fatal("isolated binary required")
	}
	dir := t.TempDir()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		io.WriteString(w, host)
	}))
	defer web.Close()
	tlsSource := httptest.NewTLSServer(http.NotFoundHandler())
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSource.Certificate().Raw}))
	key := tlsSource.TLS.Certificates[0].PrivateKey
	_ = key
	tlsSource.Close()
	// Use the known httptest keypair as PEM via X509 marshaling below.
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, []byte(cert), 0600)
	keyBytes, e := marshalTestKey(key)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(keyPath, keyBytes, 0600)
	ports := map[string]int{}
	ins := []any{}
	rules := []any{}
	for _, kind := range []string{"http", "https", "socks", "vless", "trojan", "shadowsocks"} {
		port := freePort(t)
		ports[kind] = port
		in := map[string]any{"tag": kind, "type": kind, "listen": "8.8.8.8", "listen_port": port}
		if kind == "https" {
			in["type"] = "http"
			in["tls"] = map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}
		}
		switch kind {
		case "vless":
			in["users"] = []any{map[string]any{"uuid": "11111111-1111-4111-8111-111111111111"}}
		case "trojan":
			in["users"] = []any{map[string]any{"password": "synthetic-test-secret"}}
			in["tls"] = map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}
		case "shadowsocks":
			in["method"] = "aes-128-gcm"
			in["password"] = "synthetic-test-secret"
		}
		ins = append(ins, in)
		exit := "exit"
		if kind == "socks" {
			exit = "intermediate"
		}
		rules = append(rules, map[string]any{"inbound": []any{kind}, "outbound": exit})
	}
	start := func(name string, config map[string]any) {
		t.Helper()
		path := filepath.Join(dir, name+".json")
		os.WriteFile(path, canonical(config), 0600)
		cmd := exec.Command(binary, "run", "-c", path)
		cmd.Env = append(os.Environ(), "TZSING_POLICY_DB=")
		log, _ := os.Create(filepath.Join(dir, name+".log"))
		cmd.Stderr = log
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
	}
	start("remote", map[string]any{"log": map[string]any{"level": "error"}, "inbounds": ins, "outbounds": []any{map[string]any{"type": "direct", "tag": "exit", "inet4_bind_address": "127.0.0.3"}, map[string]any{"type": "direct", "tag": "intermediate", "inet4_bind_address": "127.0.0.4"}}, "route": map[string]any{"rules": rules}})
	for _, kind := range []string{"http", "https", "socks", "vless", "trojan", "shadowsocks", "selector", "urltest"} {
		t.Run(kind, func(t *testing.T) {
			exitKind := kind
			if kind == "selector" || kind == "urltest" {
				exitKind = "vless"
			}
			root := map[string]any{"type": exitKind, "tag": "destination", "server": "8.8.8.8", "server_port": ports[exitKind], "detour": "transport"}
			if exitKind == "https" {
				root["type"] = "http"
				root["tls"] = map[string]any{"enabled": true, "server_name": "example.com", "certificate": []any{cert}}
			}
			switch exitKind {
			case "vless":
				root["uuid"] = "11111111-1111-4111-8111-111111111111"
			case "trojan":
				root["password"] = "synthetic-test-secret"
				root["tls"] = map[string]any{"enabled": true, "server_name": "example.com", "certificate": []any{cert}}
			case "shadowsocks":
				root["method"] = "aes-128-gcm"
				root["password"] = "synthetic-test-secret"
			}
			outs := []any{root, map[string]any{"type": "socks", "tag": "transport", "server": "8.8.8.8", "server_port": ports["socks"], "detour": "base"}, map[string]any{"type": "http", "tag": "base", "server": "8.8.8.8", "server_port": ports["http"]}, map[string]any{"type": "direct", "tag": "direct"}}
			selected := map[string]string{}
			if kind == "selector" || kind == "urltest" {
				choice := map[string]any{"type": kind, "tag": "choice", "outbounds": []any{"destination", "direct"}}
				outs = append(outs, choice)
				root = choice
				selected["choice"] = "destination"
			}
			graph, e := probeGraph(map[string]any{"outbounds": outs}, root, selected)
			if e != nil {
				t.Fatal(e)
			}
			port := freePort(t)
			start("client-"+kind, map[string]any{"log": map[string]any{"level": "error"}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": graph, "route": map[string]any{"final": root["tag"]}})
			want := "127.0.0.3"
			if kind == "socks" {
				want = "127.0.0.4"
			}
			until := time.Now().Add(4 * time.Second)
			var got string
			var last error
			for time.Now().Before(until) {
				d, _ := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: time.Second})
				tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
				res, e := (&http.Client{Transport: tr, Timeout: time.Second}).Get(web.URL)
				last = e
				if e == nil {
					b, _ := io.ReadAll(res.Body)
					res.Body.Close()
					got = string(b)
				}
				tr.CloseIdleConnections()
				if got == want {
					break
				}
				time.Sleep(30 * time.Millisecond)
			}
			if got != want {
				for _, n := range []string{"remote", "client-" + kind} {
					b, _ := os.ReadFile(filepath.Join(dir, n+".log"))
					t.Log(n, string(b))
				}
				t.Fatal("final exit differs from destination proxy; intermediate must not be reported", got, last)
			}
		})
	}
}

func marshalTestKey(key any) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
