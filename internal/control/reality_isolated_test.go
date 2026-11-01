package control

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

// No host service commands: the only activations are disposable subprocesses.
func TestIsolatedRealityCreateShared443AndRollback(t *testing.T) {
	if os.Getenv("TZSING_ISOLATED_NETNS") != "1" {
		t.Skip("isolated netns required")
	}
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Skip("explicit isolated binary required")
	}
	dir := t.TempDir()
	shared, upstream, ca, cb := 443, freePort(t), freePort(t), freePort(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		io.WriteString(w, host)
	}))
	defer web.Close()
	socks := func(port int) map[string]any {
		return map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port}
	}
	direct := func(bind string) map[string]any {
		return map[string]any{"type": "direct", "tag": "direct", "inet4_bind_address": bind}
	}
	// Check installed sing-box option spelling before any subprocess is started.
	alice := "11111111-1111-4111-8111-111111111111"
	bob := "22222222-2222-4222-8222-222222222222"
	id := model.UUIDAuthID(alice)
	main := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": shared, "users": []any{map[string]any{"name": "alice", "uuid": alice}, map[string]any{"name": "bob", "uuid": bob}}}}, "outbounds": []any{direct("127.0.0.2")}, "route": map[string]any{"final": "direct", "rules": []any{}}}
	handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "handshake") }))
	handshake.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	handshake.StartTLS()
	defer handshake.Close()
	hh, hp, _ := net.SplitHostPort(handshake.Listener.Addr().String())
	hport, _ := strconv.Atoi(hp)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	in := findInbound(main, "shared")
	in["tls"] = map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": hh, "server_port": hport}}}
	for _, v := range array(in["users"]) {
		object(v)["flow"] = "xtls-rprx-vision"
	}
	clientTLS := map[string]any{"enabled": true, "server_name": "localhost", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "short_id": "0123456789abcdef"}}
	path := filepath.Join(dir, "main.json")
	raw := canonical(main)
	os.WriteFile(path, raw, 0600)
	check := func(b []byte) error {
		p := filepath.Join(dir, "check.json")
		if e := os.WriteFile(p, b, 0600); e != nil {
			return e
		}
		cmd := exec.Command(binary, "check", "-c", p)
		if out, e := cmd.CombinedOutput(); e != nil {
			return errors.New(string(out))
		}
		return nil
	}
	if e := check(raw); e != nil {
		t.Fatal(e)
	}
	start := func(name string, c map[string]any) {
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, canonical(c), 0600)
		cmd := exec.Command(binary, "run", "-c", p)
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	start("upstream", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(upstream)}, "outbounds": []any{direct("127.0.0.3")}})
	for _, c := range []struct {
		uuid string
		port int
	}{{alice, ca}, {bob, cb}} {
		start(strconv.Itoa(c.port), map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(c.port)}, "outbounds": []any{map[string]any{"type": "vless", "tag": "remote", "server": "127.0.0.1", "server_port": shared, "uuid": c.uuid, "flow": "xtls-rprx-vision", "tls": clientTLS}}})
	}
	var current *exec.Cmd
	activations := 0
	failRestart, failHealth := false, false
	healthActivation := 0
	activate := func() error {
		activations++
		if current != nil {
			current.Process.Kill()
			current.Wait()
			current = nil
		}
		if failRestart {
			failRestart = false
			return errors.New("injected restart failure")
		}
		current = exec.Command(binary, "run", "-c", path)
		return current.Start()
	}
	defer func() {
		if current != nil {
			current.Process.Kill()
			current.Wait()
		}
	}()
	request := func(port int) (string, error) {
		d, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: time.Second})
		if e != nil {
			return "", e
		}
		tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
		defer tr.CloseIdleConnections()
		res, e := (&http.Client{Transport: tr, Timeout: 500 * time.Millisecond}).Get(web.URL)
		if e != nil {
			return "", e
		}
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		return string(b), e
	}
	wait := func(port int, want string) error {
		until := time.Now().Add(4 * time.Second)
		for time.Now().Before(until) {
			s, e := request(port)
			if e == nil && s == want {
				return nil
			}
			time.Sleep(30 * time.Millisecond)
		}
		return errors.New("isolated path did not match " + want)
	}
	healthy := func(map[string]any) error {
		if failHealth && activations == healthActivation {
			failHealth = false
			return errors.New("injected health failure")
		}
		return wait(cb, "127.0.0.2")
	}
	if e := activate(); e != nil {
		t.Fatal(e)
	}
	if e := wait(ca, "127.0.0.2"); e != nil {
		t.Fatal(e)
	}
	if e := wait(cb, "127.0.0.2"); e != nil {
		t.Fatal(e)
	}
	c := &Controller{Config: ServiceConfig{Config: path, State: dir}, Hooks: &ApplyHooks{Check: check, Activate: activate, Healthy: healthy, Probe: func(map[string]any) error { return nil }}}
	out := map[string]any{"type": "socks", "tag": managedTag(identityKey("shared", id)), "server": "127.0.0.1", "server_port": upstream}
	changed, s, e := ChangeIdentity(raw, "shared", id, out, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(raw), Tag: "shared", AuthID: id, Candidate: changed, Snapshot: s}); e != nil {
		t.Fatal(e)
	}
	if e = wait(ca, "127.0.0.3"); e != nil {
		t.Fatal("target actual exit did not change", e)
	}
	if e = wait(cb, "127.0.0.2"); e != nil {
		t.Fatal("peer changed", e)
	}
	restored, e := RestoreIdentity(changed, "shared", id, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(changed), Tag: "shared", AuthID: id, Candidate: restored, Restore: true}); e != nil {
		t.Fatal(e)
	}
	if e = wait(ca, "127.0.0.2"); e != nil {
		t.Fatal("original path did not return", e)
	}
	base, _ := os.ReadFile(path)
	for _, mode := range []string{"restart", "health"} {
		changed, s, e = ChangeIdentity(base, "shared", id, out, nil)
		if e != nil {
			t.Fatal(e)
		}
		if mode == "restart" {
			failRestart = true
		} else {
			failHealth = true
			healthActivation = activations + 1
		}
		e = c.apply(plan{Hash: digest(base), Tag: "shared", AuthID: id, Candidate: changed, Snapshot: s})
		if e == nil || !strings.Contains(e.Error(), "已恢复") {
			t.Fatal(mode, e)
		}
		after, _ := os.ReadFile(path)
		if digest(after) != digest(base) {
			t.Fatal("rollback bytes differ")
		}
		if e = wait(ca, "127.0.0.2"); e != nil {
			t.Fatal(e)
		}
		if e = wait(cb, "127.0.0.2"); e != nil {
			t.Fatal(e)
		}
	}
	// Use the actual UUID preview/apply APIs, not just candidate helpers.
	c.Config.WriteEnabled = true
	call := func(path string, body any) map[string]any {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(string(canonical(body)))))
		if w.Code != 200 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body.String())
		}
		return candidateMap(w.Body.Bytes())
	}
	beforeCreate, _ := os.ReadFile(path)
	fresh := "33333333-3333-4333-8333-333333333333"
	preview := call("/uuid-preview", map[string]any{"node": UUIDNodeRequest{Inbound: "shared", Name: "new", UUID: fresh, Outbound: "direct", Enabled: true}})
	call("/uuid-apply", map[string]any{"plan": preview["plan"]})
	replay := httptest.NewRecorder()
	c.ServeHTTP(replay, httptest.NewRequest("POST", "/uuid-apply", strings.NewReader(string(canonical(map[string]any{"plan": preview["plan"]})))))
	if replay.Code != 409 {
		t.Fatal("create token replay")
	}
	afterCreate, _ := os.ReadFile(path)
	if !reflect.DeepEqual(findInbound(candidateMap(beforeCreate), "shared")["tls"], findInbound(candidateMap(afterCreate), "shared")["tls"]) {
		t.Fatal("shared REALITY changed")
	}
	cc := freePort(t)
	start("new-client", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(cc)}, "outbounds": []any{map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": 443, "uuid": fresh, "flow": "xtls-rprx-vision", "tls": clientTLS}}})
	if e = wait(cc, "127.0.0.2"); e != nil {
		t.Fatal("new real REALITY UUID cannot connect", e)
	}
	if e = wait(cb, "127.0.0.2"); e != nil {
		t.Fatal("peer after creation", e)
	}
	deleted, e := IdentityMutation(afterCreate, "shared", model.UUIDAuthID(fresh), "delete")
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(afterCreate), Tag: "shared", AuthID: model.UUIDAuthID(fresh), Action: "delete", Candidate: deleted}); e != nil {
		t.Fatal(e)
	}
	if _, e = request(cc); e == nil {
		t.Fatal("deleted UUID still connects")
	}
	if e = wait(cb, "127.0.0.2"); e != nil {
		t.Fatal("peer after deletion", e)
	}
	for _, action := range []string{"disable", "enable", "delete"} {
		before, _ := os.ReadFile(path)
		candidate, e := IdentityMutation(before, "shared", id, action)
		if e != nil {
			t.Fatal(action, e)
		}
		if e = c.apply(plan{Hash: digest(before), Tag: "shared", AuthID: id, Action: action, Candidate: candidate}); e != nil {
			t.Fatal(action, e)
		}
		if e = wait(cb, "127.0.0.2"); e != nil {
			t.Fatal("peer lost", e)
		}
		if action == "enable" {
			if e = wait(ca, "127.0.0.2"); e != nil {
				t.Fatal(e)
			}
		} else {
			if _, e = request(ca); e == nil {
				t.Fatal("disabled/deleted identity still works")
			}
		}
	}
}
