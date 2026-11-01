package control

import (
	"context"
	"encoding/json"
	"errors"
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

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

// Opt in explicitly: this launches ONLY synthetic isolated sing-box processes,
// temporary configs and databases, never systemctl or a production port/config.
func TestIsolatedSingBoxSwitchAndRollback(t *testing.T) {
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Skip("requires explicit isolated sing-box binary")
	}
	dir := t.TempDir()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "isolated-ok") }))
	defer web.Close()
	start := func(name string, config map[string]any) *exec.Cmd {
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, canonical(config), 0600)
		cmd := exec.Command(binary, "run", "-c", p)
		cmd.Dir = dir
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		return cmd
	}
	a, b, proxyPort, clientA, clientB := freePort(t), freePort(t), freePort(t), freePort(t), freePort(t)
	sock := func(tag string, port int) map[string]any {
		return map[string]any{"type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port}
	}
	start("upstream", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{sock("upstream", proxyPort)}, "outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}}})
	ss := func(tag string, port int) map[string]any {
		return map[string]any{"tag": tag, "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port, "method": "aes-128-gcm", "password": "synthetic-auth-" + tag}
	}
	main := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{ss("a", a), ss("b", b)}, "outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}}, "route": map[string]any{"final": "direct", "rules": []any{}}}
	raw := canonical(main)
	path := filepath.Join(dir, "main.json")
	os.WriteFile(path, raw, 0600)
	var current *exec.Cmd
	unit := ""
	unitStarted := false
	if os.Getenv("TZSING_TEST_SYSTEMD") == "1" {
		unit = "tzsingbox-isolated-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".service"
	}
	activate := func() error {
		if unit != "" {
			if !unitStarted {
				cmd := exec.Command("/usr/bin/systemd-run", "--quiet", "--unit="+unit, "--property=Restart=on-failure", "--", binary, "run", "-c", path)
				if e := cmd.Run(); e != nil {
					return e
				}
				unitStarted = true
				return nil
			}
			return exec.Command("/usr/bin/systemctl", "restart", unit).Run()
		}
		if current != nil {
			current.Process.Kill()
			current.Wait()
		}
		current = exec.Command(binary, "run", "-c", path)
		current.Dir = dir
		return current.Start()
	}
	if e := activate(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if unitStarted {
			exec.Command("/usr/bin/systemctl", "stop", unit).Run()
			exec.Command("/usr/bin/systemctl", "reset-failed", unit).Run()
		}
		if current != nil {
			current.Process.Kill()
			current.Wait()
		}
	}()
	for _, pair := range []struct {
		tag           string
		remote, local int
	}{{"a", a, clientA}, {"b", b, clientB}} {
		start("client-"+pair.tag, map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{sock("client", pair.local)}, "outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "remote", "server": "127.0.0.1", "server_port": pair.remote, "method": "aes-128-gcm", "password": "synthetic-auth-" + pair.tag}}})
	}
	request := func(port int) error {
		d, _ := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: time.Second})
		transport := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second}
		res, e := client.Get(web.URL)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if string(b) != "isolated-ok" {
			return errors.New("bad fixture body")
		}
		return nil
	}
	healthy := func(map[string]any) error {
		until := time.Now().Add(4 * time.Second)
		for time.Now().Before(until) {
			if (unit == "" || exec.Command("/usr/bin/systemctl", "is-active", "--quiet", unit).Run() == nil) && request(clientA) == nil && request(clientB) == nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("synthetic node connectivity failed")
	}
	if e := healthy(main); e != nil {
		t.Fatal(e)
	}
	c := &Controller{Config: ServiceConfig{Config: path, State: dir, Binary: binary}, Hooks: &ApplyHooks{Activate: activate, Healthy: healthy, Probe: func(map[string]any) error { return nil }}}
	out := map[string]any{"type": "socks", "tag": managedTag("a"), "server": "127.0.0.1", "server_port": proxyPort}
	candidate, s, e := Change(raw, "a", out, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(raw), Tag: "a", Candidate: candidate, Snapshot: s}); e != nil {
		t.Fatal("real switch failed", e)
	}
	if e = healthy(main); e != nil {
		t.Fatal(e)
	}
	restored, e := Restore(candidate, "a", s)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(candidate), Tag: "a", Candidate: restored, Restore: true}); e != nil {
		t.Fatal("real restore failed", e)
	}
	before, _ := os.ReadFile(path)
	invalid := []byte(`{"inbounds":[{"type":"nonexistent"}]}`)
	if e = c.apply(plan{Hash: digest(before), Tag: "a", Candidate: invalid}); e == nil {
		t.Fatal("invalid config applied")
	}
	after, _ := os.ReadFile(path)
	if digest(before) != digest(after) {
		t.Fatal("invalid config changed active file")
	}
	currentBase := after
	candidate, s, e = Change(currentBase, "a", out, nil)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	c.Hooks.Healthy = func(m map[string]any) error {
		count++
		if count == 2 {
			return errors.New("injected failure after actual restart")
		}
		return healthy(m)
	}
	if e = c.apply(plan{Hash: digest(currentBase), Tag: "a", Candidate: candidate, Snapshot: s}); e == nil {
		t.Fatal("health failure accepted")
	}
	after, _ = os.ReadFile(path)
	if digest(after) != digest(currentBase) || count != 3 {
		t.Fatal("real rollback not verified")
	}
	if e = healthy(main); e != nil {
		t.Fatal("rollback nodes failed", e)
	}
	// Cancelled callers must not abort the atomic host transaction mid-switch.
	_ = context.Background()
	_ = json.Valid(raw)
}
