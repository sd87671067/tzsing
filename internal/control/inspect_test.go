package control

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadonlyInspectionLocalListenerUnknownPathAndLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	raw, _ := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"tag": "a", "type": "socks", "listen": "127.0.0.1", "listen_port": ln.Addr().(*net.TCPAddr).Port}}})
	os.WriteFile(path, raw, 0600)
	checks := 0
	activated := 0
	c := &Controller{Config: ServiceConfig{Config: path, State: dir, AgentConfig: filepath.Join(dir, "nonexistent")}, Hooks: &ApplyHooks{Check: func([]byte) error { checks++; return nil }, Activate: func() error { activated++; return nil }}}
	request := func(endpoint, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", endpoint, strings.NewReader(body))
		w := httptest.NewRecorder()
		c.ServeHTTP(w, r)
		return w
	}
	out := request("/diagnostics", `{"tag":"a"}`)
	if out.Code != 422 || !strings.Contains(out.Body.String(), "无法指定") {
		t.Fatal(out.Code, out.Body.String())
	}
	if checks != 0 || activated != 0 {
		t.Fatal("HTTP exit checks must not inspect listener or restart")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("production config mutated")
	}
	if request("/diagnostics", `{"tag":"a"}`).Code != 429 {
		t.Fatal("node rate missing")
	}
	if request("/intel", `{"tag":"a","source":"ippure"}`).Code != 200 {
		t.Fatal("independent provider path")
	}
	if request("/intel", `{"tag":"a","source":"http://127.0.0.1"}`).Code != 400 {
		t.Fatal("unbounded provider")
	}
	c.inspectLast = map[string]time.Time{}
	c.mu.Lock()
	if request("/diagnostics", `{"tag":"a"}`).Code != 429 {
		t.Fatal("concurrency limit missing")
	}
	c.mu.Unlock()
	if request("/diagnostics", `{"tag":"missing"}`).Code != 403 {
		t.Fatal("unknown config tag accepted")
	}
	if localAddress("example.com") || localAddress("192.0.2.123") {
		t.Fatal("nonlocal scanning target")
	}
}
