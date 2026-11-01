package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/control"
	"tzsingbox/internal/model"
	"tzsingbox/web"
)

// Explicit synthetic browser fixture: no production paths or host activations.
func TestTakeoverBrowserFixture(t *testing.T) {
	target := os.Getenv("TZSING_BROWSER_STAGE")
	if target == "" {
		t.Skip("explicit stage output required")
	}
	f := setup(t)
	f.app.Static = http.FileServer(http.FS(web.Files()))
	d := t.TempDir()
	cfg := filepath.Join(d, "config.json")
	c := map[string]any{"inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen_port": 443, "users": []any{map[string]any{"name": "alice", "uuid": "11111111-1111-4111-8111-111111111111"}, map[string]any{"name": "bob", "uuid": "22222222-2222-4222-8222-222222222222"}}, "tls": map[string]any{"enabled": true, "server_name": "example.com", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": "example.com", "server_port": 443}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "socks", "tag": "relay", "server": "192.0.2.1", "server_port": 1080}}, "route": map[string]any{"final": "direct", "rules": []any{}}}
	raw, _ := json.Marshal(c)
	os.WriteFile(cfg, raw, 0600)
	ctl := &control.Controller{Config: control.ServiceConfig{Config: cfg, State: d, WriteEnabled: true, Endpoints: map[string]control.Endpoint{"shared": {Host: "example.com", Port: 443}}}, Hooks: &control.ApplyHooks{Check: func([]byte) error { return nil }, Activate: func() error { return nil }, Healthy: func(map[string]any) error { return nil }, Probe: func(map[string]any) error { return nil }}}
	sock := filepath.Join(d, "controller.sock")
	ln, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: ctl}
	go srv.Serve(ln)
	defer srv.Close()
	f.app.ControlSocket = sock
	f.app.ControlServer = "one"
	for _, a := range []string{"change", "restore", "copy", "view", "import_shadowrocket", "import_v2rayn"} {
		f.db.Exec("INSERT INTO control_permissions VALUES(1,?)", a)
	}
	f.db.Exec("DELETE FROM servers WHERE id='two'")
	os.WriteFile(target, []byte(f.srv.URL+"/testprefix"), 0600)
	until := time.Now().Add(3 * time.Minute)
	for time.Now().Before(until) {
		if _, e := os.Stat(target + ".done"); e == nil {
			return
		}
		raw, _ := os.ReadFile(cfg)
		var c map[string]any
		json.Unmarshal(raw, &c)
		in := c["inbounds"].([]any)[0].(map[string]any)
		tags := []model.Tag{}
		for _, v := range in["users"].([]any) {
			u := v.(map[string]any)
			id := model.UUIDAuthID(u["uuid"].(string))
			tags = append(tags, model.Tag{Name: model.IdentityName("shared", id), AuthID: id, AuthName: u["name"].(string), AuthScheme: "uuid-v1", InboundTag: "shared", Identity: "inbound", Type: "vless", Accounting: "unavailable", State: "online"})
		}
		report := model.Report{ServerID: "one", At: time.Now().Unix(), Interval: 2, Tags: tags}
		raw, _ = json.Marshal(report)
		f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", raw, time.Now().Unix())
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal("browser stage timeout")
}
