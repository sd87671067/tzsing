package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/model"
	"tzsingbox/web"
)

// Explicit opt-in disposable browser fixture, with a synthetic controller. This
// validates UI only; real configuration execution is tested in control package.
func TestAdminBrowserStage(t *testing.T) {
	dir := os.Getenv("TZSING_BROWSER_STAGE")
	if dir == "" {
		t.Skip("browser fixture opt-in")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := setup(t)
	f.app.Static = http.FileServer(http.FS(web.Files()))
	socket := filepath.Join(t.TempDir(), "browser.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/outbound-catalog":
			io.WriteString(w, `{"items":[{"tag":"relay","protocol":"http","references":[]}]}`)
		case "/status":
			io.WriteString(w, `{"share":true,"apply":true,"restore":true,"preview":true,"profiles":[{"id":"single","label":"当前 UUID"}],"reason":"隔离 UI 夹具"}`)
		case "/share":
			io.WriteString(w, `{"link":"vless://11111111-1111-4111-8111-111111111111@example.org:443?security=reality&pbk=public"}`)
		case "/intel":
			io.WriteString(w, `{"source":"ipinfo","at":1793520000,"data":{"country_code":"US","city":"Fixture"}}`)
		case "/diagnostics":
			json.NewEncoder(w).Encode(map[string]any{"at": time.Now().Unix(), "outbound": "relay", "ip": model.Exit{Verified: true, IPv4: "9.9.9.9", CountryCode: "US", Updated: time.Now().Unix(), Path: "relay@fixture"}, "network": map[string]any{"ipv4": map[string]any{"status": "ok", "ip": "9.9.9.9"}, "successes": 1, "attempts": 2}})
		case "/preview", "/restore-preview":
			io.WriteString(w, `{"plan":"synthetic-plan","preview":{"protocol":"socks","server":"***.example.org","port":1080},"effects":{"shared_listener":443,"other_uuids":1,"listeners":[{"tag":"shared","port":443}]},"writable":true,"impact":"仅 UI 夹具"}`)
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	f.app.ControlServer = "one"
	for _, action := range []string{"copy", "view", "change", "restore", "import_v2rayn", "import_shadowrocket"} {
		f.db.Exec("INSERT INTO control_permissions VALUES(1,?)", action)
	}
	tags := []model.Tag{}
	for _, pair := range []struct{ id, name string }{{"11111111-1111-4111-8111-111111111111", "Alice"}, {"22222222-2222-4222-8222-222222222222", "Bob"}} {
		id := model.UUIDAuthID(pair.id)
		tag := model.IdentityName("shared", id)
		zero := float64(0)
		count := int64(0)
		tags = append(tags, model.Tag{Name: tag, AuthName: pair.name, AuthID: id, AuthScheme: "uuid-v1", InboundTag: "shared", Identity: "inbound", Type: "vless", Accounting: "native_user_observed", Up: &zero, Down: &zero, Upload: &count, Download: &count, RouteVersion: "fixture", Egress: "relay", Egresses: []model.EgressPath{{Tag: "relay", Type: "socks", IP: &model.Exit{Verified: true, IPv4: "8.8.8.8", CountryCode: "US", Path: "relay@fixture", Updated: time.Now().Unix()}}}})
	}
	for i, tag := range tags {
		f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES(?, 'one',?)", []string{"alice", "bob"}[i], tag.Name)
	}
	f.db.Exec("DELETE FROM grants WHERE user_id=2")
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", tags[0].Name)
	f.db.Exec("INSERT INTO uuid_permissions VALUES(2,'alice',1,1,1,1)")
	o, _ := f.db.RegisterOutbound("one", "relay", "合成出站", 0)
	f.db.Exec("INSERT INTO uuid_outbound_grants VALUES(2,'alice',?)", o.ID)
	data, _ := json.Marshal(map[string]any{"base": f.srv.URL + "/testprefix", "admin": "administrator-test-password", "viewer": "viewer-test-password"})
	if e = os.WriteFile(filepath.Join(dir, "browser.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	deadline := time.After(10 * time.Minute)
	for {
		select {
		case <-deadline:
			t.Fatal("browser stage timed out")
		case <-tick.C:
			if _, e := os.Stat(filepath.Join(dir, "done")); e == nil {
				return
			}
			b, _ := json.Marshal(model.Report{ServerID: "one", At: time.Now().Unix(), Interval: 2, Tags: tags})
			f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
		}
	}
}
