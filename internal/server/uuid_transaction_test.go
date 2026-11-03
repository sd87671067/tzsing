package server

import (
	"crypto/tls"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/control"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
	"tzsingbox/web"
)

// The whole Web -> Unix controller -> atomic config/receipt path uses disposable
// files. Hooks replace only service activation/validation, never production.
func uuidTransactionFixture(t *testing.T, dropResponses ...bool) (*fixture, func()) {
	f := setup(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "singbox.json")
	raw := []byte(`{"inbounds":[{"tag":"shared","type":"vless","listen_port":443,"users":[{"name":"original","uuid":"11111111-1111-4111-8111-111111111111"}],"tls":{"enabled":true,"reality":{"enabled":true}}}],"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}`)
	os.WriteFile(path, raw, 0600)
	ctrl := &control.Controller{Config: control.ServiceConfig{Config: path, State: dir, WriteEnabled: true}, Hooks: &control.ApplyHooks{Probe: func(map[string]any) error { return nil }, Check: func([]byte) error { return nil }, Activate: func() error { time.Sleep(100 * time.Millisecond); return nil }, Healthy: func(map[string]any) error { return nil }}}
	report := func() {
		b, _ := os.ReadFile(path)
		var config struct {
			Inbounds []struct {
				Tag   string
				Users []struct{ Name, UUID string }
			}
		}
		json.Unmarshal(b, &config)
		tags := []model.Tag{}
		zero := float64(0)
		count := int64(0)
		for _, in := range config.Inbounds {
			for _, u := range in.Users {
				id := model.UUIDAuthID(u.UUID)
				tags = append(tags, model.Tag{Name: model.IdentityName(in.Tag, id), AuthID: id, AuthScheme: "uuid-v1", AuthName: u.Name, InboundTag: in.Tag, Identity: "inbound", Type: "vless", Accounting: "native_user_observed", Egress: "direct", EgressType: "direct", PolicyState: "reserved_uncertain", Up: &zero, Down: &zero, Upload: &count, Download: &count})
			}
		}
		b, _ = json.Marshal(model.Report{ServerID: "one", At: time.Now().Unix(), Interval: 2, Tags: tags})
		f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	}
	report()
	ln, e := net.Listen("unix", filepath.Join(dir, "controller.sock"))
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/uuid-apply" && len(dropResponses) > 0 && dropResponses[0] {
			recorder := httptest.NewRecorder()
			ctrl.ServeHTTP(recorder, r)
			report()
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		ctrl.ServeHTTP(w, r)
		if r.URL.Path == "/uuid-apply" {
			report()
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.app.ControlSocket = ln.Addr().String()
	f.app.ControlServer = "one"
	f.db.Exec("INSERT INTO control_permissions VALUES(1,'change')")
	return f, report
}
func TestUUIDTransactionNamesRediscoveryAndWebRestart(t *testing.T) {
	f, report := uuidTransactionFixture(t, true)
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	headers := http.Header{"Cookie": []string{f.admin.String()}, "Origin": []string{f.srv.URL}}
	ws, _, err := dialer.Dial("wss"+strings.TrimPrefix(f.srv.URL, "https")+"/testprefix/ws", headers)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var tokens []string
	for _, name := range []string{"ck", "second"} {
		r := f.req(t, "POST", "/api/admin/node-preview", map[string]any{"server": "one", "node": control.UUIDNodeRequest{Inbound: "shared", Name: name, Enabled: true}}, f.admin, f.acs)
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(v)
		}
		token := v["nonce"].(string)
		tokens = append(tokens, token)
		for i := 0; i < 2; i++ {
			r = f.req(t, "POST", "/api/admin/node-create", map[string]string{"server": "one", "nonce": token}, f.admin, f.acs)
			r.Body.Close()
			if r.StatusCode != 202 {
				t.Fatal(r.StatusCode)
			}
		}
		deadline := time.Now().Add(4 * time.Second)
		for {
			r = f.req(t, "GET", "/api/admin/node-transaction?id="+token, nil, f.admin, "")
			json.NewDecoder(r.Body).Decode(&v)
			r.Body.Close()
			if v["state"] == "succeeded" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(v)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var views []model.View
		if err := ws.ReadJSON(&views); err != nil {
			t.Fatal("WebSocket updates", err)
		}
		names := map[string]int{}
		for _, view := range views {
			for _, tag := range view.Report.Tags {
				names[tag.Name]++
			}
		}
		if names["ck"] == 1 && names["second"] == 1 {
			break
		}
	}
	// Rediscovery and rebuilding the Web app must retain opaque IDs and all names.
	before := map[string]string{}
	rows, _ := f.db.Query("SELECT id,name FROM nodes WHERE name!=''")
	for rows.Next() {
		var id, name string
		rows.Scan(&id, &name)
		before[id] = name
	}
	rows.Close()
	report()
	replacement := New(f.db, f.app.Prefix, f.app.Origin, http.NotFoundHandler())
	replacement.ControlSocket = f.app.ControlSocket
	replacement.ControlServer = f.app.ControlServer
	for _, token := range tokens {
		w := httptest.NewRecorder()
		replacement.uuidOperationStatus(w, httptest.NewRequest("GET", "/?id="+token, nil), store.User{ID: 1, Role: "admin"})
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	reopenedPath := filepath.Join(t.TempDir(), "restart.db")
	if _, e := f.db.Exec("VACUUM INTO ?", reopenedPath); e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(reopenedPath)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	views, e := reopened.ManagementViews(store.User{ID: 1, Role: "admin"})
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, v := range views {
		for _, tag := range v.Report.Tags {
			seen[tag.Name] = true
		}
	}
	if !seen["ck"] || !seen["second"] {
		t.Fatal(seen)
	}
	for id, name := range before {
		var got string
		f.db.QueryRow("SELECT name FROM nodes WHERE id=?", id).Scan(&got)
		if got != name {
			t.Fatal("identity/name changed")
		}
	}
}

func TestUUIDTransactionBrowserStage(t *testing.T) {
	dir := os.Getenv("TZSING_UUID_BROWSER_STAGE")
	if dir == "" {
		t.Skip("isolated browser fixture opt-in")
	}
	os.MkdirAll(dir, 0700)
	f, _ := uuidTransactionFixture(t)
	f.app.Static = http.FileServer(http.FS(web.Files()))
	data, _ := json.Marshal(map[string]any{"base": f.srv.URL + "/testprefix", "admin": "administrator-test-password"})
	os.WriteFile(filepath.Join(dir, "browser.json"), data, 0600)
	deadline := time.After(6 * time.Minute)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("browser stage timed out")
		case <-ticker.C:
			if _, e := os.Stat(filepath.Join(dir, "done")); e == nil {
				return
			}
		}
	}
}

// A persisted intent has survived SQLite close/reopen while Web's confirmation
// cache and workers are gone. The status endpoint must dispatch the same plan.
func TestUUIDPendingIntentAfterSQLiteReopen(t *testing.T) {
	f, _ := uuidTransactionFixture(t, true)
	r := f.req(t, "POST", "/api/admin/node-preview", map[string]any{"server": "one", "node": control.UUIDNodeRequest{Inbound: "shared", Name: "ck", Enabled: true}}, f.admin, f.acs)
	var v map[string]any
	json.NewDecoder(r.Body).Decode(&v)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(v)
	}
	token := v["nonce"].(string)
	id := auth.Digest(token)
	f.app.mu.Lock()
	intent := f.app.controlNonces[id]
	f.app.mu.Unlock()
	if _, e := f.db.Exec("INSERT INTO uuid_operations(id,user_id,server,plan,name,tag,created) VALUES(?,1,'one',?,?,?,?)", id, intent.Plan, intent.Node, intent.IdentityTag, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "reopened.db")
	if _, e := f.db.Exec("VACUUM INTO ?", path); e != nil {
		t.Fatal(e)
	}
	db, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	db, e = store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	app := New(db, f.app.Prefix, f.app.Origin, http.NotFoundHandler())
	app.ControlSocket = f.app.ControlSocket
	app.ControlServer = f.app.ControlServer
	until := time.Now().Add(5 * time.Second)
	for {
		w := httptest.NewRecorder()
		app.uuidOperationStatus(w, httptest.NewRequest("GET", "/?id="+token, nil), store.User{ID: 1, Role: "admin"})
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		json.Unmarshal(w.Body.Bytes(), &v)
		if v["state"] == "succeeded" {
			break
		}
		if time.Now().After(until) {
			t.Fatal(v)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var name string
	var count int
	db.QueryRow("SELECT count(*),name FROM nodes WHERE server='one' AND tag=?", intent.IdentityTag).Scan(&count, &name)
	if count != 1 || name != "ck" {
		t.Fatal(count, name)
	}
}
