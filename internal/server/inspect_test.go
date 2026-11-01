package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestInboundInspectPermissionScopeCSRFRateAndRevocation(t *testing.T) {
	f := setup(t)
	rep := model.Report{ServerID: "one", At: time.Now().Unix(), Interval: 2, Tags: []model.Tag{{Name: "inbound:a", InboundTag: "a", Identity: "inbound", Type: "vless", Egress: "direct", EgressType: "direct", RouteVersion: "fixture"}, {Name: "inbound:b", InboundTag: "b", Identity: "inbound", Type: "socks"}}}
	b, _ := json.Marshal(rep)
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('a-id','one','inbound:a'),('b-id','one','inbound:b')")
	f.db.Exec("INSERT INTO grants VALUES(2,'one','inbound:a')")
	path := filepath.Join(t.TempDir(), "inspect.sock")
	ln, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int64
	var revoke atomic.Bool
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var v map[string]string
		json.NewDecoder(r.Body).Decode(&v)
		if v["tag"] != "a" || v["source"] != "ipinfo" || len(v) != 2 {
			t.Error("untrusted target reached helper", v)
		}
		if revoke.Load() {
			f.db.Exec("DELETE FROM grants WHERE user_id=2")
		}
		io.WriteString(w, `{"source":"ipinfo","message":"fixture"}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.app.ControlServer = "one"
	f.app.ControlSocket = path
	payload := map[string]string{"node_id": "a-id", "action": "intel", "source": "ipinfo"}
	call := func(payload any, csrf string, expected int) {
		r := f.req(t, "POST", "/api/node-inspect", payload, f.user, csrf)
		defer r.Body.Close()
		if r.StatusCode != expected {
			t.Fatalf("status %d expected %d", r.StatusCode, expected)
		}
	}
	call(payload, "", 403)
	call(map[string]string{"node_id": "b-id", "action": "intel", "source": "ipinfo"}, f.ucs, 403)
	call(map[string]string{"node_id": "a-id", "action": "intel", "source": "ipinfo", "url": "http://127.0.0.1"}, f.ucs, 400)
	if calls.Load() != 0 {
		t.Fatal("unauthorized helper request")
	}
	call(payload, f.ucs, 200)
	legacy := f.req(t, "GET", "/api/history?server=one&tag=allowed", nil, f.admin, "")
	legacy.Body.Close()
	if legacy.StatusCode != 403 {
		t.Fatal("retired outbound history exposed")
	}
	revoke.Store(true)
	call(payload, f.ucs, 403)
	revoke.Store(false)
	f.db.Exec("INSERT INTO grants VALUES(2,'one','inbound:a')")
	for n := 0; n < 28; n++ {
		call(payload, f.ucs, 200)
	}
	call(payload, f.ucs, 429)
	if calls.Load() != 30 {
		t.Fatal("rate limit", calls.Load())
	}
	f.db.Exec("DELETE FROM server_grants WHERE user_id=2")
	call(payload, f.ucs, 403)
}
func TestRetiredOutboundArchiveNoLongerExposed(t *testing.T) {
	f := setup(t)
	r := f.req(t, "GET", "/api/archives", nil, f.admin, "")
	defer r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
	r = f.req(t, "POST", "/api/node-inspect", map[string]string{"node_id": "arbitrary", "action": "intel", "source": "https://internal"}, f.admin, f.acs)
	defer r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal(r.StatusCode)
	}
	if strings.Contains(f.app.ControlSocket, "http") {
		t.Fatal("helper must use Unix socket")
	}
}
