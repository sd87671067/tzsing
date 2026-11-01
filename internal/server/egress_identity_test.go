package server

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestUUIDInspectSelectedPathAndPermissionRevocation(t *testing.T) {
	f := setup(t)
	id := model.AuthID("alice")
	raw := model.IdentityName("shared", id)
	paths := []model.EgressPath{{Tag: "direct", Type: "direct", IP: &model.Exit{Verified: true, IPv4: "8.8.8.8", Updated: time.Now().Unix(), Path: "direct@one"}}, {Tag: "relay", Type: "socks", IP: &model.Exit{Verified: true, IPv4: "1.1.1.1", Updated: time.Now().Unix(), Path: "relay@one"}}}
	report := model.Report{ServerID: "one", At: time.Now().Unix(), Tags: []model.Tag{{Name: raw, InboundTag: "shared", AuthID: id, Identity: "inbound", Type: "vless", Accounting: "rule_user_observed", RouteVersion: "one", Egresses: paths}}}
	b, _ := json.Marshal(report)
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('uuid','one',?)", raw)
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
	socket := filepath.Join(t.TempDir(), "inspect.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int64
	var revoke atomic.Bool
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var v map[string]string
		json.NewDecoder(r.Body).Decode(&v)
		if v["tag"] != "shared" || v["auth_id"] != id || v["outbound"] != "relay" || v["route_version"] != "one" || v["previous_ipv4"] != "1.1.1.1" {
			t.Error("wrong server-owned identity/path", v)
		}
		if revoke.Load() {
			f.db.Exec("DELETE FROM grants WHERE user_id=2")
		}
		w.Write([]byte(`{"source":"ipinfo","outbound":"relay","data":{"country":"US"}}`))
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlServer = "one"
	f.app.ControlSocket = socket
	payload := map[string]any{"node_id": "uuid", "action": "intel", "source": "ipinfo", "path_index": 1}
	call := func(want int) {
		r := f.req(t, "POST", "/api/node-inspect", payload, f.user, f.ucs)
		defer r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("status %d want %d", r.StatusCode, want)
		}
	}
	call(200)
	snapshot := f.req(t, "GET", "/api/snapshot", nil, f.user, "")
	var views []model.View
	json.NewDecoder(snapshot.Body).Decode(&views)
	snapshot.Body.Close()
	if len(views) != 1 || len(views[0].Report.Tags) != 1 || len(views[0].Report.Tags[0].Egresses) != 2 {
		t.Fatal("authorized paths lost")
	}
	out, _ := json.Marshal(views)
	if strings.Contains(string(out), "relay") || strings.Contains(string(out), "direct@one") || strings.Contains(string(out), id) {
		t.Fatal("hidden internal identity leaked")
	}
	payload["path_index"] = 9
	call(422)
	if calls.Load() != 1 {
		t.Fatal("invalid path reached helper")
	}
	payload["path_index"] = 1
	revoke.Store(true)
	call(403)
	call(403)
	if calls.Load() != 2 {
		t.Fatal("revocation ignored")
	}
}
