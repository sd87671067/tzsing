package server

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func TestOutboundDisplayNameAcrossCatalogsSnapshotsAndPersistence(t *testing.T) {
	f := setup(t)
	f.app.ControlServer = "one"
	f.db.Exec("INSERT INTO control_permissions VALUES(1,'change')")
	config := []byte(`{"outbounds":[{"tag":"us-out-01","type":"direct"}],"route":{"final":"us-out-01"}}`)
	before := sha256.Sum256(config)
	mutations := 0
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "names.sock"))
	if err != nil {
		t.Fatal(err)
	}
	f.app.ControlSocket = ln.Addr().String()
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/outbound-catalog":
			json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"tag": "us-out-01"}, map[string]any{"tag": "hk-out"}}})
		case "/uuid-catalog":
			json.NewEncoder(w).Encode(map[string]any{"outbounds": []any{map[string]any{"tag": "us-out-01"}}})
		case "/outbound-preview":
			json.NewEncoder(w).Encode(map[string]any{"plan": "save-plan"})
		case "/outbound-apply":
			mutations++
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "tag": "us-out-01"})
		default:
			t.Errorf("unexpected controller mutation %s", r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	registry, err := f.db.RegisterOutbound("one", "us-out-01", "us-out-01", 0)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string, value any) map[string]any {
		method := "POST"
		if value == nil {
			method = "GET"
		}
		res := f.req(t, method, path, value, f.admin, f.acs)
		defer res.Body.Close()
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d %v", path, res.StatusCode, out)
		}
		return out
	}
	plan := request("/api/admin/outbounds", map[string]any{"action": "save", "name": "美国洛杉矶", "node": map[string]any{}})
	request("/api/admin/outbounds", map[string]any{"action": "apply", "nonce": plan["nonce"]})
	if f.db.OutboundDisplayName("one", "us-out-01") != "美国洛杉矶" {
		t.Fatal("new name not saved")
	}
	report := model.Report{At: time.Now().Unix(), Tags: []model.Tag{{Name: "inbound:shared", Identity: "inbound", InboundTag: "shared", Egress: "us-out-01", Egresses: []model.EgressPath{{Tag: "us-out-01", Type: "direct"}}, Type: "direct"}}}
	b, _ := json.Marshal(report)
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	for _, name := range []string{"美国高速线路", "同名出口", ""} {
		request("/api/admin/outbounds", map[string]any{"action": "rename", "name": name, "node": map[string]any{"tag": "us-out-01"}})
		want := name
		if want == "" {
			want = "us-out-01"
		}
		for _, path := range []string{"/api/admin/outbounds", "/api/admin/node-catalog"} {
			out := request(path, nil)
			key := "items"
			if path == "/api/admin/node-catalog" {
				key = "outbounds"
			}
			item := out[key].([]any)[0].(map[string]any)
			if item["tag"] != "us-out-01" || item["name"] != want {
				t.Fatalf("%s: %v", path, item)
			}
		}
		views, err := f.db.Views(store.User{ID: 1, Role: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		tag := views[0].Report.Tags[0]
		if tag.Egress != "us-out-01" || tag.EgressName != want || tag.Egresses[0].Name != want || tag.Egresses[0].Tag != "us-out-01" {
			t.Fatalf("snapshot %+v", tag)
		}
		current, _ := f.db.Outbound(registry.ID)
		if current.ID != registry.ID || current.Tag != "us-out-01" {
			t.Fatal("stable identity changed")
		}
	}
	request("/api/admin/outbounds", map[string]any{"action": "rename", "name": "同名出口", "node": map[string]any{"tag": "us-out-01"}})
	request("/api/admin/outbounds", map[string]any{"action": "rename", "name": "同名出口", "node": map[string]any{"tag": "hk-out"}})
	other, _ := f.db.RegisterOutbound("one", "hk-out", "hk-out", 0)
	if other.ID == registry.ID {
		t.Fatal("duplicate names merged identities")
	}
	var seq int
	var dbname, dbpath string
	f.db.QueryRow("PRAGMA database_list").Scan(&seq, &dbname, &dbpath)
	reopened, err := store.Open(dbpath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.OutboundDisplayName("one", "us-out-01") != "同名出口" {
		t.Fatal("persistent name lost")
	}
	if sha256.Sum256(config) != before || mutations != 1 {
		t.Fatal("rename changed controller config")
	}
}
