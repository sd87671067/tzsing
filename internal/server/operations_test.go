package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestUserOperationsDefaultSeparationRevocationAndNodeBoundary(t *testing.T) {
	f := setup(t)
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	raw := model.IdentityName("shared", id)
	b, _ := json.Marshal(model.Report{At: time.Now().Unix(), Tags: []model.Tag{{Name: raw, InboundTag: "shared", AuthID: id, AuthScheme: "uuid-v1", Identity: "inbound", Type: "vless", Accounting: "native_user_observed"}}})
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('mine','one',?)", raw)
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
	socket := filepath.Join(t.TempDir(), "control.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]string
		json.NewDecoder(r.Body).Decode(&v)
		if v["auth_id"] != id || v["tag"] != "shared" {
			t.Error("identity scope lost")
		}
		if r.URL.Path == "/status" {
			io.WriteString(w, `{"share":true,"apply":false,"profiles":[{"id":"mine","label":"single"}]}`)
		} else {
			io.WriteString(w, `{"link":"vless://synthetic-mine@example.org:443"}`)
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	f.app.ControlServer = "one"
	call := func(path, method string, v any, cookie *http.Cookie, csrf string, want int) map[string]any {
		t.Helper()
		r := f.req(t, method, path, v, cookie, csrf)
		defer r.Body.Close()
		var out map[string]any
		json.NewDecoder(r.Body).Decode(&out)
		if r.StatusCode != want {
			t.Fatalf("%s %d expected %d: %v", path, r.StatusCode, want, out)
		}
		return out
	}
	gate := func(want int) map[string]any {
		return call("/api/control/status?node_id=mine", "GET", nil, f.user, "", want)
	}
	gate(403)
	// Legacy admin-only permission rows never grant normal-user operations.
	f.db.Exec("INSERT INTO control_permissions VALUES(2,'copy')")
	gate(403)
	call("/api/admin/operations", "PUT", map[string]any{"user_id": 2, "actions": []string{"copy"}}, f.user, f.ucs, 403)
	put := func(actions []string) {
		call("/api/admin/operations", "PUT", map[string]any{"user_id": 2, "actions": actions}, f.admin, f.acs, 200)
	}
	put([]string{"copy"})
	g := gate(200)
	share := map[string]string{"node_id": "mine", "nonce": g["nonce"].(string), "action": "import_v2rayn", "profile": "mine"}
	call("/api/control/share", "POST", share, f.user, f.ucs, 403)
	share["action"] = "import_shadowrocket"
	call("/api/control/share", "POST", share, f.user, f.ucs, 403)
	share["action"] = "copy"
	call("/api/control/share", "POST", share, f.user, f.ucs, 200)
	// Renaming has independent authorization, and a normal user cannot rename globally.
	call("/api/alias", "PUT", map[string]string{"node_id": "mine", "name": "mine"}, f.user, f.ucs, 403)
	put([]string{"rename"})
	call("/api/alias", "PUT", map[string]string{"node_id": "mine", "name": "mine"}, f.user, f.ucs, 200)
	call("/api/admin/nodes", "PATCH", map[string]string{"node_id": "mine", "name": "all"}, f.user, f.ucs, 403)
	put([]string{"copy"})
	g = gate(200)
	share["nonce"] = g["nonce"].(string)
	put([]string{})
	call("/api/control/share", "POST", share, f.user, f.ucs, 403)
	put([]string{"copy"})
	call("/api/control/share", "POST", share, f.user, f.ucs, 409)
	// Having an operation never supplies a missing node grant.
	f.db.Exec("DELETE FROM grants WHERE user_id=2")
	gate(403)
	var count int
	f.db.QueryRow("SELECT count(*) FROM user_operations WHERE user_id=2").Scan(&count)
	if count != 1 {
		t.Fatal("node grants altered operation grants")
	}
}
