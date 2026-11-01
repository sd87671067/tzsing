package server

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestUUIDCreateSessionPermissionNonceAndAlias(t *testing.T) {
	f := setup(t)
	sock := filepath.Join(t.TempDir(), "control.sock")
	ln, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	var applied atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/uuid-preview" {
			w.Write([]byte(`{"plan":"hidden-plan","writable":true}`))
			return
		}
		if r.URL.Path == "/uuid-apply" {
			applied.Add(1)
			w.Write([]byte(`{"ok":true,"auth_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inbound":"shared"}`))
			return
		}
		w.WriteHeader(404)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.app.ControlSocket = sock
	f.app.ControlServer = "one"
	f.db.Exec("INSERT INTO control_permissions VALUES(1,'change')")
	preview := func() string {
		r := f.req(t, "POST", "/api/admin/node-preview", map[string]any{"server": "one", "node": map[string]any{"inbound": "shared", "name": "新节点", "enabled": true}}, f.admin, f.acs)
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal(r.StatusCode)
		}
		var out map[string]any
		json.NewDecoder(r.Body).Decode(&out)
		if out["plan"] != nil {
			t.Fatal("host plan leaked")
		}
		return out["nonce"].(string)
	}
	token := preview()
	body := map[string]string{"server": "one", "nonce": token}
	for _, test := range []struct {
		cookie *http.Cookie
		csrf   string
		want   int
	}{{f.user, f.ucs, 403}, {f.admin, "", 403}, {f.admin, f.acs, 200}, {f.admin, f.acs, 409}} {
		r := f.req(t, "POST", "/api/admin/node-create", body, test.cookie, test.csrf)
		r.Body.Close()
		if r.StatusCode != test.want {
			t.Fatal("create gate", r.StatusCode, test.want)
		}
	}
	if applied.Load() != 1 {
		t.Fatal("apply replayed")
	}
	var name string
	f.db.QueryRow("SELECT name FROM nodes WHERE server='one' AND tag LIKE 'identity:%'").Scan(&name)
	if name != "新节点" {
		t.Fatal("display name lost", name)
	}
	token = preview()
	f.db.Exec("DELETE FROM control_permissions WHERE user_id=1")
	r := f.req(t, "POST", "/api/admin/node-create", map[string]string{"server": "one", "nonce": token}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 403 || applied.Load() != 1 {
		t.Fatal("revoked grant applied")
	}
}
