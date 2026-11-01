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
)

func TestDedicatedControlPermissionsCSRFNonceAndCredentialBoundary(t *testing.T) {
	f := setup(t)
	path := filepath.Join(t.TempDir(), "controller.sock")
	ln, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			io.WriteString(w, `{"apply":true,"restore":true,"share":true,"profiles":[{"id":"synthetic-profile","label":"认证"}]}`)
		case "/share":
			io.WriteString(w, `{"link":"vless://credential-canary@example.com:443"}`)
		case "/preview":
			io.WriteString(w, `{"plan":"synthetic-plan","preview":{"server":"***.example.com"}}`)
		default:
			io.WriteString(w, `{"ok":true}`)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.app.ControlSocket = path
	f.app.ControlServer = "one"
	id := "opaque-inbound-node"
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES(?, 'one','inbound:actual')", id)
	endpoint := "/api/control/status?node_id=" + id
	status := func(cookie *http.Cookie, expected int) map[string]any {
		r := f.req(t, "GET", endpoint, nil, cookie, "")
		defer r.Body.Close()
		if r.StatusCode != expected {
			t.Fatalf("status %d expected %d", r.StatusCode, expected)
		}
		var out map[string]any
		json.NewDecoder(r.Body).Decode(&out)
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
		return out
	}
	status(f.admin, 403)
	if calls.Load() != 0 {
		t.Fatal("admin role bypassed dedicated permission")
	}
	f.db.Exec("INSERT INTO control_permissions VALUES(1,'copy')")
	f.db.Exec("INSERT INTO control_permissions VALUES(2,'copy')")
	status(f.user, 403)
	gate := status(f.admin, 200)
	body := map[string]string{"node_id": id, "nonce": gate["nonce"].(string), "action": "copy", "profile": "synthetic-profile"}
	r := f.req(t, "POST", "/api/control/share", body, f.admin, "")
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("CSRF bypass")
	}
	body["action"] = "view"
	r = f.req(t, "POST", "/api/control/share", body, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("copy permission authorized view")
	}
	body["action"] = "copy"
	r = f.req(t, "POST", "/api/control/share", body, f.admin, f.acs)
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(string(b), "credential-canary") || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("explicit protected copy failed", r.StatusCode)
	}
	r = f.req(t, "POST", "/api/control/share", body, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("replay")
	}
	gate = status(f.admin, 200)
	body["nonce"] = gate["nonce"].(string)
	f.db.Exec("DELETE FROM control_permissions WHERE user_id=1")
	r = f.req(t, "POST", "/api/control/share", body, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("permission revocation ignored")
	}
	for _, p := range []string{"/api/snapshot", "/api/admin/nodes", "/api/archives", "/api/admin/audit"} {
		r = f.req(t, "GET", p, nil, f.admin, "")
		b, _ = io.ReadAll(r.Body)
		r.Body.Close()
		if strings.Contains(string(b), "credential-canary") {
			t.Fatal("credential in", p)
		}
	}
	f.db.Exec("INSERT INTO control_permissions VALUES(1,'change')")
	gate = status(f.admin, 200)
	r = f.req(t, "POST", "/api/control/preview", map[string]string{"node_id": id, "nonce": gate["nonce"].(string), "link": "socks://u:private-canary@example.com:1080"}, f.admin, f.acs)
	var preview map[string]any
	json.NewDecoder(r.Body).Decode(&preview)
	r.Body.Close()
	if r.StatusCode != 200 || preview["plan"] != nil || preview["nonce"] == nil {
		t.Fatal("plan not session-bound")
	}
	r = f.req(t, "POST", "/api/control/apply", map[string]string{"node_id": id, "nonce": preview["nonce"].(string)}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("authorized confirmed apply", r.StatusCode)
	}
	r = f.req(t, "POST", "/api/control/apply", map[string]string{"node_id": id, "nonce": preview["nonce"].(string)}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("apply replay")
	}
	var count int
	f.db.QueryRow("SELECT count(*) FROM audit WHERE event LIKE '%canary%'").Scan(&count)
	if count != 0 {
		t.Fatal("sensitive audit")
	}
}
