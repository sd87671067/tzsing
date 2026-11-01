package server

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func TestPreciseUUIDOutboundIsolationAndRevocation(t *testing.T) {
	f := setup(t)
	ids := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	tags := []model.Tag{}
	for i, uuid := range ids {
		id := model.UUIDAuthID(uuid)
		raw := model.IdentityName("shared", id)
		node := []string{"alice-node", "bob-node"}[i]
		f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES(?,'one',?)", node, raw)
		f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
		tags = append(tags, model.Tag{Name: raw, Identity: "inbound", InboundTag: "shared", AuthID: id, AuthScheme: "uuid-v1", Type: "vless", Accounting: "native_user_observed"})
	}
	b, _ := json.Marshal(model.Report{ServerID: "one", At: time.Now().Unix(), Tags: tags})
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	f.app.ControlServer = "one"
	allowed, _ := f.db.RegisterOutbound("one", "allowed-out", "Allowed", 0)
	private, _ := f.db.RegisterOutbound("one", "private-out", "Private", 3)
	f.db.Exec("INSERT INTO uuid_permissions VALUES(2,'alice-node',1,1,1,1)")
	f.db.Exec("INSERT INTO uuid_permissions VALUES(2,'bob-node',1,0,0,0)")
	f.db.Exec("INSERT INTO uuid_outbound_grants VALUES(2,'alice-node',?)", allowed.ID)
	socket := filepath.Join(t.TempDir(), "control.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	calls := map[string]int{}
	restoreFail := false
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		switch r.URL.Path {
		case "/outbound-catalog":
			json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"tag": "allowed-out"}, map[string]any{"tag": "private-out"}}})
		case "/status":
			json.NewEncoder(w).Encode(map[string]any{"apply": true, "restore": true, "outbounds": []any{map[string]string{"tag": "private-out"}}})
		case "/preview":
			if v["outbound"] != "allowed-out" {
				t.Error("host received unauthorized outbound")
			}
			json.NewEncoder(w).Encode(map[string]any{"plan": "route-plan", "preview": map[string]any{"server": "private-secret"}})
		case "/restore-preview":
			if restoreFail {
				w.WriteHeader(409)
				w.Write([]byte(`{"error":"conflict"}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"plan": "restore-plan"})
		default:
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	get := func(node string) map[string]any {
		r := f.req(t, "GET", "/api/control/status?node_id="+node, nil, f.user, "")
		defer r.Body.Close()
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		if r.StatusCode != 200 {
			t.Fatal("status", r.StatusCode)
		}
		return v
	}
	status := get("alice-node")
	wire, _ := json.Marshal(status)
	if strings.Contains(string(wire), "private-out") || strings.Contains(string(wire), private.ID) {
		t.Fatal("private catalog leaked")
	}
	post := func(node, outbound, nonce string, want int) map[string]any {
		r := f.req(t, "POST", "/api/control/preview", map[string]string{"node_id": node, "outbound": outbound, "nonce": nonce}, f.user, f.ucs)
		defer r.Body.Close()
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		if r.StatusCode != want {
			t.Fatal("preview", r.StatusCode, v)
		}
		return v
	}
	for _, bad := range []string{"allowed-out", private.ID, "guessed"} {
		s := get("alice-node")
		post("alice-node", bad, s["nonce"].(string), 403)
	}
	s := get("bob-node")
	post("bob-node", allowed.ID, s["nonce"].(string), 403)
	s = get("alice-node")
	p := post("alice-node", allowed.ID, s["nonce"].(string), 200)
	wire, _ = json.Marshal(p)
	if strings.Contains(string(wire), "private-secret") {
		t.Fatal("host details disclosed")
	}
	// Revoke after preview: old nonce cannot bypass a changed grant.
	f.db.Exec("DELETE FROM uuid_outbound_grants WHERE user_id=2")
	r := f.req(t, "POST", "/api/control/apply", map[string]any{"node_id": "alice-node", "nonce": p["nonce"]}, f.user, f.ucs)
	r.Body.Close()
	if r.StatusCode != 403 || calls["/apply"] != 0 {
		t.Fatal("stale grant applied")
	}
	f.db.Exec("INSERT INTO uuid_outbound_grants VALUES(2,'alice-node',?)", allowed.ID)
	s = get("alice-node")
	p = post("alice-node", allowed.ID, s["nonce"].(string), 200)
	r = f.req(t, "POST", "/api/control/apply", map[string]any{"node_id": "alice-node", "nonce": p["nonce"]}, f.user, f.ucs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("authorized apply", r.StatusCode)
	}
	restoreFail = true
	r = f.req(t, "PUT", "/api/admin/grants", map[string]any{"user_id": 2, "grants": []any{}}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("failed restore silently revoked", r.StatusCode)
	}
	var n int
	f.db.QueryRow("SELECT count(*) FROM grants WHERE user_id=2").Scan(&n)
	if n == 0 {
		t.Fatal("grants removed before restore")
	}
	restoreFail = false
	r = f.req(t, "PUT", "/api/admin/grants", map[string]any{"user_id": 2, "grants": []any{}}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("revoke failed", r.StatusCode)
	}
	f.db.QueryRow("SELECT count(*) FROM uuid_bindings").Scan(&n)
	if n != 0 || calls["/restore-preview"] != 2 {
		t.Fatal("binding survived revoke")
	}
}

func TestPersonalOutboundLifecyclePermissionsAndSecrets(t *testing.T) {
	f := setup(t)
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	raw := model.IdentityName("shared", id)
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('uuid','one',?)", raw)
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
	f.db.Exec("INSERT INTO uuid_permissions VALUES(2,'uuid',1,1,1,1)")
	f.app.ControlServer = "one"
	socket := filepath.Join(t.TempDir(), "personal.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	tag := "tz-out-generated"
	created := false
	applies := 0
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/outbound-catalog":
			items := []any{map[string]any{"tag": "someone-elses-out", "password": "DO-NOT-RETURN", "uuid": "DO-NOT-RETURN"}}
			if created {
				items = append(items, map[string]any{"tag": tag, "password": "DO-NOT-RETURN"})
			}
			json.NewEncoder(w).Encode(map[string]any{"items": items})
		case "/outbound-preview":
			json.NewEncoder(w).Encode(map[string]any{"tag": tag, "plan": "internal-private-plan", "ip": "8.8.8.8"})
		case "/outbound-apply":
			created = true
			applies++
			json.NewEncoder(w).Encode(map[string]any{"tag": tag, "ok": true})
		default:
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "ip": "8.8.8.8"})
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	private, _ := f.db.RegisterOutbound("one", "someone-elses-out", "Private", 99)
	post := func(body map[string]any, want int) map[string]any {
		r := f.req(t, "POST", "/api/personal-outbounds", body, f.user, f.ucs)
		defer r.Body.Close()
		var out map[string]any
		json.NewDecoder(r.Body).Decode(&out)
		if r.StatusCode != want {
			t.Fatal("personal", r.StatusCode, out)
		}
		wire, _ := json.Marshal(out)
		if strings.Contains(string(wire), "DO-NOT-RETURN") || strings.Contains(string(wire), "internal-private-plan") {
			t.Fatal("credential or host plan leak")
		}
		return out
	}
	for _, action := range []string{"test", "edit", "delete"} {
		post(map[string]any{"node_id": "uuid", "action": action, "id": private.ID, "name": "x", "link": "http://synthetic:secret@example.org:443"}, 403)
	}
	post(map[string]any{"node_id": "uuid", "action": "create", "id": private.ID, "name": "x", "link": "http://example.org:443"}, 403)
	p := post(map[string]any{"node_id": "uuid", "action": "create", "name": "Personal", "link": "http://synthetic:secret@example.org:443"}, 200)
	oid := p["id"].(string)
	if !f.db.CanBind(mustUser(t, f, 2), "uuid", oid) {
		t.Fatal("new personal node not scoped to creating UUID")
	}
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 200)
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 403)
	r := f.req(t, "GET", "/api/personal-outbounds?node_id=uuid", nil, f.user, "")
	var list map[string]any
	json.NewDecoder(r.Body).Decode(&list)
	r.Body.Close()
	wire, _ := json.Marshal(list)
	if strings.Contains(string(wire), "DO-NOT-RETURN") || strings.Contains(string(wire), private.ID) || strings.Contains(string(wire), "someone-elses-out") {
		t.Fatal("private catalog disclosed")
	}
	// Nonce approval does not freeze edit authorization.
	p = post(map[string]any{"node_id": "uuid", "action": "edit", "id": oid, "name": "Updated", "link": "http://example.org:443"}, 200)
	f.db.Exec("UPDATE uuid_permissions SET can_edit=0 WHERE user_id=2")
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 403)
	if applies != 1 {
		t.Fatal("revoked edit applied")
	}
	p = post(map[string]any{"node_id": "uuid", "action": "delete", "id": oid}, 200)
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 200)
	if _, e = f.db.Outbound(oid); e == nil {
		t.Fatal("deleted registry retained")
	}
}

func mustUser(t *testing.T, f *fixture, id int64) store.User {
	t.Helper()
	u, e := f.db.User(id)
	if e != nil {
		t.Fatal(e)
	}
	return u
}

func TestDeletedOwnerIDCannotBeReassigned(t *testing.T) {
	f := setup(t)
	o, e := f.db.RegisterOutbound("one", "retained-personal", "Private", 2)
	if e != nil {
		t.Fatal(e)
	}
	r := f.req(t, "DELETE", "/api/admin/users", map[string]any{"id": 2}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("delete", r.StatusCode)
	}
	r = f.req(t, "POST", "/api/admin/users", map[string]any{"name": "replacement", "password": "synthetic-replacement-password"}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("create", r.StatusCode)
	}
	var id int64
	f.db.QueryRow("SELECT id FROM users WHERE name='replacement'").Scan(&id)
	if id <= o.Owner {
		t.Fatal("deleted owner id reused")
	}
	preserved, e := f.db.Outbound(o.ID)
	if e != nil || preserved.Owner == id {
		t.Fatal("private ownership reassigned")
	}
}
