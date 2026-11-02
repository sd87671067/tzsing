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
)

func TestDynamicOutboundUnionAndRevocation(t *testing.T) {
	f := setup(t)
	tags := []model.Tag{}
	mappings := map[string][]string{}
	for i, uuid := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"} {
		id := model.UUIDAuthID(uuid)
		raw := model.IdentityName("shared", id)
		node := []string{"a", "b", "c", "outside"}[i]
		if _, e := f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES(?,'one',?)", node, raw); e != nil {
			t.Fatal(e)
		}
		if i < 3 {
			f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
		}
		tags = append(tags, model.Tag{Name: raw, Identity: "inbound", InboundTag: "shared", AuthID: id, AuthScheme: "uuid-v1", Type: "vless", Accounting: "native_user_observed"})
		mappings[raw] = []string{[]string{"HK", "JP", "US", "exclusive"}[i]}
	}
	report, _ := json.Marshal(model.Report{ServerID: "one", At: time.Now().Unix(), Tags: tags})
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", report, time.Now().Unix())
	f.app.ControlServer = "one"
	own, _ := f.db.RegisterOutbound("one", "mine", "Personal", 2)
	private, _ := f.db.RegisterOutbound("one", "private", "Other user", 99)
	ids := map[string]string{}
	for _, tag := range []string{"HK", "JP", "US", "exclusive", "direct", "chain"} {
		o, e := f.db.RegisterOutbound("one", tag, tag, 0)
		if e != nil {
			t.Fatal(e)
		}
		ids[tag] = o.ID
	}
	socket := filepath.Join(t.TempDir(), "control.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	calls := map[string]int{}
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		switch r.URL.Path {
		case "/outbound-catalog":
			items := []any{}
			for _, tag := range []string{"HK", "JP", "US", "exclusive", "mine", "private", "direct", "chain"} {
				items = append(items, map[string]any{"tag": tag})
			}
			json.NewEncoder(w).Encode(map[string]any{"items": items, "mappings": mappings})
		case "/status":
			json.NewEncoder(w).Encode(map[string]any{"apply": true, "restore": true})
		case "/preview":
			json.NewEncoder(w).Encode(map[string]any{"plan": "route-plan", "preview": map[string]any{"server": "secret"}, "writable": true, "effects": map[string]any{}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	call := func(method, path string, body any, admin bool, want int) map[string]any {
		t.Helper()
		cookie, csrf := f.user, f.ucs
		if admin {
			cookie, csrf = f.admin, f.acs
		}
		r := f.req(t, method, "/api/"+path, body, cookie, csrf)
		defer r.Body.Close()
		v := map[string]any{}
		json.NewDecoder(r.Body).Decode(&v)
		if r.StatusCode != want {
			t.Fatalf("%s status=%d want=%d body=%v", path, r.StatusCode, want, v)
		}
		return v
	}
	status := func(node string, want int) map[string]any {
		return call("GET", "control/status?node_id="+node, nil, false, want)
	}
	// A retained legacy whitelist cannot override the sole global switch.
	for _, q := range []string{
		"CREATE TABLE uuid_permissions(user_id INTEGER,node_id TEXT,can_change INTEGER)",
		"CREATE TABLE uuid_outbound_grants(user_id INTEGER,node_id TEXT,outbound_id TEXT)",
		"INSERT INTO uuid_permissions VALUES(2,'a',1)",
		"INSERT INTO uuid_outbound_grants VALUES(2,'a','HK')",
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	status("a", 403)
	call("POST", "control/preview", map[string]any{"node_id": "a", "outbound": ids["HK"]}, false, 403)
	f.db.Exec("INSERT INTO user_operations VALUES(2,'change')")
	check := func(node string, want ...string) map[string]any {
		t.Helper()
		v := status(node, 200)
		got := map[string]bool{}
		for _, x := range v["outbounds"].([]any) {
			o := x.(map[string]any)
			got[o["tag"].(string)] = true
		}
		if len(got) != len(want) {
			t.Fatalf("union %s got=%v want=%v", node, got, want)
		}
		for _, id := range want {
			if !got[id] {
				t.Fatal("missing", id, got)
			}
		}
		return v
	}
	for _, node := range []string{"a", "b", "c"} {
		check(node, ids["HK"], ids["JP"], ids["US"], own.ID)
	}
	preview := func(node, id string, want int) map[string]any {
		s := status(node, 200)
		return call("POST", "control/preview", map[string]any{"node_id": node, "outbound": id, "nonce": s["nonce"]}, false, want)
	}
	for _, id := range []string{private.ID, ids["exclusive"], "HK"} {
		preview("a", id, 403)
	}
	status("outside", 403)
	p := preview("a", ids["JP"], 200)
	call("POST", "control/apply", map[string]any{"node_id": "a", "nonce": p["nonce"]}, false, 200)
	// A granted UUID referencing another user's private node still cannot share it.
	mappings[tags[2].Name] = []string{"US", "private", "direct", "chain"}
	check("a", ids["HK"], ids["JP"], ids["US"], ids["direct"], ids["chain"], own.ID)
	p = preview("a", ids["US"], 200)
	f.db.Exec("DELETE FROM user_operations WHERE user_id=2 AND action='change'")
	call("POST", "control/apply", map[string]any{"node_id": "a", "nonce": p["nonce"]}, false, 403)
	if calls["/apply"] != 1 {
		t.Fatal("revoked switch applied")
	}
	f.db.Exec("INSERT INTO user_operations VALUES(2,'change')")
	p = preview("a", ids["US"], 200)
	f.db.Exec("DELETE FROM grants WHERE user_id=2 AND tag=?", tags[2].Name)
	call("POST", "control/apply", map[string]any{"node_id": "a", "nonce": p["nonce"]}, false, 403)
	// Shared HK remains available through B when A is revoked; no restore/delete.
	mappings[tags[1].Name] = []string{"HK"}
	call("PUT", "admin/grants", map[string]any{"user_id": 2, "servers": []string{"one"}, "grants": []map[string]string{{"server": "one", "tag": tags[1].Name}}}, true, 200)
	check("b", ids["HK"], own.ID)
	status("a", 403)
	var n int
	f.db.QueryRow("SELECT count(*) FROM uuid_bindings WHERE node_id='a'").Scan(&n)
	if n != 1 || calls["/restore-preview"] != 0 || calls["/outbound-apply"] != 0 || calls["/apply"] != 1 {
		t.Fatal("revoke altered binding or route", n, calls)
	}
	if _, err := f.db.Outbound(ids["HK"]); err != nil {
		t.Fatal("shared outbound removed", err)
	}
	call("PUT", "admin/uuid-permissions", map[string]any{}, true, 404)
}

func TestPersonalOutboundLifecyclePermissionsAndSecrets(t *testing.T) {
	f := setup(t)
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	raw := model.IdentityName("shared", id)
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('uuid','one',?)", raw)
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
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
	// The global change permission protects every endpoint before host calls.
	for _, action := range []string{"create", "edit", "delete", "test", "apply"} {
		post(map[string]any{"node_id": "uuid", "action": action}, 403)
	}
	denied := f.req(t, "GET", "/api/personal-outbounds?node_id=uuid", nil, f.user, "")
	denied.Body.Close()
	if denied.StatusCode != 403 {
		t.Fatal("disabled catalog", denied.StatusCode)
	}
	admin := f.req(t, "GET", "/api/personal-outbounds?node_id=uuid", nil, f.admin, "")
	admin.Body.Close()
	if admin.StatusCode != 200 {
		t.Fatal("admin exemption", admin.StatusCode)
	}
	f.db.Exec("INSERT INTO user_operations VALUES(2,'change')")
	for _, action := range []string{"test", "edit", "delete"} {
		post(map[string]any{"node_id": "uuid", "action": action, "id": private.ID, "name": "x", "link": "http://synthetic:secret@example.org:443"}, 403)
	}
	post(map[string]any{"node_id": "uuid", "action": "create", "id": private.ID, "name": "x", "link": "http://example.org:443"}, 403)
	p := post(map[string]any{"node_id": "uuid", "action": "create", "name": "Personal", "link": "http://synthetic:secret@example.org:443"}, 200)
	// Revoking the switch invalidates even an already previewed change.
	f.db.Exec("DELETE FROM user_operations WHERE user_id=2")
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 403)
	if applies != 0 {
		t.Fatal("revoked personal change reached host")
	}
	f.db.Exec("INSERT INTO user_operations VALUES(2,'change')")
	oid := p["id"].(string)
	if o, e := f.db.Outbound(oid); e != nil || o.Owner != 2 {
		t.Fatal("personal ownership lost", e)
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
	f.db.Exec("DELETE FROM grants WHERE user_id=2 AND tag=?", raw)
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 403)
	if applies != 1 {
		t.Fatal("revoked edit applied")
	}
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
	p = post(map[string]any{"node_id": "uuid", "action": "delete", "id": oid}, 200)
	post(map[string]any{"node_id": "uuid", "action": "apply", "nonce": p["nonce"]}, 200)
	if _, e = f.db.Outbound(oid); e == nil {
		t.Fatal("deleted registry retained")
	}
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
