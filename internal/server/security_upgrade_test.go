package server

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"tzsingbox/internal/auth"
)

func TestOpaquePasswordLifecycle(t *testing.T) {
	f := setup(t)
	for i, p := range []string{"密", " ", strings.Repeat("长🌐 ", 1800)} {
		name := []string{"short", "space", "long"}[i]
		r := f.req(t, "POST", "/api/admin/users", map[string]any{"name": name, "password": p}, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal("create", r.StatusCode)
		}
		c, csrf := f.login(t, name, p)
		r = f.req(t, "POST", "/api/password", map[string]string{"current": p, "password": p + "尾 "}, c, csrf)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal("change", r.StatusCode)
		}
		r = f.req(t, "GET", "/api/me", nil, c, "")
		r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatal("old session survived password change")
		}
		f.login(t, name, p+"尾 ")
		u, _ := f.db.ByName(name)
		r = f.req(t, "PATCH", "/api/admin/users", map[string]any{"id": u.ID, "password": ""}, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatal("empty reset accepted", r.StatusCode)
		}
		r = f.req(t, "PATCH", "/api/admin/users", map[string]any{"id": u.ID, "password": p}, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal("reset", r.StatusCode)
		}
		f.login(t, name, p)
	}
	r := f.req(t, "POST", "/api/login", map[string]string{"name": "long", "password": strings.Repeat("x", 70<<10)}, nil, "")
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("body cap removed", r.StatusCode)
	}
	if !auth.ValidPassword("\n ") {
		t.Fatal("whitespace normalized")
	}
}
func TestNullAndEmptyPasswordDoNotEnableOrResetUser(t *testing.T) {
	f := setup(t)
	f.db.Exec("UPDATE users SET disabled=1 WHERE name='viewer'")
	for _, body := range []map[string]any{{"id": 2, "password": nil}, {"id": 2, "password": ""}, {"id": 2}} {
		r := f.req(t, "PATCH", "/api/admin/users", body, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatal("ambiguous reset accepted", r.StatusCode)
		}
	}
	u, _ := f.db.User(2)
	if !u.Disabled {
		t.Fatal("rejected reset enabled account")
	}
}

func TestControlGateNonceAndNoSecrets(t *testing.T) {
	f := setup(t)
	u, _ := f.db.ByName("admin")
	v, e := f.db.ManagementViews(u)
	if e != nil {
		t.Fatal(e)
	}
	id := v[0].Report.Tags[0].ID
	path := "/api/control/status?node_id=" + id
	r := f.req(t, "GET", path, nil, f.user, "")
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("viewer control access")
	}
	r = f.req(t, "GET", path, nil, f.admin, "")
	var gate map[string]any
	json.NewDecoder(r.Body).Decode(&gate)
	r.Body.Close()
	if gate["apply"] != false || gate["share"] != false {
		t.Fatal("unsafe gate")
	}
	body := map[string]string{"node_id": id, "nonce": gate["nonce"].(string), "link": "socks://user:credential-canary@example.com:1080"}
	r = f.req(t, "POST", "/api/control/preview", body, f.admin, "")
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("CSRF bypass")
	}
	r = f.req(t, "POST", "/api/control/preview", body, f.admin, f.acs)
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || strings.Contains(string(b), "credential-canary") {
		t.Fatal("preview disclosure or failure", r.StatusCode)
	}
	r = f.req(t, "POST", "/api/control/preview", body, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 409 {
		t.Fatal("replay accepted")
	}
	for _, p := range []string{"apply", "restore", "probe", "share"} {
		r = f.req(t, "POST", "/api/control/"+p, body, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 501 {
			t.Fatal("production mutation enabled")
		}
	}
	var count int
	f.db.QueryRow("SELECT count(*) FROM audit WHERE event LIKE '%credential-canary%'").Scan(&count)
	if count != 0 {
		t.Fatal("secret in audit")
	}
}
