package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

type fixture struct {
	app         *App
	db          *store.Store
	srv         *httptest.Server
	admin, user *http.Cookie
	acs, ucs    string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db, e := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Init("admin", "administrator-test-password"); e != nil {
		t.Fatal(e)
	}
	db.Exec("INSERT INTO users(name,role,hash) VALUES('viewer','user',?)", auth.Hash("viewer-test-password"))
	db.Exec("INSERT INTO servers(id,name,token) VALUES('one','One',?)", auth.Digest(strings.Repeat("x", 43)))
	db.Exec("INSERT INTO servers(id,name,token) VALUES('two','Two',?)", auth.Digest(strings.Repeat("y", 43)))
	db.Exec("INSERT INTO grants VALUES(2,'one','allowed')")
	db.Exec("INSERT INTO server_grants VALUES(2,'one')")
	rep := model.Report{ServerID: "one", At: time.Now().Unix(), Interval: 2, Host: &model.Host{MemoryTotal: 123}, Tags: []model.Tag{{Name: "allowed", Type: "Direct", Egress: "secret", Kind: "logical", IP: &model.Exit{IPv4: "1.2.3.4"}}, {Name: "secret", Type: "Direct", Kind: "actual"}}}
	b, _ := json.Marshal(rep)
	db.Exec("UPDATE servers SET report=?,seen=?", b, time.Now().Unix())
	app := New(db, "/testprefix", "", http.NotFoundHandler())
	srv := httptest.NewTLSServer(app)
	app.Origin = srv.URL
	f := &fixture{app: app, db: db, srv: srv}
	f.admin, f.acs = f.login(t, "admin", "administrator-test-password")
	f.user, f.ucs = f.login(t, "viewer", "viewer-test-password")
	t.Cleanup(func() { srv.Close(); db.Close() })
	return f
}
func (f *fixture) req(t *testing.T, method, path string, v any, c *http.Cookie, csrf string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(v)
	r, _ := http.NewRequest(method, f.srv.URL+"/testprefix"+path, bytes.NewReader(b))
	r.Header.Set("Origin", f.srv.URL)
	r.Header.Set("X-CSRF-Token", csrf)
	if c != nil {
		r.AddCookie(c)
	}
	res, e := f.srv.Client().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	return res
}
func (f *fixture) login(t *testing.T, n, p string) (*http.Cookie, string) {
	res := f.req(t, "POST", "/api/login", map[string]string{"name": n, "password": p}, nil, "")
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("login", res.StatusCode)
	}
	var out struct {
		CSRF string `json:"csrf"`
	}
	json.NewDecoder(res.Body).Decode(&out)
	cs := res.Cookies()
	if len(cs) != 1 || !cs[0].Secure || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure cookie")
	}
	return cs[0], out.CSRF
}
func TestRBACAndCSRF(t *testing.T) {
	f := setup(t)
	res := f.req(t, "GET", "/api/snapshot", nil, f.user, "")
	var vs []model.View
	json.NewDecoder(res.Body).Decode(&vs)
	res.Body.Close()
	if len(vs) != 1 || len(vs[0].Report.Tags) != 1 || vs[0].Report.Host != nil || vs[0].Report.Tags[0].Egress != "" || vs[0].Report.Tags[0].IP != nil {
		t.Fatalf("RBAC disclosure: %+v", vs)
	}
	for _, p := range []string{"/api/admin/users", "/api/history?server=one&tag=secret", "/api/control/nodes"} {
		r := f.req(t, "GET", p, nil, f.user, "")
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatal(p, r.StatusCode)
		}
	}
	r := f.req(t, "POST", "/api/admin/users", map[string]string{"name": "new", "password": "new-long-test-password"}, f.admin, "")
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("CSRF accepted")
	}
	r = f.req(t, "POST", "/api/admin/users", map[string]string{"name": "new", "password": "new-long-test-password"}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("user create", r.StatusCode)
	}
}
func TestWebsocketRevokedImmediately(t *testing.T) {
	f := setup(t)
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	h := http.Header{}
	h.Set("Cookie", f.user.String())
	h.Set("Origin", f.srv.URL)
	c, _, e := d.Dial("wss"+strings.TrimPrefix(f.srv.URL, "https")+"/testprefix/ws", h)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	var v []model.View
	if e = c.ReadJSON(&v); e != nil {
		t.Fatal(e)
	}
	if len(v) != 1 {
		t.Fatal("WS leaked servers")
	}
	r := f.req(t, "PUT", "/api/admin/grants", map[string]any{"user_id": 2, "grants": []any{}}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, e = c.ReadMessage(); e == nil {
		t.Fatal("subscription not revoked")
	}
}
func TestAgentAuthenticationReplayAndTotals(t *testing.T) {
	f := setup(t)
	post := func(v model.Report, token string) int {
		b, _ := json.Marshal(v)
		r, _ := http.NewRequest("POST", f.srv.URL+"/testprefix/api/agent/report", bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+token)
		res, e := f.srv.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
	u, d := int64(100), int64(200)
	v := model.Report{ServerID: "one", Epoch: auth.Random(), Seq: 1, At: time.Now().Unix(), Interval: 2, Tags: []model.Tag{{Name: "allowed", Type: "Direct", Kind: "actual", Upload: &u, Download: &d}}}
	if post(v, strings.Repeat("z", 43)) != 401 {
		t.Fatal("bad agent accepted")
	}
	if post(v, strings.Repeat("x", 43)) != 200 {
		t.Fatal("valid agent rejected")
	}
	if post(v, strings.Repeat("x", 43)) != 409 {
		t.Fatal("replay accepted")
	}
	old := v.Epoch
	v.Epoch = auth.Random()
	u = 20
	d = 30
	if post(v, strings.Repeat("x", 43)) != 200 {
		t.Fatal("restart rejected")
	}
	var total int64
	f.db.QueryRow("SELECT totalup FROM counters WHERE server='one' AND tag='allowed'").Scan(&total)
	var monthly int64
	f.db.QueryRow("SELECT used FROM monthly WHERE server='one' AND tag='allowed' AND month=?", time.Now().UTC().Format("2006-01")).Scan(&monthly)
	if monthly != 350 {
		t.Fatal("monthly deltas / restart", monthly)
	}
	if total != 120 {
		t.Fatal("restart totals", total)
	}
	v.Epoch = old
	v.Seq = 2
	if post(v, strings.Repeat("x", 43)) != 409 {
		t.Fatal("old epoch replay accepted")
	}
	v.Epoch = auth.Random()
	v.At -= 120
	if post(v, strings.Repeat("x", 43)) != 400 {
		t.Fatal("stale report accepted")
	}
}
func TestDisabledSessionAndRateLimit(t *testing.T) {
	f := setup(t)
	res := f.req(t, "PATCH", "/api/admin/users", map[string]any{"id": 2, "disabled": true}, f.admin, f.acs)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	res = f.req(t, "GET", "/api/snapshot", nil, f.user, "")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("disabled user session accepted")
	}
	for i := 0; i < 10; i++ {
		res = f.req(t, "POST", "/api/login", map[string]string{"name": "noone", "password": "incorrect"}, nil, "")
		res.Body.Close()
	}
	if res.StatusCode != 429 {
		t.Fatal("login limiter inactive")
	}
}
