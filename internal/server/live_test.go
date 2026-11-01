package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func TestLiveDeployment(t *testing.T) {
	if os.Getenv("TZ_LIVE") != "1" {
		t.Skip("explicit live deployment opt-in required")
	}
	env, e := os.ReadFile(os.Getenv("TZ_LIVE_ENV_FILE"))
	if e != nil {
		t.Fatal(e)
	}
	prefix := ""
	for _, l := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(l, "URL_PREFIX=") {
			prefix = strings.TrimPrefix(l, "URL_PREFIX=")
		}
	}
	pem, e := os.ReadFile(os.Getenv("TZ_LIVE_CA_FILE"))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 8 * time.Second}
	base := "https://127.0.0.1:19443" + prefix
	origin := os.Getenv("TZ_LIVE_ORIGIN")
	call := func(method, path string, v any, cookie *http.Cookie, csrf string) (*http.Response, []byte) {
		b, _ := json.Marshal(v)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(b))
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		return res, body.Bytes()
	}
	login := func(name, password string) (*http.Cookie, string) {
		r, b := call("POST", "/api/login", map[string]string{"name": name, "password": password}, nil, "")
		if r.StatusCode != 200 {
			t.Fatal("live login", r.StatusCode)
		}
		var d struct {
			CSRF string `json:"csrf"`
		}
		json.Unmarshal(b, &d)
		return r.Cookies()[0], d.CSRF
	}
	p, e := os.ReadFile(os.Getenv("TZ_LIVE_PASSWORD_FILE"))
	if e != nil {
		t.Fatal(e)
	}
	admin, acs := login("admin", strings.TrimSpace(string(p)))
	defer call("POST", "/api/logout", map[string]any{}, admin, acs)
	r, b := call("GET", "/api/snapshot", nil, admin, "")
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	var vs []model.View
	vs = nil
	json.Unmarshal(b, &vs)
	if len(vs) == 0 || !vs[0].Online || len(vs[0].Report.Tags) < 2 {
		t.Fatal("live Agent not reporting")
	}
	_, b = call("GET", "/api/admin/nodes", nil, admin, "")
	vs = nil
	json.Unmarshal(b, &vs)
	server := vs[0].ID
	tag, other := "", ""
	for _, x := range vs[0].Report.Tags {
		if x.Kind == "actual" {
			if tag == "" {
				tag = x.RawTag
			} else if other == "" {
				other = x.RawTag
			}
		}
	}
	if tag == "" || other == "" {
		t.Fatal("need actual tags")
	}
	name := "verify-" + time.Now().Format("150405")
	password := auth.Random()
	r, _ = call("POST", "/api/admin/users", map[string]string{"name": name, "password": password}, admin, acs)
	if r.StatusCode != 200 {
		t.Fatal("live create", r.StatusCode)
	}
	_, b = call("GET", "/api/admin/users", nil, admin, "")
	var users []store.User
	json.Unmarshal(b, &users)
	var id int64
	for _, u := range users {
		if u.Name == name {
			id = u.ID
		}
	}
	if id == 0 {
		t.Fatal("new user missing")
	}
	defer call("DELETE", "/api/admin/users", map[string]int64{"id": id}, admin, acs)
	viewer, vcs := login(name, password)
	r, b = call("GET", "/api/snapshot", nil, viewer, "")
	if strings.TrimSpace(string(b)) != "[]" {
		t.Fatal("default user disclosure")
	}
	r, _ = call("PUT", "/api/admin/grants", map[string]any{"user_id": id, "servers": []string{server}, "grants": []store.Grant{{Server: server, Tag: tag}}}, admin, acs)
	if r.StatusCode != 200 {
		t.Fatal("grant failed")
	}
	r, b = call("GET", "/api/snapshot", nil, viewer, "")
	vs = nil
	json.Unmarshal(b, &vs)
	if len(vs) != 1 || len(vs[0].Report.Tags) != 1 || vs[0].Report.Host != nil || vs[0].Report.Tags[0].RawTag != "" || vs[0].Report.Tags[0].ID == "" {
		t.Fatal("live RBAC disclosure")
	}
	for _, path := range []string{"/api/admin/users", "/api/history?server=" + server + "&tag=" + other} {
		r, _ = call("GET", path, nil, viewer, "")
		if r.StatusCode != 403 {
			t.Fatal("live forbidden endpoint", r.StatusCode)
		}
	}
	dial := websocket.Dialer{TLSClientConfig: tc}
	headers := http.Header{"Cookie": []string{viewer.String()}, "Origin": []string{origin}}
	c, _, e := dial.Dial("wss://127.0.0.1:19443"+prefix+"/ws", headers)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if e = c.ReadJSON(&vs); e != nil {
		t.Fatal(e)
	}
	if len(vs) != 1 || len(vs[0].Report.Tags) != 1 {
		t.Fatal("live WS disclosure")
	}
	r, _ = call("PUT", "/api/admin/grants", map[string]any{"user_id": id, "grants": []store.Grant{}}, admin, acs)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, e = c.ReadMessage(); e == nil {
		t.Fatal("live revocation failed")
	}
	r, _ = call("POST", "/api/logout", map[string]any{}, viewer, vcs)
	if r.StatusCode != 200 {
		t.Fatal("live logout", r.StatusCode)
	}
	t.Log("verified private TLS, live admin login, live ordinary-user isolation, history RBAC, WebSocket stream and immediate revocation; temporary user removed")
}
