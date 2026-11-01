package server

import (
	"crypto/tls"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func snapshot(t *testing.T, f *fixture, c *http.Cookie) ([]model.View, string) {
	t.Helper()
	path := "/api/snapshot"
	if c.Value == f.admin.Value {
		path = "/api/admin/nodes"
	}
	r := f.req(t, "GET", path, nil, c, "")
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 {
		t.Fatalf("snapshot %d %s", r.StatusCode, b)
	}
	var v []model.View
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v, string(b)
}
func put(t *testing.T, f *fixture, path string, v any, c *http.Cookie, csrf string, want int) {
	t.Helper()
	r := f.req(t, "PUT", path, v, c, csrf)
	defer r.Body.Close()
	if r.StatusCode != want {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("%s: %d %s", path, r.StatusCode, b)
	}
}
func TestNodePrivacyAliasesAndSwitch(t *testing.T) {
	f := setup(t)
	f.db.Exec("INSERT INTO user_operations VALUES(2,'rename')")
	admin, _ := snapshot(t, f, f.admin)
	var id string
	for _, n := range admin[0].Report.Tags {
		if n.RawTag == "allowed" {
			id = n.ID
		}
	}
	if id == "" {
		t.Fatal("admin missing raw identity")
	}
	v, b := snapshot(t, f, f.user)
	if strings.Contains(b, "allowed") || strings.Contains(b, "secret") || strings.Contains(b, "raw_tag") || strings.Contains(b, "global_name") {
		t.Fatal("raw tag leak:", b)
	}
	if v[0].Report.Tags[0].Name != "节点 01" || !strings.HasPrefix(v[0].Report.Tags[0].ID, id) {
		t.Fatal(v)
	}
	put(t, f, "/api/admin/nodes", map[string]any{"node_id": id, "name": "香港专线", "quota": 1073741824}, f.admin, f.acs, 200)
	v, _ = snapshot(t, f, f.user)
	if v[0].Report.Tags[0].Name != "香港专线" {
		t.Fatal("global alias missing")
	}
	put(t, f, "/api/alias", map[string]any{"node_id": id, "name": "我的香港"}, f.user, f.ucs, 200)
	v, _ = snapshot(t, f, f.user)
	if v[0].Report.Tags[0].Name != "我的香港" {
		t.Fatal("personal alias missing")
	}
	v, _ = snapshot(t, f, f.admin)
	if v[0].Report.Tags[0].Name != "香港专线" {
		t.Fatal("personal alias affected admin")
	}
	var secretID string
	for _, n := range v[0].Report.Tags {
		if n.RawTag == "secret" {
			secretID = n.ID
		}
	}
	put(t, f, "/api/alias", map[string]any{"node_id": secretID, "name": "偷看"}, f.user, f.ucs, 403)
	for _, path := range []string{"/api/history?server=one&tag=allowed", "/api/history?node_id=" + secretID, "/api/export?node_id=" + secretID} {
		r := f.req(t, "GET", path, nil, f.user, "")
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatal(path, r.StatusCode)
		}
	}
	for _, path := range []string{"/api/history?node_id=" + id, "/api/export?node_id=" + id} {
		r := f.req(t, "GET", path, nil, f.user, "")
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || strings.Contains(string(b), "allowed") {
			t.Fatal(path, r.StatusCode, string(b))
		}
	}
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	h := http.Header{}
	h.Set("Cookie", f.user.String())
	h.Set("Origin", f.srv.URL)
	c, _, err := d.Dial("wss"+strings.TrimPrefix(f.srv.URL, "https")+"/testprefix/ws", h)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	settings := func(show bool) {
		put(t, f, "/api/admin/settings", map[string]any{"sample_seconds": 2, "retention_days": 30, "show_raw_tag": show, "default_node_name": "优选线路"}, f.admin, f.acs, 200)
	}
	frame := func(show bool) {
		c.SetReadDeadline(time.Now().Add(4 * time.Second))
		_, b, err := c.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "raw_tag") != show || strings.Contains(string(b), "secret") {
			t.Fatal("WS privacy", string(b))
		}
	}
	frame(false)
	settings(true)
	frame(true)
	v, _ = snapshot(t, f, f.user)
	if v[0].Report.Tags[0].RawTag != "allowed" {
		t.Fatal("switch on missing tag")
	}
	settings(false)
	frame(false)
	_, b = snapshot(t, f, f.user)
	if strings.Contains(b, "raw_tag") {
		t.Fatal(b)
	}
	put(t, f, "/api/alias", map[string]any{"node_id": id, "name": ""}, f.user, f.ucs, 200)
	put(t, f, "/api/admin/nodes", map[string]any{"node_id": id, "name": "", "quota": 0}, f.admin, f.acs, 200)
	v, _ = snapshot(t, f, f.user)
	if !strings.HasPrefix(v[0].Report.Tags[0].Name, "优选线路 ") {
		t.Fatal("friendly fallback missing")
	}
	v, _ = snapshot(t, f, f.admin)
	if !v[0].Report.Tags[0].NeedsName {
		t.Fatal("admin name warning missing")
	}
	f.db.Exec("DELETE FROM grants WHERE user_id=2")
	put(t, f, "/api/alias", map[string]any{"node_id": id, "name": "revoked"}, f.user, f.ucs, 403)
}

func TestWildcardProjectionDoesNotLeakEgress(t *testing.T) {
	f := setup(t)
	f.db.Exec("INSERT INTO user_operations VALUES(2,'rename')")
	snapshot(t, f, f.admin) // register existing report nodes before resolving references
	f.db.Exec("UPDATE grants SET tag='*' WHERE user_id=2")
	v, b := snapshot(t, f, f.user)
	if strings.Contains(b, "allowed") || strings.Contains(b, "secret") || strings.Contains(b, "raw_tag") {
		t.Fatal("wildcard leaked raw identity", b)
	}
	if len(v[0].Report.Tags) != 2 || v[0].Report.Tags[0].Egress == "" {
		t.Fatal("authorized egress label missing")
	}
	var id string
	admin, _ := snapshot(t, f, f.admin)
	for _, n := range admin[0].Report.Tags {
		if n.RawTag == "secret" {
			id = n.ID
		}
	}
	put(t, f, "/api/alias", map[string]any{"node_id": id, "name": "我的出口"}, f.user, f.ucs, 200)
	v, _ = snapshot(t, f, f.user)
	if v[0].Report.Tags[0].Egress != "我的出口" {
		t.Fatal("egress alias priority", v[0].Report.Tags[0])
	}
}
