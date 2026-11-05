package server

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestOutboundAdminPermissionSessionNonceAndReplay(t *testing.T) {
	f := setup(t)
	socket := filepath.Join(t.TempDir(), "outbound.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	deleted := false
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/outbound-preview" {
			json.NewEncoder(w).Encode(map[string]any{"plan": "internal-plan", "tag": "provider", "ip": "8.8.8.8"})
		} else {
			calls++
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "tag": "provider", "deleted": deleted})
		}
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	f.app.ControlServer = "one"
	f.db.Exec("INSERT OR IGNORE INTO control_permissions VALUES(1,'change')")
	for _, method := range []string{"GET", "POST"} {
		r := f.req(t, method, "/api/admin/outbounds", map[string]any{"action": "test"}, f.user, f.ucs)
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatal("viewer reached outbound management", r.StatusCode)
		}
	}
	r := f.req(t, "POST", "/api/admin/outbounds", map[string]any{"action": "save", "name": "共享出口", "node": map[string]any{"config": map[string]any{"type": "direct"}}}, f.admin, f.acs)
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	r.Body.Close()
	if r.StatusCode != 200 || out["plan"] != nil || out["nonce"] == nil {
		t.Fatal("unsafe preview", out)
	}
	for i, want := range []int{200, 200} {
		r = f.req(t, "POST", "/api/admin/outbounds", map[string]any{"action": "apply", "nonce": out["nonce"]}, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatal(i, r.StatusCode)
		}
	}
	if calls != 1 {
		t.Fatal("duplicate outbound applied", calls)
	}
	var name string
	f.db.QueryRow("SELECT name FROM nodes WHERE server='one' AND tag='provider'").Scan(&name)
	if name != "共享出口" {
		t.Fatal("alias not saved")
	}
	deleted = true
	r = f.req(t, "POST", "/api/admin/outbounds", map[string]any{"action": "delete", "node": map[string]any{"tag": "provider"}}, f.admin, f.acs)
	json.NewDecoder(r.Body).Decode(&out)
	r.Body.Close()
	r = f.req(t, "POST", "/api/admin/outbounds", map[string]any{"action": "apply", "nonce": out["nonce"]}, f.admin, f.acs)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("delete apply", r.StatusCode)
	}
	var count int
	f.db.QueryRow("SELECT count(*) FROM nodes WHERE server='one' AND tag='provider'").Scan(&count)
	if count != 0 {
		t.Fatal("deleted outbound metadata resurrected")
	}
}
func TestPolicyVisibilityInAdminViewerAPIAndWebSocket(t *testing.T) {
	f := setup(t)
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	raw := model.IdentityName("shared", id)
	rep := model.Report{ServerID: "one", At: time.Now().Unix(), Tags: []model.Tag{{Name: raw, InboundTag: "shared", AuthID: id, AuthScheme: "uuid-v1", Identity: "inbound", Type: "vless", Accounting: "native_user_observed"}}}
	b, _ := json.Marshal(rep)
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	f.db.Exec("INSERT INTO nodes(id,server,tag) VALUES('uuid','one',?)", raw)
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", raw)
	socket := filepath.Join(t.TempDir(), "policy.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	helper := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "items": map[string]any{raw: map[string]any{"quota": 1000, "expires_at": 2000000000, "used": 123, "reserved": 2, "uncertain": true, "since": 1, "status": "reserved_uncertain"}}})
	})}
	go helper.Serve(ln)
	defer helper.Close()
	f.app.ControlSocket = socket
	f.app.ControlServer = "one"
	for _, on := range []int{0, 1} {
		f.db.Exec("UPDATE settings SET value=? WHERE key IN ('show_expiry','show_quota')", on)
		for _, cookie := range []*http.Cookie{f.admin, f.user} {
			r := f.req(t, "GET", "/api/snapshot", nil, cookie, "")
			var views []model.View
			json.NewDecoder(r.Body).Decode(&views)
			r.Body.Close()
			tag := views[0].Report.Tags[0]
			if on == 0 && (tag.ExpiresAt != 0 || tag.Quota != 0 || tag.BillableUsed != nil || tag.PolicyReserved != 0 || tag.ShowExpiry || tag.ShowQuota) {
				t.Fatal("hidden policy disclosed", tag)
			}
			if on == 1 && (tag.ExpiresAt != 2000000000 || tag.Quota != 1000 || tag.BillableUsed == nil) {
				t.Fatal("policy missing", tag)
			}
		}
	}
	f.db.Exec("UPDATE settings SET value=0 WHERE key IN ('show_expiry','show_quota')")
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = f.srv.Client().Transport.(*http.Transport).TLSClientConfig
	h := http.Header{"Origin": []string{f.srv.URL}, "Cookie": []string{f.admin.String()}}
	ws, _, e := dialer.Dial("wss"+strings.TrimPrefix(f.srv.URL, "https")+"/testprefix/ws", h)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(4 * time.Second))
	var views []model.View
	if e = ws.ReadJSON(&views); e != nil {
		t.Fatal(e)
	}
	tag := views[0].Report.Tags[0]
	if tag.ExpiresAt != 0 || tag.Quota != 0 || tag.PolicyReserved != 0 || tag.BillableUsed != nil {
		t.Fatal("WS policy disclosure")
	}
}
