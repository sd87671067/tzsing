package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/adapter"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func TestAuthenticationEndToEndCountsPermissionsAndRecovery(t *testing.T) {
	f := setup(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			w.Write([]byte(`{"proxies":{"direct":{"type":"direct"}}}`))
		} else {
			w.Write([]byte(`{"connections":[]}`))
		}
	}))
	defer upstream.Close()
	c := adapter.New(upstream.URL, "")
	c.SetInventory(&adapter.Inventory{Inbounds: []adapter.Inbound{{Tag: "a", Type: "vless", AuthIDs: []string{model.AuthID("alice"), model.AuthID("bob")}, AuthCount: 2, Routes: []string{"direct"}}, {Tag: "b", Type: "vless", Routes: []string{"direct"}}, {Tag: "idle", Type: "trojan", Unknown: true}}, Outbounds: []adapter.Outbound{{Tag: "direct", Type: "direct"}}})
	tags, e := c.Collect()
	if e != nil || len(tags) != 5 {
		t.Fatal("adapter discovery", e, len(tags))
	}
	report := model.Report{ServerID: "one", Epoch: strings.Repeat("E", 43), Seq: 1, At: time.Now().Unix(), Interval: 2, Tags: tags, Discovery: c.Discovery(len(tags))}
	b, _ := json.Marshal(report)
	req, _ := http.NewRequest("POST", f.srv.URL+"/testprefix/api/agent/report", strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 43))
	res, e := f.srv.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("report route/status %d", res.StatusCode)
	}
	admin := store.User{ID: 1, Role: "admin"}
	viewer := store.User{ID: 2, Role: "user"}
	views, e := f.db.Views(admin)
	if e != nil {
		t.Fatal(e)
	}
	var own model.View
	for _, v := range views {
		if v.ID == "one" {
			own = v
		}
	}
	if len(own.Report.Tags) != 5 || own.Diagnostics.Reported != 5 || own.Diagnostics.BackendVisible != 5 || own.Diagnostics.Authorized != 5 {
		t.Fatal("backend counts", own.Diagnostics)
	}
	var account model.Tag
	for _, v := range own.Report.Tags {
		if v.AuthID == model.AuthID("alice") {
			account = v
		}
	}
	history := f.req(t, "GET", "/api/history?node_id="+account.ID, nil, f.admin, "")
	history.Body.Close()
	if history.StatusCode != 200 {
		t.Fatal("authentication history", history.StatusCode)
	}
	if account.Upload != nil || account.MonthUsed != nil {
		t.Fatal("invented identity flow")
	}
	f.db.Exec("INSERT INTO grants VALUES(2,'one',?)", model.IdentityName("a", model.AuthID("alice")))
	vv, e := f.db.Views(viewer)
	if e != nil || len(vv) != 1 || len(vv[0].Report.Tags) != 1 {
		t.Fatal("partial permissions", e, vv)
	}
	if vv[0].Report.Discovery != nil || vv[0].Report.Tags[0].AuthID != "" || vv[0].Report.Tags[0].InboundTag != "" {
		t.Fatal("identity/count leakage")
	}
	response := f.req(t, "GET", "/api/admin/monitor-diagnostics?user_id=2", nil, f.admin, "")
	var counts []map[string]json.RawMessage
	json.NewDecoder(response.Body).Decode(&counts)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("diagnostics", response.StatusCode)
	}
	d := f.db.MonitorDiagnostics
	ds, _ := d(viewer)
	if len(ds) != 2 || ds[0]["counts"].(*model.Diagnostics).PermissionFiltered != 4 {
		t.Fatal("permission diagnostic", ds)
	}
	f.db.Exec("UPDATE servers SET seen=0 WHERE id='one'")
	off, _ := f.db.Views(admin)
	for _, v := range off {
		if v.ID == "one" && (v.Online || len(v.Report.Tags) != 5) {
			t.Fatal("offline identities vanished")
		}
	}
	f.db.Exec("UPDATE servers SET seen=? WHERE id='one'", time.Now().Unix())
	on, _ := f.db.Views(admin)
	for _, v := range on {
		if v.ID == "one" {
			for _, a := range v.Report.Tags {
				if a.AuthID == model.AuthID("alice") && a.ID != account.ID {
					t.Fatal("recovery changed ID")
				}
			}
		}
	}
	// Existing inbound keys/IDs and old history survive; grants do not expand to children.
	f.db.Exec("INSERT INTO grants VALUES(2,'one','inbound:a')")
	f.db.Exec("DELETE FROM grants WHERE user_id=2 AND tag=?", model.IdentityName("a", model.AuthID("alice")))
	vv, _ = f.db.Views(viewer)
	if len(vv[0].Report.Tags) != 1 || vv[0].Report.Tags[0].Accounting != "unattributed" {
		t.Fatal("parent grant expanded")
	}
	f.db.Exec("DELETE FROM server_grants WHERE user_id=2")
	vv, _ = f.db.Views(viewer)
	if len(vv) != 0 {
		t.Fatal("server revocation")
	}
}
