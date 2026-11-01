package server

import (
	"encoding/json"
	"strings"
	"testing"
	"tzsingbox/internal/model"
)

func TestUUIDDisplayRenamePreservesAccountingAndRejectsFalseLimits(t *testing.T) {
	f := setup(t)
	id := model.UUIDAuthID("00000000-0000-4000-8000-000000000001")
	raw := model.IdentityName("shared", id)
	tags := []model.Tag{{Name: raw, AuthID: id, AuthScheme: "uuid-v1", AuthName: "alice", Identity: "inbound", InboundTag: "shared", Type: "vless", Accounting: "rule_user_observed"}}
	b, _ := json.Marshal(model.Report{Tags: tags, Interval: 2})
	f.db.Exec("UPDATE servers SET report=? WHERE id='one'", b)
	v, _ := snapshot(t, f, f.admin)
	nodeID := v[0].Report.Tags[0].ID
	f.db.Exec("UPDATE nodes SET quota=123 WHERE id=?", nodeID)
	f.db.Exec("INSERT INTO node_metadata VALUES(?,1900000000,1,'UTC',80)", nodeID)
	call := func(body map[string]any, want int) {
		t.Helper()
		r := f.req(t, "PATCH", "/api/admin/nodes", body, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatal(r.StatusCode)
		}
	}
	call(map[string]any{"node_id": nodeID, "name": "显示别名"}, 200)
	var quota, expiry int64
	var name string
	f.db.QueryRow("SELECT n.name,n.quota,m.expires_at FROM nodes n JOIN node_metadata m ON n.id=m.node_id WHERE n.id=?", nodeID).Scan(&name, &quota, &expiry)
	if name != "显示别名" || quota != 123 || expiry != 1900000000 {
		t.Fatal("rename cleared old settings")
	}
	call(map[string]any{"node_id": nodeID, "name": "x", "quota": 999}, 400)
	put(t, f, "/api/admin/nodes", map[string]any{"node_id": nodeID, "quota": 999}, f.admin, f.acs, 503)
	r := f.req(t, "PATCH", "/api/admin/nodes", map[string]any{"node_id": nodeID, "name": "hack"}, f.user, f.ucs)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("viewer escalated")
	}
	call(map[string]any{"node_id": nodeID, "name": ""}, 200)
	v, s := snapshot(t, f, f.admin)
	if v[0].Report.Tags[0].ID != nodeID || v[0].Report.Tags[0].Name != "alice" || strings.Contains(s, "auth_name") {
		t.Fatal("identity or name fallback lost")
	}
}
