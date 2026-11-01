package server

import (
	"encoding/json"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestSelectAllGrantsNeverIncludeFutureNodes(t *testing.T) {
	f := setup(t)
	put(t, f, "/api/admin/grants", map[string]any{"user_id": 2, "servers": []string{"one"}, "grants": []map[string]string{{"server": "one", "tag": "*"}}}, f.admin, f.acs, 200)
	u, _, _ := f.db.Session(f.user.Value)
	if !f.db.Allowed(u, "one", "allowed") || !f.db.Allowed(u, "one", "*") {
		t.Fatal("current grant lost")
	}
	b, _ := json.Marshal(model.Report{At: time.Now().Unix(), Interval: 2, Tags: []model.Tag{{Name: "allowed", Type: "Direct"}, {Name: "future", Type: "Direct"}}})
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, time.Now().Unix())
	if f.db.Allowed(u, "one", "future") {
		t.Fatal("new node automatically authorized")
	}
	v, _ := snapshot(t, f, f.user)
	if len(v[0].Report.Tags) != 1 {
		t.Fatal("future node leaked", v)
	}
	admin, _ := f.db.ByName("admin")
	v, e := f.db.ManagementViews(admin)
	if e != nil || len(v[0].Report.Tags) != 2 {
		t.Fatal("new node missing from admin choices")
	}
}
