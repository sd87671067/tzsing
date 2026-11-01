package server

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestConsolePrivacyAndIndependentGrants(t *testing.T) {
	f := setup(t)
	u, _, _ := f.db.Session(f.user.Value)
	vs, _ := f.db.Views(u)
	id := vs[0].Report.Tags[0].ID
	put(t, f, "/api/admin/nodes", map[string]any{"node_id": id, "name": "专线", "quota": 1234567, "expires_at": 1900000000, "billing_day": 15, "timezone": "Asia/Shanghai", "alert_threshold": 75}, f.admin, f.acs, 200)
	for _, show := range []bool{false, true, false} {
		put(t, f, "/api/admin/settings", map[string]any{"sample_seconds": 2, "retention_days": 30, "show_raw_tag": show, "show_quota": show, "show_expiry": show}, f.admin, f.acs, 200)
		_, raw := snapshot(t, f, f.user)
		for _, field := range []string{"quota", "expires_at", "raw_tag", "billing_day", "alert_threshold", "timezone", "period_start"} {
			if strings.Contains(raw, `"`+field+`"`) != show {
				t.Fatalf("hidden %s leaked or missing: %s", field, raw)
			}
		}
		for _, path := range []string{"/api/history?node_id=" + id + "&range=30d", "/api/export?node_id=" + id} {
			res := f.req(t, "GET", path, nil, f.user, "")
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 200 || strings.Contains(string(b), "expires_at") || strings.Contains(string(b), "quota") {
				t.Fatal(path, res.StatusCode, string(b))
			}
		}
	}
	// A valid node grant without its independent server grant is insufficient.
	f.db.Exec("DELETE FROM server_grants WHERE user_id=2")
	v, raw := snapshot(t, f, f.user)
	if len(v) != 0 {
		t.Fatal("node-only access leaked", raw)
	}
	for _, path := range []string{"/api/history?node_id=" + id, "/api/export?node_id=" + id} {
		res := f.req(t, "GET", path, nil, f.user, "")
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatal("node-only history leaked", res.StatusCode)
		}
	}
	// A server grant without node authorization is also insufficient.
	f.db.Exec("INSERT INTO server_grants VALUES(2,'one')")
	f.db.Exec("DELETE FROM grants WHERE user_id=2")
	v, raw = snapshot(t, f, f.user)
	if len(v) != 0 {
		t.Fatal("server-only access leaked", raw)
	}
	put(t, f, "/api/admin/grants", map[string]any{"user_id": 2, "servers": []string{"one"}, "grants": []map[string]string{{"server": "one", "tag": "allowed"}}}, f.admin, f.acs, 200)
	v, _ = snapshot(t, f, f.user)
	if len(v) != 1 || len(v[0].Report.Tags) != 1 {
		t.Fatal("intersection lost")
	}
	// Reject invalid dates/zones rather than silently applying UTC.
	put(t, f, "/api/admin/nodes", map[string]any{"node_id": id, "timezone": "Mars/Olympus"}, f.admin, f.acs, 400)
}

func TestConsoleHistoryBoundsAndMultipleDirect(t *testing.T) {
	f := setup(t)
	now := time.Now().Unix()
	tags := []model.Tag{{Name: "direct-a", Type: "Direct"}, {Name: "direct-b", Type: "direct"}, {Name: "relay", Type: "SOCKS", IP: &model.Exit{Verified: true, Updated: now, IPv4: "8.8.8.8"}}, {Name: "never", Type: "SOCKS"}, {Name: "reject", Type: "Reject"}, {Name: "block", Type: "Block"}, {Name: "logic", Type: "Selector", Egress: "relay"}}
	b, _ := json.Marshal(model.Report{At: now, Interval: 2, Tags: tags})
	f.db.Exec("UPDATE servers SET report=?,seen=? WHERE id='one'", b, now)
	put(t, f, "/api/admin/grants", map[string]any{"user_id": 2, "servers": []string{"one"}, "grants": []map[string]string{{"server": "one", "tag": "*"}}}, f.admin, f.acs, 200)
	v, _ := snapshot(t, f, f.user)
	if len(v) != 1 || len(v[0].Report.Tags) != 3 {
		t.Fatal("filter failure", v)
	}
	ts := v[0].Report.Tags
	if ts[0].Category != "直连" || ts[1].Category != "直连" || ts[2].Category != "中转" || ts[0].ID == ts[1].ID {
		t.Fatal("direct identity collision", ts)
	}
	for i, n := range ts {
		if n.Name != fmt.Sprintf("节点 %02d", i+1) {
			t.Fatal("visible numbering mismatch", n.Name)
		}
	}
	tx, _ := f.db.Begin()
	for i := 0; i < 30*24*60; i++ {
		if _, e := tx.Exec("INSERT INTO history VALUES('one','direct-a',?,1,2,3,4)", now/60-int64(i)); e != nil {
			t.Fatal(e)
		}
	}
	if e := tx.Commit(); e != nil {
		t.Fatal(e)
	}
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		res := f.req(t, "GET", "/api/history?node_id="+ts[0].ID+"&range="+period, nil, f.user, "")
		var out []map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if res.StatusCode != 200 || len(out) == 0 || len(out) > 720 {
			t.Fatal("unbounded history", period, res.StatusCode, len(out))
		}
	}
}
