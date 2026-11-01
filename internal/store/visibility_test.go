package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestFilteredViewPersistenceAndServerIdentity(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	u := User{Role: "admin"}
	now := time.Now().Unix()
	for _, server := range []string{"a", "b"} {
		tags := []model.Tag{{Name: "direct", Type: "Direct"}, {Name: "proxy", Type: "SOCKS", IP: &model.Exit{Verified: true, IPv4: "8.8.8.8", Updated: now}}, {Name: "never", Type: "SOCKS"}, {Name: "blocked", Type: "Reject"}, {Name: "selector", Type: "URLTest", Egress: "proxy"}}
		b, _ := json.Marshal(model.Report{Interval: 2, Tags: tags})
		s.Exec("INSERT INTO servers(id,name,token,seen,report) VALUES(?,?,?, ?,?)", server, server, "x", now, b)
	}
	v, e := s.Views(u)
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 2 || len(v[0].Report.Tags) != 2 || len(v[1].Report.Tags) != 2 {
		t.Fatalf("filter: %+v", v)
	}
	if v[0].Report.Tags[0].ID == v[1].Report.Tags[0].ID {
		t.Fatal("cross-server ID collision")
	}
	if v[0].Report.Tags[0].RawTag != "" {
		t.Fatal("ordinary admin view must respect hiding")
	}
	m, e := s.ManagementViews(u)
	if e != nil || len(m[0].Report.Tags) != 3 || m[0].Report.Tags[2].RawTag != "never" {
		t.Fatal("management includes helpers or lost an actual outbound", e)
	}
	var retained int
	s.QueryRow("SELECT count(*) FROM nodes WHERE tag IN ('blocked','selector')").Scan(&retained)
	if retained != 4 {
		t.Fatal("hidden identities were deleted")
	}
	old := model.Exit{Verified: true, IPv4: "8.8.4.4", Updated: now - 10, Source: "ipify", Path: "singbox_route"}
	b, _ := json.Marshal(old)
	s.Exec("INSERT INTO exit_cache VALUES('a','never',?)", b)
	n := model.Tag{Name: "never", Type: "SOCKS", IP: &model.Exit{Error: "timeout", Attempted: now}}
	if e = s.Present(u, "a", &n); e != nil {
		t.Fatal(e)
	}
	if !n.DisplayEligible || n.Verification != "stale" || n.IP.IPv4 != "8.8.4.4" || n.IP.Updated != now-10 {
		t.Fatalf("stale recovery: %+v", n)
	}
	n = model.Tag{Name: "bad", Type: "SOCKS", IP: &model.Exit{Verified: true, IPv4: "127.0.0.1", Updated: now}}
	s.Present(u, "a", &n)
	if n.DisplayEligible {
		t.Fatal("private exit accepted")
	}
}
