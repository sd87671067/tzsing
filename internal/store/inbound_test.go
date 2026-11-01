package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestInboundMigrationPreservesLegacyNamesHistoryAndNoSharedCounterAttribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	s.Exec("INSERT INTO users(id,name,role,hash) VALUES(1,'admin','admin','h'),(2,'viewer','user','h')")
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','server','h')")
	s.Exec("INSERT INTO nodes VALUES('legacy-id','s','direct','旧名称',1000)")
	s.Exec("INSERT INTO aliases VALUES(2,'legacy-id','个人旧名称')")
	s.Exec("INSERT INTO history VALUES('s','direct',1,0,0,30,70)")
	s.Exec("INSERT INTO counters VALUES('s','direct','epoch',30,70,30,70,1)")
	s.Exec("INSERT INTO grants VALUES(2,'s','direct')")
	s.Exec("INSERT INTO server_grants VALUES(2,'s')")
	report := model.Report{Tags: []model.Tag{{Name: "inbound:a", InboundTag: "a", Identity: "inbound", Type: "direct", Egress: "direct", RouteVersion: "new"}, {Name: "inbound:b", InboundTag: "b", Identity: "inbound", Type: "direct", Egress: "direct", RouteVersion: "new"}}, At: time.Now().Unix()}
	b, _ := json.Marshal(report)
	s.Exec("UPDATE servers SET report=?,seen=?", b, time.Now().Unix())
	s.Close()
	for i := 0; i < 2; i++ {
		s, e = Open(path)
		if e != nil {
			t.Fatal(e)
		}
		admin := User{ID: 1, Role: "admin"}
		v, e := s.Views(admin)
		if e != nil || len(v) != 1 || len(v[0].Report.Tags) != 2 {
			t.Fatal("inbound cards", e)
		}
		for _, tag := range v[0].Report.Tags {
			if tag.ID == "legacy-id" || tag.Upload != nil && *tag.Upload != 0 {
				t.Fatal("shared outbound history attributed to inbound")
			}
		}
		viewer := User{ID: 2, Role: "user"}
		vv, e := s.Views(viewer)
		if e != nil || len(vv) != 0 {
			t.Fatal("old outbound grant expanded to inbound", e)
		}
		var name, alias string
		var total int64
		s.QueryRow("SELECT name FROM nodes WHERE id='legacy-id'").Scan(&name)
		s.QueryRow("SELECT name FROM aliases WHERE node_id='legacy-id'").Scan(&alias)
		s.QueryRow("SELECT SUM(upload+download) FROM history WHERE tag='direct'").Scan(&total)
		if name != "旧名称" || alias != "个人旧名称" || total != 100 {
			t.Fatal("legacy data not preserved")
		}
		s.Close()
	}
}
func TestInboundExitCacheMustMatchCurrentMapping(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','server','h')")
	old := model.Exit{Verified: true, Updated: time.Now().Unix(), IPv4: "1.1.1.1", Path: "direct@old"}
	b, _ := json.Marshal(old)
	s.Exec("INSERT INTO exit_cache VALUES('s','inbound:a',?)", b)
	for _, egress := range []string{"", "other", "direct"} {
		tag := model.Tag{Name: "inbound:a", InboundTag: "a", Identity: "inbound", Type: "direct", Egress: egress, RouteVersion: "new"}
		if e = s.Present(User{Role: "admin"}, "s", &tag); e != nil {
			t.Fatal(e)
		}
		if tag.IP != nil {
			t.Fatal("cached exit from previous mapping disclosed")
		}
	}
}

func TestInboundInventoryExcludesMixedLegacyCounters(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','test','fixture')")
	report := model.Report{Tags: []model.Tag{{Name: "inbound:a", InboundTag: "a", Identity: "inbound", Type: "vless", Egress: "direct", EgressType: "direct"}, {Name: "direct", Type: "direct", Egress: "direct"}}, At: time.Now().Unix()}
	b, _ := json.Marshal(report)
	s.Exec("UPDATE servers SET report=?,seen=?", b, time.Now().Unix())
	s.Exec("INSERT INTO counters VALUES('s','direct','e',999,999,999,999,1)")
	for _, management := range []bool{false, true} {
		views, e := s.views(User{Role: "admin"}, management)
		if e != nil || len(views) != 1 || len(views[0].Report.Tags) != 1 {
			t.Fatal("legacy measurement leaked", e, views)
		}
		tag := views[0].Report.Tags[0]
		if tag.Type != "vless" || tag.Upload != nil && *tag.Upload != 0 {
			t.Fatal("legacy measurement attributed", tag)
		}
	}
}
