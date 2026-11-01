package store

import (
	"path/filepath"
	"testing"
	"tzsingbox/internal/model"
)

func TestUUIDMigrationPreservesOpaqueIDGrantsAndHistoryOnce(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "identity.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','s','x')")
	s.Exec("INSERT INTO users VALUES(1,'viewer','user',0,'x')")
	legacy := model.AuthID("old-name")
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	old, current := model.IdentityName("shared", legacy), model.IdentityName("shared", id)
	s.Exec("INSERT INTO nodes VALUES('opaque','s',?,'中文名',500)", old)
	s.Exec("INSERT INTO grants VALUES(1,'s',?)", old)
	s.Exec("INSERT INTO aliases VALUES(1,'opaque','个人名')")
	s.Exec("INSERT INTO node_metadata VALUES('opaque',123,10,'Asia/Shanghai',80)")
	s.Exec("INSERT INTO history VALUES('s',?,1,0,0,12,34)", old)
	tag := model.Tag{Identity: "inbound", Type: "vless", InboundTag: "shared", AuthID: id, LegacyAuthID: legacy, AuthScheme: "uuid-v1"}
	migrate := func(tag model.Tag) {
		t.Helper()
		tx, e := s.Begin()
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if e = MigrateUUIDIdentities(tx, "s", []model.Tag{tag}); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	migrate(tag)
	migrate(tag)
	// Exact reversal keeps journals and historical rows; the next upgrade can
	// replay the recorded binding without inventing/transferring permissions.
	for _, table := range []string{"nodes", "grants", "history", "counters", "daily_flow", "monthly_flow", "monthly", "billing_usage", "exit_cache"} {
		if _, e = s.Exec("UPDATE "+table+" SET tag=? WHERE server='s' AND tag=?", old, current); e != nil {
			t.Fatal(e)
		}
	}
	migrate(tag)
	var got, name string
	var used int
	s.QueryRow("SELECT id,name FROM nodes WHERE server='s' AND tag=?", current).Scan(&got, &name)
	if got != "opaque" || name != "中文名" {
		t.Fatal("lost identity metadata")
	}
	s.QueryRow("SELECT upload+download FROM history WHERE tag=?", current).Scan(&used)
	if used != 46 {
		t.Fatal("lost history")
	}
	var n int
	s.QueryRow("SELECT count(*) FROM grants WHERE tag=?", current).Scan(&n)
	if n != 1 {
		t.Fatal("lost grants")
	}
	// A renamed account remains this UUID. A rotated UUID cannot steal its grant.
	tag.LegacyAuthID = model.AuthID("new-name")
	migrate(tag)
	tag.LegacyAuthID = legacy
	tag.AuthID = model.UUIDAuthID("22222222-2222-4222-8222-222222222222")
	migrate(tag)
	s.QueryRow("SELECT count(*) FROM grants WHERE tag=?", model.IdentityName("shared", tag.AuthID)).Scan(&n)
	if n != 0 {
		t.Fatal("rotated UUID inherited grants")
	}
	s.QueryRow("SELECT name FROM aliases WHERE node_id='opaque'").Scan(&got)
	if got != "个人名" {
		t.Fatal("lost alias")
	}
}
