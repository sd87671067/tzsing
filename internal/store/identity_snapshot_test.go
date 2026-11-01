package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"tzsingbox/internal/model"
)

// Optional pre-deployment rehearsal against a consistent, isolated SQLite copy.
func TestUUIDMigrationSnapshotRehearsal(t *testing.T) {
	p := os.Getenv("TZSING_MIGRATION_COPY")
	if p == "" {
		t.Skip("isolated database snapshot required")
	}
	if filepath.Base(p) != "migration-copy.db" {
		t.Fatal("explicit isolated copy required")
	}
	s, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b, e := os.ReadFile(os.Getenv("TZSING_MIGRATION_TAGS"))
	if e != nil {
		t.Fatal(e)
	}
	var tags []model.Tag
	if json.Unmarshal(b, &tags) != nil {
		t.Fatal("tags")
	}
	before := map[string]string{}
	rows, e := s.Query("SELECT id,name||'|'||quota FROM nodes")
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var id, v string
		rows.Scan(&id, &v)
		before[id] = v
	}
	rows.Close()
	var grantsBefore, historyBefore int
	s.QueryRow("SELECT count(*) FROM grants").Scan(&grantsBefore)
	s.QueryRow("SELECT count(*) FROM history").Scan(&historyBefore)
	for i := 0; i < 2; i++ {
		tx, e := s.Begin()
		if e != nil {
			t.Fatal(e)
		}
		if e = MigrateUUIDIdentities(tx, "local", tags); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	s.QueryRow("SELECT count(*) FROM grants").Scan(&count)
	if count != grantsBefore {
		t.Fatal("grant count changed")
	}
	s.QueryRow("SELECT count(*) FROM history").Scan(&count)
	if count != historyBefore {
		t.Fatal("history count changed")
	}
	for id, v := range before {
		var got string
		if e = s.QueryRow("SELECT name||'|'||quota FROM nodes WHERE id=?", id).Scan(&got); e != nil || v != got {
			t.Fatal("opaque identity/name/quota changed")
		}
	}
	for _, tag := range tags {
		var id string
		if e = s.QueryRow("SELECT id FROM nodes WHERE server='local' AND tag=?", tag.Name).Scan(&id); e != nil {
			t.Fatal("UUID mapping missing")
		}
	}
	t.Logf("%d UUID identities rehearsed; IDs/names/quotas/grants and %d history rows preserved; migration idempotent", len(tags), historyBefore)
}
