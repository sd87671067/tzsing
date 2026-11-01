package store

import (
	"path/filepath"
	"testing"
)

func TestLegacyOutboundPermissionsRemainInertAndPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	// Synthetic pre-upgrade metadata remains available to rollback tools only.
	for _, q := range []string{
		"CREATE TABLE uuid_permissions(user_id INTEGER,node_id TEXT,can_change INTEGER)",
		"CREATE TABLE uuid_outbound_grants(user_id INTEGER,node_id TEXT,outbound_id TEXT)",
		"INSERT INTO uuid_permissions VALUES(2,'historic',1)",
		"INSERT INTO uuid_outbound_grants VALUES(2,'historic','old-outbound')",
	} {
		if _, e = s.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	s.Close()
	for i := 0; i < 2; i++ {
		s, e = Open(path)
		if e != nil {
			t.Fatal(e)
		}
		for _, table := range []string{"uuid_permissions", "uuid_outbound_grants"} {
			var n int
			if e = s.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 1 {
				t.Fatal("history lost", table, n, e)
			}
		}
		var n int
		s.QueryRow("SELECT count(*) FROM user_operations").Scan(&n)
		if n != 0 {
			t.Fatal("legacy permissions promoted")
		}
		s.Close()
	}
}
