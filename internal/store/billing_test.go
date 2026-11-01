package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBillingCalendarAndGrantMigration(t *testing.T) {
	for _, c := range []struct {
		now        string
		day        int
		zone, want string
	}{{"2026-03-01T00:00:00Z", 31, "UTC", "2026-02-28T00:00:00Z"}, {"2026-11-01T00:00:00Z", 15, "Asia/Shanghai", "2026-10-14T16:00:00Z"}, {"2026-11-15T16:01:00Z", 15, "America/New_York", "2026-11-15T05:00:00Z"}} {
		now, _ := time.Parse(time.RFC3339, c.now)
		if got := BillingStart(now, c.day, c.zone).UTC().Format(time.RFC3339); got != c.want {
			t.Fatal(got, c.want)
		}
	}
	p := filepath.Join(t.TempDir(), "migration.db")
	s, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	s.Exec("INSERT INTO users VALUES(1,'v','user',0,'h')")
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','s','h')")
	s.Exec("INSERT INTO grants VALUES(1,'s','node')")
	s.Exec("DELETE FROM preferences WHERE key='server_grants_initialized'")
	s.Close()
	s, e = Open(p)
	if e != nil {
		t.Fatal(e)
	}
	u := User{ID: 1, Role: "user"}
	if !s.Allowed(u, "s", "node") {
		t.Fatal("legacy grants not migrated")
	}
	s.Exec("DELETE FROM server_grants")
	s.Close()
	s, e = Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Allowed(u, "s", "node") {
		t.Fatal("revoked server access recreated on restart")
	}
}
