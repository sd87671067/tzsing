package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestWALPersistenceAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Init("admin", "persistent-test-password"); e != nil {
		t.Fatal(e)
	}
	var mode string
	s.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if mode != "wal" {
		t.Fatal(mode)
	}
	s.Exec("INSERT INTO history VALUES('s','t',?,0,0,1,1)", time.Now().Add(-31*24*time.Hour).Unix()/60)
	s.Cleanup()
	var n int
	s.QueryRow("SELECT count(*) FROM history").Scan(&n)
	if n != 0 {
		t.Fatal("retention failed")
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	u, e := s.ByName("admin")
	if e != nil || u.Role != "admin" {
		t.Fatal("persistence failed")
	}
}
