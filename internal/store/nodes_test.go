package store

import (
	"path/filepath"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestNodePersistenceAndMonthlyIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	s.Exec("INSERT INTO users(id,name,role,hash) VALUES(1,'viewer','user','hash')")
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','Server','token')")
	s.Exec("INSERT INTO grants VALUES(1,'s','*')")
	n := model.Tag{Name: "private_tag", Type: "Direct", Kind: "actual"}
	u := User{ID: 1, Role: "user"}
	if e = s.Present(u, "s", &n); e != nil {
		t.Fatal(e)
	}
	id := n.ID
	s.Exec("UPDATE nodes SET name='东京专线',quota=1000")
	s.Exec("INSERT INTO aliases VALUES(1,?,'我的东京')", id)
	s.Exec("UPDATE settings SET value=1 WHERE key='show_raw_tag'")
	s.Exec("INSERT INTO monthly VALUES('s','private_tag',?,250)", time.Now().UTC().Format("2006-01"))
	s.Exec("INSERT INTO monthly VALUES('s','private_tag','2000-01',99999)")
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n = model.Tag{Name: "private_tag", Type: "Direct", Kind: "actual"}
	if e = s.Present(u, "s", &n); e != nil {
		t.Fatal(e)
	}
	if n.ID != id || n.Name != "我的东京" || n.RawTag != "private_tag" || n.Quota != 1000 || n.MonthUsed == nil || *n.MonthUsed != 250 {
		t.Fatalf("persistence/month %+v", n)
	}
	s.Exec("UPDATE settings SET value=0 WHERE key='show_raw_tag'")
	n = model.Tag{Name: "private_tag", Type: "Direct", Kind: "actual"}
	s.Present(u, "s", &n)
	if n.RawTag != "" {
		t.Fatal("hidden switch")
	}
}

func TestMonthlyHistoryBackfillOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backfill.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	s.Exec("DELETE FROM preferences WHERE key='monthly_history_initialized'")
	s.Exec("INSERT INTO history VALUES('s','t',?,0,0,20,30)", time.Now().Unix()/60)
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	var used int64
	s.QueryRow("SELECT used FROM monthly WHERE server='s' AND tag='t'").Scan(&used)
	if used != 50 {
		t.Fatal("backfill missing", used)
	}
	s.Exec("UPDATE monthly SET used=100")
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.QueryRow("SELECT used FROM monthly WHERE server='s' AND tag='t'").Scan(&used)
	if used != 100 {
		t.Fatal("backfill repeated", used)
	}
}
