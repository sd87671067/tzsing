// Package policy owns durable UUID policy and payload admission accounting.
// Monitoring snapshots never write this ledger. Each data-path debit commits
// with SQLite FULL synchronous. Pending reservations and settled usage are separate.
package policy

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"
)

type Limit struct {
	Quota      int64  `json:"quota"`
	ExpiresAt  int64  `json:"expires_at"`
	BillingDay int    `json:"billing_day"`
	Timezone   string `json:"timezone"`
}
type State struct {
	Limit
	Used      int64  `json:"used"`
	Reserved  int64  `json:"reserved"`
	Upload    int64  `json:"actual_upload"`
	Download  int64  `json:"actual_download"`
	Uncertain bool   `json:"uncertain"`
	Start     int64  `json:"start"`
	Since     int64  `json:"since"`
	Status    string `json:"status"`
}
type Ledger struct {
	owner string
	db    *sql.DB
	mu    sync.Mutex
	Now   func() time.Time
}

// Qualified stays false until authenticated payload, protocol and crash recovery
// acceptance is complete. A live heartbeat alone never enables production policy.
const Qualified = false

var ErrDenied = errors.New("UUID policy denied payload admission")

func Open(path string) (*Ledger, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	token := make([]byte, 24)
	if _, e = rand.Read(token); e != nil {
		db.Close()
		return nil, e
	}
	l := &Ledger{db: db, Now: time.Now, owner: hex.EncodeToString(token)}
	for _, q := range []string{"PRAGMA busy_timeout=5000", `CREATE TABLE IF NOT EXISTS reservations(token TEXT PRIMARY KEY,inbound TEXT NOT NULL,user TEXT NOT NULL,start INTEGER NOT NULL,amount INTEGER NOT NULL,direction TEXT NOT NULL,owner TEXT NOT NULL,at INTEGER NOT NULL,actual INTEGER)`, `CREATE INDEX IF NOT EXISTS pending_reservations ON reservations(inbound,user,actual)`, `CREATE TABLE IF NOT EXISTS transferred(inbound TEXT NOT NULL,user TEXT NOT NULL,start INTEGER NOT NULL,direction TEXT NOT NULL,actual INTEGER NOT NULL,PRIMARY KEY(inbound,user,start,direction))`, "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", `CREATE TABLE IF NOT EXISTS policies(inbound TEXT NOT NULL,user TEXT NOT NULL,quota INTEGER NOT NULL,expires INTEGER NOT NULL,day INTEGER NOT NULL,zone TEXT NOT NULL,since INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(inbound,user))`, `CREATE TABLE IF NOT EXISTS usage(inbound TEXT NOT NULL,user TEXT NOT NULL,start INTEGER NOT NULL,used INTEGER NOT NULL,PRIMARY KEY(inbound,user,start))`, `CREATE TABLE IF NOT EXISTS runtime(id INTEGER PRIMARY KEY CHECK(id=1),pid INTEGER NOT NULL,at INTEGER NOT NULL)`} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, e
		}
	}
	os.Chmod(path, 0600)
	return l, nil
}
func (l *Ledger) Close() error { return l.db.Close() }
func Normalize(v Limit) (Limit, error) {
	if v.Timezone == "" {
		v.Timezone = "UTC"
	}
	if v.BillingDay == 0 {
		v.BillingDay = 1
	}
	_, e := time.LoadLocation(v.Timezone)
	if e != nil || v.Quota < 0 || v.Quota > 1<<60 || v.ExpiresAt < 0 || v.ExpiresAt > 253402300799 || v.BillingDay < 1 || v.BillingDay > 31 {
		return v, fmt.Errorf("额度、到期时间、时区或重置日无效")
	}
	return v, nil
}
func BillingStart(now time.Time, day int, zone string) time.Time {
	loc, e := time.LoadLocation(zone)
	if e != nil {
		loc = time.UTC
	}
	if day < 1 || day > 31 {
		day = 1
	}
	now = now.In(loc)
	start := func(y int, m time.Month) time.Time {
		return time.Date(y, m, min(day, time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day()), 0, 0, 0, 0, loc)
	}
	s := start(now.Year(), now.Month())
	if now.Before(s) {
		s = start(now.Year(), now.Month()-1)
	}
	return s
}
func (l *Ledger) Set(in, user string, v Limit) error {
	v, e := Normalize(v)
	if e != nil {
		return e
	}
	if in == "" || user == "" || len(in) > 128 || len(user) > 128 {
		return fmt.Errorf("认证身份无效")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var oldDay int
	var oldZone string
	e = l.db.QueryRow("SELECT day,zone FROM policies WHERE inbound=? AND user=?", in, user).Scan(&oldDay, &oldZone)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	// A period edit never discards already charged bytes. Transfer the current
	// period balance once, transactionally, into the new period before applying it.
	tx, e := l.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if oldDay != 0 && (oldDay != v.BillingDay || oldZone != v.Timezone) {
		oldStart := BillingStart(l.Now(), oldDay, oldZone).Unix()
		newStart := BillingStart(l.Now(), v.BillingDay, v.Timezone).Unix()
		if oldStart != newStart {
			_, e = tx.Exec(`INSERT INTO usage SELECT inbound,user,?,used FROM usage WHERE inbound=? AND user=? AND start=? ON CONFLICT(inbound,user,start) DO UPDATE SET used=MAX(usage.used,excluded.used)`, newStart, in, user, oldStart)
			if e != nil {
				return e
			}
		}
	}
	_, e = tx.Exec(`INSERT INTO policies VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(inbound,user) DO UPDATE SET quota=excluded.quota,expires=excluded.expires,day=excluded.day,zone=excluded.zone,revision=policies.revision+1`, in, user, v.Quota, v.ExpiresAt, v.BillingDay, v.Timezone, l.Now().Unix())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (l *Ledger) Remove(in, user string) error {
	_, e := l.db.Exec("DELETE FROM policies WHERE inbound=? AND user=?", in, user)
	return e
}
func (l *Ledger) State(in, user string) (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state(in, user)
}
func (l *Ledger) state(in, user string) (State, error) {
	s := State{Limit: Limit{BillingDay: 1, Timezone: "UTC"}, Status: "unlimited"}
	e := l.db.QueryRow("SELECT quota,expires,day,zone,since FROM policies WHERE inbound=? AND user=?", in, user).Scan(&s.Quota, &s.ExpiresAt, &s.BillingDay, &s.Timezone, &s.Since)
	if errors.Is(e, sql.ErrNoRows) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	s.Start = BillingStart(l.Now(), s.BillingDay, s.Timezone).Unix()
	e = l.db.QueryRow("SELECT used FROM usage WHERE inbound=? AND user=? AND start=?", in, user, s.Start).Scan(&s.Used)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return s, e
	}
	if e = l.db.QueryRow("SELECT COALESCE(SUM(amount),0) FROM reservations WHERE inbound=? AND user=? AND actual IS NULL", in, user).Scan(&s.Reserved); e != nil {
		return s, e
	}
	var foreign int
	if e = l.db.QueryRow("SELECT COUNT(*) FROM reservations WHERE inbound=? AND user=? AND actual IS NULL AND owner!=?", in, user, l.owner).Scan(&foreign); e != nil {
		return s, e
	}
	s.Uncertain = foreign > 0
	if e = l.db.QueryRow("SELECT COALESCE(SUM(CASE WHEN direction='upload' THEN actual ELSE 0 END),0),COALESCE(SUM(CASE WHEN direction='download' THEN actual ELSE 0 END),0) FROM transferred WHERE inbound=? AND user=? AND start=?", in, user, s.Start).Scan(&s.Upload, &s.Download); e != nil {
		return s, e
	}
	if s.ExpiresAt > 0 && s.ExpiresAt <= l.Now().Unix() {
		s.Status = "expired"
	} else if s.Uncertain {
		s.Status = "reconciliation_required"
	} else if s.Quota > 0 && s.Used >= s.Quota {
		s.Status = "quota_exceeded"
	} else {
		s.Status = "enabled"
	}
	return s, nil
}

// Charge is an admission-only check. Payload must use Reserve/Settle so that
// unknown in-flight bytes never become committed usage.
func (l *Ledger) Charge(in, user string, n int64) error {
	if n != 0 {
		return ErrDenied
	}
	s, e := l.State(in, user)
	if e != nil {
		return e
	}
	if s.Uncertain {
		return ErrUncertain
	}
	if s.Status == "expired" || (s.Quota > 0 && s.Used+s.Reserved >= s.Quota) {
		return ErrDenied
	}
	return nil
}
func (l *Ledger) Heartbeat() error {
	_, e := l.db.Exec("INSERT INTO runtime VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET pid=excluded.pid,at=excluded.at", os.Getpid(), time.Now().Unix())
	return e
}
func (l *Ledger) Ready() bool {
	var pid int
	var at int64
	return l.db.QueryRow("SELECT pid,at FROM runtime WHERE id=1").Scan(&pid, &at) == nil && time.Now().Unix()-at < 4 && time.Now().Unix() >= at && processAlive(pid)
}

func processAlive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }
