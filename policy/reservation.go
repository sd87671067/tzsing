package policy

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrUncertain = errors.New("unsettled payload from a previous executor; reconciliation required")

type Reservation struct {
	Token  string
	Amount int64
	Start  int64
}

// Reserve atomically considers committed usage AND outstanding reservations.
// A reservation is never returned as billable/actual usage. A previous process's
// unresolved I/O remains visible and blocks only this identity, not other UUIDs.
func (l *Ledger) Reserve(in, user, direction string, amount int64) (Reservation, error) {
	var r Reservation
	if in == "" || user == "" || amount <= 0 || amount > 64<<10 || (direction != "upload" && direction != "download") {
		return r, ErrDenied
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, e := l.db.Conn(context.Background())
	if e != nil {
		return r, e
	}
	defer conn.Close()
	ctx := context.Background()
	if _, e = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return r, e
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	now := l.Now()
	if _, e = conn.ExecContext(ctx, `INSERT OR IGNORE INTO policies VALUES(?,?,0,0,1,'UTC',?,1)`, in, user, now.Unix()); e != nil {
		return r, e
	}
	var v Limit
	if e = conn.QueryRowContext(ctx, "SELECT quota,expires,day,zone FROM policies WHERE inbound=? AND user=?", in, user).Scan(&v.Quota, &v.ExpiresAt, &v.BillingDay, &v.Timezone); e != nil {
		return r, e
	}
	if v.ExpiresAt > 0 && now.Unix() >= v.ExpiresAt {
		return r, ErrDenied
	}
	r.Start = BillingStart(now, v.BillingDay, v.Timezone).Unix()
	var used, reserved int64
	e = conn.QueryRowContext(ctx, "SELECT used FROM usage WHERE inbound=? AND user=? AND start=?", in, user, r.Start).Scan(&used)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return r, e
	}
	// Include all pending I/O, including operations crossing a month boundary.
	if e = conn.QueryRowContext(ctx, "SELECT COALESCE(SUM(amount),0) FROM reservations WHERE inbound=? AND user=? AND actual IS NULL AND (start=? OR owner=?)", in, user, r.Start, l.owner).Scan(&reserved); e != nil {
		return r, e
	}
	if v.Quota > 0 {
		remaining := v.Quota - used - reserved
		if remaining <= 0 {
			return r, ErrDenied
		}
		amount = min(amount, remaining)
	}
	r.Amount = amount
	token := make([]byte, 24)
	if _, e = rand.Read(token); e != nil {
		return r, e
	}
	r.Token = hex.EncodeToString(token)
	if _, e = conn.ExecContext(ctx, "INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?,NULL)", r.Token, in, user, r.Start, amount, direction, l.owner, now.Unix()); e != nil {
		return r, e
	}
	_, e = conn.ExecContext(ctx, "COMMIT")
	return r, e
}

// Settle is idempotent for an identical result. A failed commit leaves a durable
// pending reservation; callers fail closed and must not invent a byte count.
func (l *Ledger) Settle(token string, actual int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, e := l.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var in, user, dir string
	var start, amount int64
	var old sql.NullInt64
	if e = tx.QueryRow("SELECT inbound,user,start,amount,direction,actual FROM reservations WHERE token=?", token).Scan(&in, &user, &start, &amount, &dir, &old); e != nil {
		return e
	}
	if actual < 0 || actual > amount {
		return ErrDenied
	}
	if old.Valid {
		if old.Int64 != actual {
			return fmt.Errorf("conflicting settlement")
		}
		return nil
	}
	result, e := tx.Exec("UPDATE reservations SET actual=? WHERE token=? AND actual IS NULL", actual, token)
	if e != nil {
		return e
	}
	count, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if count != 1 {
		return fmt.Errorf("settlement conflict")
	}
	if _, e = tx.Exec(`INSERT INTO usage VALUES(?,?,?,?) ON CONFLICT(inbound,user,start) DO UPDATE SET used=used+excluded.used`, in, user, start, actual); e != nil {
		return e
	}
	if _, e = tx.Exec(`INSERT INTO transferred VALUES(?,?,?,?,?) ON CONFLICT(inbound,user,start,direction) DO UPDATE SET actual=actual+excluded.actual`, in, user, start, dir, actual); e != nil {
		return e
	}
	return tx.Commit()
}
