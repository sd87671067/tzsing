package policy

import (
	"testing"
	"time"
)

func TestLiveReaderDoesNotMislabelExecutorReservations(t *testing.T) {
	l, p := ledger(t)
	if e := l.Heartbeat(); e != nil {
		t.Fatal(e)
	}
	if !l.Ready() {
		t.Fatal("versioned executor not ready")
	}
	l.Set("443", "a", Limit{Quota: 100})
	r, e := l.Reserve("443", "a", "download", 20)
	if e != nil {
		t.Fatal(e)
	}
	reader, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	s, e := reader.State("443", "a")
	if e != nil || s.Uncertain || s.Reserved != 20 {
		t.Fatal("live executor mislabelled by reader", s, e)
	}
	l.Settle(r.Token, 3)
}
func TestCrashReservationConsumesOnlyItsBillingPeriod(t *testing.T) {
	l, p := ledger(t)
	now := time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	l.Set("443", "a", Limit{Quota: 10})
	l.Reserve("443", "a", "download", 10)
	l.Close()
	next, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.Now = func() time.Time { return now }
	if e = next.Charge("443", "a", 0); e == nil {
		t.Fatal("uncertain allowance refunded")
	}
	now = now.Add(2 * time.Hour)
	s, e := next.State("443", "a")
	if e != nil || s.Used != 0 || s.Reserved != 0 || s.Uncertain {
		t.Fatal("old uncertainty leaked into new month", s, e)
	}
	if e = next.Charge("443", "a", 0); e != nil {
		t.Fatal("month not restored", e)
	}
	r, e := next.Reserve("443", "a", "upload", 10)
	if e != nil || r.Amount != 10 {
		t.Fatal(r, e)
	}
}

func TestExecutorIdentityProofRequiresCurrentOwnerAndExactUUIDName(t *testing.T) {
	l, p := ledger(t)
	l.Heartbeat()
	l.RegisterIdentity("443", "stable-a", "auth-a")
	l.MarkInboundStarted("443")
	reader, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	if !reader.Registered("443", "stable-a", "auth-a") || reader.Registered("443", "stable-a", "other") || reader.Registered("443", "stable-b", "auth-a") || reader.RegisteredCount("443") != 1 {
		t.Fatal("identity proof accepted a disk-only change")
	}
	next, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.Heartbeat()
	if reader.Registered("443", "stable-a", "auth-a") {
		t.Fatal("old executor registration reused")
	}
	next.RegisterIdentity("443", "stable-b", "auth-b")
	next.MarkInboundStarted("443")
	if !reader.Registered("443", "stable-b", "auth-b") {
		t.Fatal("current registration lost")
	}
}
