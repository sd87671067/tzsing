package policy

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ledger(t *testing.T) (*Ledger, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ledger.sqlite")
	l, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return l, p
}
func TestReservationsNeverCountAsUsedAndSettlementIsIdempotent(t *testing.T) {
	l, _ := ledger(t)
	if e := l.Set("443", "uuid-a", Limit{Quota: 100}); e != nil {
		t.Fatal(e)
	}
	r, e := l.Reserve("443", "uuid-a", "download", 80)
	if e != nil {
		t.Fatal(e)
	}
	s, e := l.State("443", "uuid-a")
	if e != nil || s.Used != 0 || s.Reserved != 80 || s.Download != 0 {
		t.Fatal(s, e)
	}
	if e = l.Settle(r.Token, 7); e != nil {
		t.Fatal(e)
	}
	if e = l.Settle(r.Token, 7); e != nil {
		t.Fatal(e)
	}
	if e = l.Settle(r.Token, 8); e == nil {
		t.Fatal("conflicting replay accepted")
	}
	s, e = l.State("443", "uuid-a")
	if e != nil || s.Used != 7 || s.Download != 7 || s.Reserved != 0 {
		t.Fatal(s, e)
	}
}
func TestConcurrentQuotaAndFourteenIdentityIsolation(t *testing.T) {
	l, _ := ledger(t)
	for i := 0; i < 14; i++ {
		user := string(rune('a' + i))
		if e := l.Set("443", user, Limit{Quota: 1000}); e != nil {
			t.Fatal(e)
		}
	}
	var wg sync.WaitGroup
	var charged atomic.Int64
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := l.Reserve("443", "a", "upload", 37)
			if errors.Is(e, ErrDenied) {
				return
			}
			if e != nil {
				t.Error(e)
				return
			}
			if e = l.Settle(r.Token, r.Amount); e != nil {
				t.Error(e)
				return
			}
			charged.Add(r.Amount)
		}()
	}
	wg.Wait()
	s, e := l.State("443", "a")
	if e != nil || s.Used != 1000 || charged.Load() != 1000 || s.Upload != 1000 {
		t.Fatal(s, e, charged.Load())
	}
	for i := 1; i < 14; i++ {
		s, e = l.State("443", string(rune('a'+i)))
		if e != nil || s.Used != 0 || s.Reserved != 0 {
			t.Fatal("cross UUID charge", s, e)
		}
	}
}
func TestRestartKeepsUncertainReservationSeparateAndBlocksOnlyOwner(t *testing.T) {
	l, p := ledger(t)
	l.Set("443", "a", Limit{Quota: 100})
	r, e := l.Reserve("443", "a", "download", 80)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	next, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	s, e := next.State("443", "a")
	if e != nil || s.Used != 0 || s.Reserved != 80 || !s.Uncertain || s.Status != "reserved_uncertain" {
		t.Fatal(s, e)
	}
	r2, e := next.Reserve("443", "a", "upload", 100)
	if e != nil || r2.Amount != 20 {
		t.Fatal("restart refunded uncertain reservation", e, r2)
	}
	next.Settle(r2.Token, 0)
	if _, e = next.Reserve("443", "b", "upload", 1); e != nil {
		t.Fatal("other UUID blocked", e)
	}
	// An externally known result may be reconciled exactly once; restart alone
	// must never invent this result or refund potentially delivered bytes.
	if e = next.Settle(r.Token, 5); e != nil {
		t.Fatal(e)
	}
	s, e = next.State("443", "a")
	if e != nil || s.Used != 5 || s.Uncertain || s.Reserved != 0 {
		t.Fatal(s, e)
	}
}
func TestExpiryQuotaEditMonthlyResetAndPersistence(t *testing.T) {
	l, p := ledger(t)
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	if e := l.Set("443", "a", Limit{Quota: 5, ExpiresAt: now.Unix() - 1}); e != nil {
		t.Fatal(e)
	}
	if _, e := l.Reserve("443", "a", "upload", 1); !errors.Is(e, ErrDenied) {
		t.Fatal("expired admitted", e)
	}
	l.Set("443", "a", Limit{Quota: 5, ExpiresAt: now.Unix() + 100})
	r, e := l.Reserve("443", "a", "upload", 5)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Settle(r.Token, 5); e != nil {
		t.Fatal(e)
	}
	if _, e = l.Reserve("443", "a", "download", 1); !errors.Is(e, ErrDenied) {
		t.Fatal("over quota", e)
	}
	l.Set("443", "a", Limit{Quota: 10})
	r, e = l.Reserve("443", "a", "download", 1)
	if e != nil {
		t.Fatal(e)
	}
	l.Settle(r.Token, 1)
	now = now.Add(48 * time.Hour)
	s, e := l.State("443", "a")
	if e != nil || s.Used != 0 {
		t.Fatal("month not reset", s, e)
	}
	l.Set("443", "a", Limit{})
	l.Close()
	next, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.Now = l.Now
	s, e = next.State("443", "a")
	if e != nil || s.Quota != 0 || s.ExpiresAt != 0 {
		t.Fatal("unlimited lost on restart", s, e)
	}
}
func TestDatabaseFailureNeverAdmitsOrSettles(t *testing.T) {
	l, _ := ledger(t)
	r, e := l.Reserve("443", "a", "upload", 3)
	if e != nil {
		t.Fatal(e)
	}
	l.Close()
	if _, e = l.Reserve("443", "a", "download", 1); e == nil {
		t.Fatal("closed DB admitted")
	}
	if e = l.Settle(r.Token, 3); e == nil {
		t.Fatal("closed DB settlement succeeded")
	}
	if l.Ready() {
		t.Fatal("closed executor reported ready")
	}
}
