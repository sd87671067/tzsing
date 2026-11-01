package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestIPinfoCacheBudgetAndCredentialIsolation(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-credential" || r.URL.RawQuery != "" {
			t.Error("credential transport")
		}
		json.NewEncoder(w).Encode(map[string]any{"ip": "8.8.8.8", "country": "US", "city": "Example", "org": "AS15169 Example"})
	}))
	defer srv.Close()
	m := &ipinfo{token: "fixture-credential", endpoint: srv.URL + "/", file: filepath.Join(t.TempDir(), "cache.json"), state: intelState{Entries: map[string]intelEntry{}}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := model.Exit{IPv4: "8.8.8.8", Verified: true}
			m.enrich(context.Background(), srv.Client(), v.IPv4, &v)
			if v.ASN != "AS15169" || v.GeoSource == "" || v.RiskScore != nil || v.Datacenter != nil {
				t.Error("missing or fabricated metadata", v)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("shared IP was charged repeatedly", calls.Load())
	}
	b, e := os.ReadFile(m.file)
	if e != nil || strings.Contains(string(b), m.token) {
		t.Fatal("credential in persisted metadata", e)
	}
	// Force stale cache, then exhaust persisted monthly budget.
	entry := m.state.Entries["8.8.8.8"]
	entry.At = time.Now().Add(-48 * time.Hour).Unix()
	m.state.Entries["8.8.8.8"] = entry
	m.state.Monthly = 8000
	m.next = time.Time{}
	v := model.Exit{}
	m.enrich(context.Background(), srv.Client(), "8.8.8.8", &v)
	if calls.Load() != 1 || v.ASN != "AS15169" || !v.MetadataCached {
		t.Fatal("quota/stale cache protection failed")
	}
}

func TestIPinfoFailuresRetainCacheAndBackOff(t *testing.T) {
	status := 429
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == 200 {
			json.NewEncoder(w).Encode(map[string]string{"ip": "1.1.1.1", "country": "AU"})
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	old := model.Exit{ASN: "AS15169", GeoSource: "IPinfo"}
	m := &ipinfo{token: "fixture", endpoint: srv.URL + "/", state: intelState{Entries: map[string]intelEntry{"8.8.8.8": {At: time.Now().Add(-48 * time.Hour).Unix(), Value: old}}}}
	v := model.Exit{}
	m.enrich(context.Background(), srv.Client(), "8.8.8.8", &v)
	if !v.MetadataCached || v.ASN != old.ASN || time.Until(m.next) < 23*time.Hour {
		t.Fatal("429 did not protect budget and last result")
	}
	status = 200
	m.next = time.Time{}
	v = model.Exit{}
	m.enrich(context.Background(), srv.Client(), "8.8.8.8", &v)
	if v.ASN != old.ASN || m.failures != 2 {
		t.Fatal("mismatched IP accepted")
	}
}
