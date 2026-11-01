package egress

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReadonlyActualOutboundIPs(t *testing.T) {
	dir := os.Getenv("TZSING_PROBE_STAGE")
	if dir == "" {
		t.Skip("explicit read-only stage required")
	}
	b, e := os.ReadFile(filepath.Join(dir, "outbounds.json"))
	if e != nil {
		t.Fatal(e)
	}
	var inv struct {
		Hash     string `json:"config_hash"`
		Verified bool   `json:"routes_verified"`
	}
	if e = json.Unmarshal(b, &inv); e != nil || !inv.Verified {
		t.Fatal("unverified inventory", e)
	}
	ps, e := ReadPaths(filepath.Join(dir, "probe-paths.json"), inv.Hash)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for _, p := range ps {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := CheckPath(context.Background(), p)
			if r.Successes == 0 {
				t.Errorf("outbound=%s no successful HTTPS IP; ipv4=%s ipv6=%s", p.Tag, r.IPv4.Status, r.IPv6.Status)
				return
			}
			t.Logf("outbound=%s IPv4=%s IPv6=%s", p.Tag, r.IPv4.IP, r.IPv6.IP)
		}()
	}
	wg.Wait()
}
