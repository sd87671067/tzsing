package egress

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Opt-in small HTTPS probes through existing, attested SOCKS mappings only.
// No sing-box config edits, signals, resets or listener changes.
func TestReadOnlyExistingDirectAndRelayProbes(t *testing.T) {
	if os.Getenv("TZSING_EGRESS_READONLY") != "1" {
		t.Skip("explicit opt-in")
	}
	b, e := os.ReadFile("/etc/tzsingbox/agent.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg struct {
		Proxies []Proxy `json:"proxies"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		t.Fatal("invalid agent config")
	}
	relay := os.Getenv("TZSING_EGRESS_RELAY")
	if relay == "" {
		t.Fatal("explicit relay tag required")
	}
	for _, tag := range []string{"direct", relay} {
		label := "relay"
		if tag == "direct" {
			label = "direct"
		}
		t.Run(label, func(t *testing.T) {
			found := false
			for _, p := range cfg.Proxies {
				if p.Tag != tag {
					continue
				}
				found = true
				if !p.Eligible || p.Mode != "singbox_route" || p.Server != "127.0.0.1" {
					t.Fatal("no attested loopback probe")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
				defer cancel()
				v := detect(ctx, p)
				if !v.Verified || v.Updated == 0 || (v.IPv4 == "" && v.IPv6 == "") {
					t.Fatal("specified outbound HTTPS proof failed")
				}
				t.Logf("specified SOCKS path HTTPS proof: IPv4=%t IPv6=%t", v.IPv4 != "", v.IPv6 != "")
			}
			if !found {
				t.Fatal("required existing probe unavailable")
			}
		})
	}
}
