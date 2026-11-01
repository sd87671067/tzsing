package egress

import (
	"os"
	"path/filepath"
	"testing"
	"tzsingbox/internal/model"
)

func TestProbePathsBoundToConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "paths.json")
	os.WriteFile(p, []byte(`{"config_hash":"new","proxies":[{"tag":"relay","mode":"singbox_route","server":"127.0.0.1","port":1234}]}`), 0600)
	if _, e := ReadPaths(p, "old"); e == nil {
		t.Fatal("stale config proof accepted")
	}
	ps, e := ReadPaths(p, "new")
	if e != nil || len(ps) != 1 || ps[0].Tag != "relay" {
		t.Fatal(ps, e)
	}
	os.WriteFile(p, []byte(`{`), 0600)
	if _, e = ReadPaths(p, "new"); e == nil {
		t.Fatal("broken proof accepted")
	}
}

func TestAsyncIntelligenceCannotReattachAfterRouteOrIPChange(t *testing.T) {
	d := New()
	p := Proxy{Tag: "relay", Eligible: true, Mode: "singbox_route"}
	d.SetProxies([]Proxy{p})
	d.SetScope("one")
	base := model.Exit{Verified: true, IPv4: "8.8.8.8"}
	d.cache[p.Tag] = base
	d.applyIntel(p, "old", base, "ipinfo", model.Exit{Country: "wrong"})
	if d.Get(p.Tag).Country != "" {
		t.Fatal("old config metadata attached")
	}
	d.applyIntel(p, "one", model.Exit{IPv4: "1.1.1.1"}, "ipinfo", model.Exit{Country: "wrong"})
	if d.Get(p.Tag).Country != "" {
		t.Fatal("old IP metadata attached")
	}
	d.applyIntel(p, "one", base, "ipinfo", model.Exit{Country: "US", MetadataAt: 1})
	if d.Get(p.Tag).Country != "US" || d.Get(p.Tag).IPv4 != "8.8.8.8" {
		t.Fatal("metadata replaced actual IP")
	}
	d.SetProxies(nil)
	d.applyIntel(p, "one", base, "ippure", model.Exit{Country: "wrong"})
	if d.Get(p.Tag) != nil {
		t.Fatal("removed path restored")
	}
}
