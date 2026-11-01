package egress

import (
	"testing"
	"tzsingbox/internal/model"
)

func TestExitProofScopeAndProxyInvalidation(t *testing.T) {
	d := New()
	p := Proxy{Tag: "relay", Mode: "singbox_route", Server: "127.0.0.1", Port: 1234, Eligible: true}
	d.SetScope("config:choice1")
	d.SetProxies([]Proxy{p})
	d.cache[p.Tag] = model.Exit{Verified: true, IPv4: "8.8.8.8"}
	d.SetScope("config:choice1")
	if d.Get(p.Tag) == nil {
		t.Fatal("same proof discarded")
	}
	d.SetScope("config:choice2")
	if d.Get(p.Tag) != nil {
		t.Fatal("old selection proof retained")
	}
	d.cache[p.Tag] = model.Exit{Verified: true, IPv4: "8.8.8.8"}
	p.Port++
	d.SetProxies([]Proxy{p})
	if d.Get(p.Tag) != nil {
		t.Fatal("changed SOCKS endpoint retained proof")
	}
	d.cache[p.Tag] = model.Exit{Verified: true}
	d.SetProxies(nil)
	if d.Get(p.Tag) != nil {
		t.Fatal("withdrawn proof retained")
	}
	if _, _, err := PathClient(Proxy{Tag: "relay", Mode: "unknown"}); err == nil {
		t.Fatal("unproven relay fell back to default network")
	}
}
