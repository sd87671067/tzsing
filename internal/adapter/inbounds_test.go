package adapter

import (
	"testing"
	"time"
)

func TestInboundIdentityAndSharedOutboundCounters(t *testing.T) {
	c := New("", "")
	c.SetInventory(&Inventory{Inbounds: []Inbound{{Tag: "a", Type: "vless", Routes: []string{"direct"}}, {Tag: "b", Type: "vless", Routes: []string{"direct"}}}, Outbounds: []Outbound{{Tag: "direct", Type: "direct"}}})
	now := time.Now()
	first := Connection{ID: "one", Upload: 100, Download: 200}
	first.Metadata.Type = "vless/a"
	second := Connection{ID: "two", Upload: 10, Download: 20}
	second.Metadata.Type = "vless/b"
	c.inboundTags(nil, &Snapshot{Connections: []Connection{first, second}}, now)
	first.Upload += 30
	second.Upload += 7
	unknown := first
	unknown.ID = "no-inbound"
	unknown.Metadata.Type = "vless"
	unknown.Upload = 99999
	tags := c.inboundTags(nil, &Snapshot{Connections: []Connection{first, second, first, unknown}}, now.Add(time.Second))
	if len(tags) != 2 || tags[0].Name == tags[1].Name || tags[0].Egress != "direct" || tags[1].Egress != "direct" {
		t.Fatal("shared outbound merged inbounds", tags)
	}
	if *tags[0].Upload != 30 || *tags[1].Upload != 7 || *tags[0].Active != 1 || *tags[1].Active != 1 {
		t.Fatal("outbound/duplicate/unknown flow attributed to inbound")
	}
	if tags[0].Type != "vless" || tags[1].Type != "vless" || tags[0].EgressType != "direct" {
		t.Fatal("inbound protocol replaced by outbound", tags)
	}
	if !tags[0].DisplayEligible || !tags[1].DisplayEligible {
		t.Fatal("inbounds require independent cards")
	}
}
func TestRuntimeSelectorsAndAmbiguity(t *testing.T) {
	c := New("", "")
	c.SetInventory(&Inventory{Inbounds: []Inbound{{Tag: "a", Type: "vless", Routes: []string{"selector"}}}, Outbounds: []Outbound{{Tag: "selector", Type: "selector", Members: []string{"test"}}, {Tag: "test", Type: "urltest", Members: []string{"proxy"}}, {Tag: "proxy", Type: "socks", Detour: "direct"}, {Tag: "direct", Type: "direct"}}})
	api := map[string]Proxy{"selector": {Now: "test"}, "test": {Now: "proxy"}}
	if c.inboundTags(api, nil, time.Now())[0].Egress != "proxy" {
		t.Fatal("multi-stage resolution failed")
	}
	api["test"] = Proxy{Now: "other"}
	if c.inboundTags(api, nil, time.Now())[0].Egress != "" {
		t.Fatal("unconfigured choice guessed")
	}
	c.inventory.Inbounds[0].Routes = []string{"direct", "proxy"}
	if c.inboundTags(api, nil, time.Now())[0].Egress != "" {
		t.Fatal("conditional route guessed")
	}
	c.inventory.Inbounds[0].Routes = []string{"direct"}
	c.inventory.Inbounds[0].Unknown = true
	if c.inboundTags(api, nil, time.Now())[0].Egress != "" {
		t.Fatal("reject/unknown route ignored")
	}
	c.inventory.Inbounds[0].Unknown = false
	c.inventory.Outbounds[3].Detour = "direct"
	if c.inboundTags(api, nil, time.Now())[0].Egress != "" {
		t.Fatal("detour cycle accepted")
	}
}

func TestInboundWithoutTrafficOrResolvedRouteStillHasProtocol(t *testing.T) {
	c := New("", "")
	c.SetInventory(&Inventory{Inbounds: []Inbound{{Tag: "idle", Type: "trojan", Unknown: true}}})
	tags := c.inboundTags(nil, nil, time.Now())
	if len(tags) != 1 || tags[0].Type != "trojan" || !tags[0].DisplayEligible || tags[0].Egress != "" || tags[0].Category != "当前路径未知" {
		t.Fatal(tags)
	}
	if tags[0].Upload != nil || tags[0].Up != nil {
		t.Fatal("unobserved counters fabricated")
	}
}
