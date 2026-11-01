package adapter

import (
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestAuthenticationMappingNoDoubleCountingAndHotReload(t *testing.T) {
	c := New("", "")
	id := model.AuthID("alice")
	other := model.AuthID("bob")
	inv := &Inventory{Inbounds: []Inbound{{Tag: "a", Type: "vless", AuthIDs: []string{id, other}, AuthCount: 2}, {Tag: "b", Type: "vless"}, {Tag: "idle", Type: "trojan", Unknown: true}}}
	c.SetInventory(inv)
	now := time.Now()
	x := Connection{ID: "x", Upload: 100}
	x.Metadata.Type = "vless/a"
	x.Metadata.InboundUser = "alice"
	tags := c.inboundTags(nil, &Snapshot{Connections: []Connection{x}}, now)
	if len(tags) != 5 {
		t.Fatal("discovery", len(tags))
	}
	x.Upload = 150
	tags = c.inboundTags(nil, &Snapshot{Connections: []Connection{x, x}}, now.Add(time.Second))
	total := int64(0)
	for _, v := range tags {
		if v.Upload != nil {
			total += *v.Upload
		}
		if v.AuthID != "" && (v.Upload != nil || v.Up != nil || v.Active != nil) {
			t.Fatal("unattested API identity guessed")
		}
	}
	if total != 50 {
		t.Fatal("unattributed aggregate", total)
	}
	// Only a separately attested extension may enable identity attribution.
	inv.Inbounds[0].UserField = "inboundUser"
	x.Upload = 180
	tags = c.inboundTags(nil, &Snapshot{Connections: []Connection{x}}, now.Add(2*time.Second))
	total = 0
	for _, v := range tags {
		if v.Upload != nil {
			total += *v.Upload
		}
		if v.AuthID == id && *v.Upload != 30 {
			t.Fatal("reliable mapping", v)
		}
	}
	if total != 80 {
		t.Fatal("traffic counted twice", total)
	}
	x.Metadata.InboundUser = "not-configured"
	x.Upload = 200
	c.inboundTags(nil, &Snapshot{Connections: []Connection{x}}, now.Add(3*time.Second))
	x.Upload = 210
	tags = c.inboundTags(nil, &Snapshot{Connections: []Connection{x}}, now.Add(4*time.Second))
	for _, v := range tags {
		if v.Name == "inbound:a" && *v.Upload != 60 {
			t.Fatal("unknown user must remain unassigned", *v.Upload)
		}
	}
	before := model.IdentityName("a", id)
	inv.Inbounds[0].AuthIDs = append(inv.Inbounds[0].AuthIDs, model.AuthID("carol"))
	inv.Inbounds[0].AuthCount = 3
	c.SetInventory(inv)
	unavailable := c.UnavailableTags()
	if len(unavailable) != 6 {
		t.Fatal("hot reload/disconnected", len(unavailable))
	}
	found := false
	for _, v := range unavailable {
		found = found || v.Name == before
	}
	if !found {
		t.Fatal("stable identity lost")
	}
	d := c.Discovery(len(unavailable))
	if d.Inbounds != 3 || d.AuthIdentities != 3 || d.Discovered != 6 || d.Reported != 6 {
		t.Fatal(d)
	}
}
