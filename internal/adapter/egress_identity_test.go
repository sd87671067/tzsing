package adapter

import (
	"encoding/json"
	"os"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestUUIDEgressConnectionsMultipleIdleAndSwitch(t *testing.T) {
	a, b := model.UUIDAuthID("11111111-1111-4111-8111-111111111111"), model.UUIDAuthID("22222222-2222-4222-8222-222222222222")
	inv := &Inventory{ConfigHash: "one", RoutesVerified: true, Outbounds: []Outbound{{Tag: "direct", Type: "direct"}, {Tag: "relay", Type: "socks", Detour: "direct"}, {Tag: "choose", Type: "selector", Members: []string{"direct", "relay"}}}, Inbounds: []Inbound{{Tag: "shared", Type: "vless", Unknown: true, AuthScheme: "uuid-v1", UserField: "inboundUser", AuthIDs: []string{a, b}, LegacyAuthIDs: map[string]string{a: model.AuthID("alice"), b: model.AuthID("bob")}}}}
	c := New("", "")
	c.SetInventory(inv)
	api := map[string]Proxy{"choose": {Now: "direct"}}
	now := time.Now()
	c.inboundTags(api, &Snapshot{}, now)
	mk := func(id, user string, chain []string, u int64) Connection {
		x := Connection{ID: id, Chains: chain, Upload: u, Download: u * 2}
		x.Metadata.Type = "vless/shared"
		x.Metadata.InboundUser = user
		return x
	}
	x := mk("a1", "alice", []string{"direct", "choose"}, 100)
	y := mk("b1", "bob", []string{"direct", "choose"}, 300)
	find := func(ts []model.Tag, id string) model.Tag {
		for _, v := range ts {
			if v.AuthID == id {
				return v
			}
		}
		t.Fatal("missing UUID")
		return model.Tag{}
	}
	tags := c.inboundTags(api, &Snapshot{Connections: []Connection{x, y}}, now.Add(time.Second))
	ta, tb := find(tags, a), find(tags, b)
	if ta.Egress != "direct" || tb.Egress != "direct" || *ta.Upload != 100 || *tb.Upload != 300 || *ta.Active != 1 || *tb.Active != 1 {
		t.Fatal("shared exit broke identity", ta, tb)
	}
	z := mk("a2", "alice", []string{"relay"}, 50)
	tags = c.inboundTags(api, &Snapshot{Connections: []Connection{x, y, z}}, now.Add(2*time.Second))
	ta = find(tags, a)
	if len(ta.Egresses) != 2 || ta.Egress != "" || ta.Category != "多个出口" || *ta.Upload != 150 || *ta.Active != 2 {
		t.Fatal("multi exit collapsed or traffic changed", ta)
	}
	tags = c.inboundTags(api, &Snapshot{}, now.Add(3*time.Second))
	ta = find(tags, a)
	if len(ta.Egresses) != 2 || *ta.Active != 0 || *ta.Up != 0 || *ta.Upload != 150 {
		t.Fatal("idle lost recent real paths", ta)
	}
	version := ta.RouteVersion
	api["choose"] = Proxy{Now: "relay"}
	tags = c.inboundTags(api, &Snapshot{}, now.Add(4*time.Second))
	ta = find(tags, a)
	if ta.RouteVersion == version || len(ta.Egresses) != 0 || ta.Category != "路径待检测" {
		t.Fatal("selector cache survived switch", ta)
	}
	// Existing connections retain their actual old exit after the selector moves.
	tags = c.inboundTags(api, &Snapshot{Connections: []Connection{x}}, now.Add(5*time.Second))
	ta = find(tags, a)
	if ta.Egress != "direct" {
		t.Fatal("runtime choice replaced actual connection path", ta)
	}
	inv.ConfigHash = "two"
	tags = c.inboundTags(api, &Snapshot{}, now.Add(6*time.Second))
	ta = find(tags, a)
	if len(ta.Egresses) != 0 {
		t.Fatal("config edit kept old identity paths")
	}
	// Unknown/blocked chains never inherit an idle path for an active connection.
	x.Chains = []string{"missing"}
	tags = c.inboundTags(api, &Snapshot{Connections: []Connection{x}}, now.Add(7*time.Second))
	ta = find(tags, a)
	if len(ta.Egresses) != 0 || ta.Egress != "" {
		t.Fatal("unknown chain guessed", ta)
	}
}

func TestUUIDIdleExactRuleResolvesURLTest(t *testing.T) {
	id := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	inv := &Inventory{ConfigHash: "one", RoutesVerified: true, Outbounds: []Outbound{{Tag: "direct", Type: "direct"}, {Tag: "relay", Type: "socks"}, {Tag: "auto", Type: "urltest", Members: []string{"direct", "relay"}}}, Inbounds: []Inbound{{Tag: "shared", Type: "vless", Unknown: true, AuthIDs: []string{id}, RuleBindings: map[string]RuleBinding{"rule": {ID: id, Outbound: "auto"}}}}}
	c := New("", "")
	c.SetInventory(inv)
	for _, choice := range []string{"relay", "direct", "missing"} {
		tags := c.inboundTags(map[string]Proxy{"auto": {Now: choice}}, &Snapshot{}, time.Now())
		for _, v := range tags {
			if v.AuthID == id {
				if choice == "missing" {
					if len(v.Egresses) != 0 {
						t.Fatal("invalid member accepted")
					}
				} else if v.Egress != choice {
					t.Fatal("exact rule did not resolve", v)
				}
			}
		}
	}
}

func TestReadOnlyUUIDActualPaths(t *testing.T) {
	if os.Getenv("TZSING_EGRESS_READONLY") != "1" {
		t.Skip("explicit read-only opt-in")
	}
	b, e := os.ReadFile("/etc/tzsingbox/agent.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg struct {
		URL       string `json:"clash_url"`
		Secret    string `json:"clash_secret"`
		Inventory string `json:"inventory_file"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		t.Fatal("invalid agent config")
	}
	inv, e := ReadInventory(cfg.Inventory)
	if e != nil {
		t.Fatal(e)
	}
	c := New(cfg.URL, cfg.Secret)
	c.SetInventory(inv)
	tags, e := c.Collect()
	if e != nil {
		t.Fatal(e)
	}
	active, mapped, idle, detected := 0, 0, 0, 0
	for _, tag := range tags {
		if tag.AuthID == "" {
			continue
		}
		detected++
		if tag.Active != nil && *tag.Active > 0 {
			active++
			if len(tag.Egresses) == 0 {
				t.Fatal("active authenticated UUID lost actual path")
			}
			mapped++
		} else {
			idle++
		}
	}
	if detected != 14 {
		t.Fatalf("UUID inventory changed: %d", detected)
	}
	t.Logf("UUIDs=%d active=%d mapped=%d idle=%d; only read-only Clash GET requests", detected, active, mapped, idle)
}
