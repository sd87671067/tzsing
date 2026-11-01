package adapter

import (
	"testing"
	"time"
	"tzsingbox/internal/model"
)

func TestRuleUUIDAttributionSharedListenerAndExit(t *testing.T) {
	a, b := model.UUIDAuthID("11111111-1111-4111-8111-111111111111"), model.UUIDAuthID("22222222-2222-4222-8222-222222222222")
	ruleA, ruleB := "inbound=shared auth_user=alice => route(direct)", "inbound=shared auth_user=bob => route(direct)"
	inv := &Inventory{ConfigHash: "one", Inbounds: []Inbound{{Tag: "shared", Type: "vless", AuthScheme: "uuid-v1", AuthIDs: []string{a, b}, AuthNames: map[string]string{a: "alice", b: "bob"}, RuleBindings: map[string]RuleBinding{model.AuthID(ruleA): {ID: a, Outbound: "direct"}, model.AuthID(ruleB): {ID: b, Outbound: "direct"}}}}}
	c := New("", "")
	c.SetInventory(inv)
	now := time.Now()
	mk := func(id, rule string, u, d int64) Connection {
		x := Connection{ID: id, Rule: rule, Upload: u, Download: d, Chains: []string{"direct"}}
		x.Metadata.Type = "vless/shared"
		return x
	}
	c.inboundTags(nil, &Snapshot{}, now)
	x, y := mk("a", ruleA, 100, 200), mk("b", ruleB, 300, 400)
	tags := c.inboundTags(nil, &Snapshot{Connections: []Connection{x, y, x}}, now.Add(time.Second))
	check := func(tags []model.Tag, id string, u, d int64, active int) {
		t.Helper()
		for _, tag := range tags {
			if tag.AuthID == id {
				if tag.Accounting != "rule_user_observed" || tag.Upload == nil || *tag.Upload != u || *tag.Download != d || *tag.Active != active {
					t.Fatalf("UUID attribution %s: %+v", id, tag)
				}
				return
			}
		}
		t.Fatal("missing UUID")
	}
	check(tags, a, 100, 200, 1)
	check(tags, b, 300, 400, 1)
	// Entire-rule comparison; substring, wrong chain and unauthenticated final
	// remain unassigned even when the destination and source are shared.
	wrong := mk("bad", ruleA+"x", 900, 800)
	wrong2 := mk("bad2", ruleA, 500, 500)
	wrong2.Chains = []string{"other"}
	x.Upload = 150
	y.Download = 450
	tags = c.inboundTags(nil, &Snapshot{Connections: []Connection{x, y, wrong, wrong2, mk("final", "final", 40, 50)}}, now.Add(2*time.Second))
	check(tags, a, 150, 200, 1)
	check(tags, b, 300, 450, 1)
	tags = c.inboundTags(nil, &Snapshot{}, now.Add(3*time.Second))
	check(tags, a, 150, 200, 0)
	check(tags, b, 300, 450, 0)
	for _, tag := range tags {
		if tag.AuthID != "" && (*tag.Up != 0 || *tag.Down != 0) {
			t.Fatal("idle nonzero")
		}
	}
	// Reusing an auth name for a new UUID cannot donate a known connection.
	c.inboundTags(nil, &Snapshot{Connections: []Connection{x}}, now.Add(4*time.Second))
	inv.Inbounds[0].RuleBindings[model.AuthID(ruleA)] = RuleBinding{ID: b, Outbound: "direct"}
	x.Upload += 100
	tags = c.inboundTags(nil, &Snapshot{Connections: []Connection{x}}, now.Add(5*time.Second))
	check(tags, b, 300, 450, 0)
}
