package adapter

import (
	"encoding/json"
	"os"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

// No traffic generation, config write, connection close, signals or resets.
func TestReadOnlyFourteenProductionUUIDMappings(t *testing.T) {
	if os.Getenv("TZSING_READONLY_UUID_LIVE") != "1" {
		t.Skip("explicit readonly opt-in")
	}
	b, e := os.ReadFile("/etc/tzsingbox/agent.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg struct {
		URL    string `json:"clash_url"`
		Secret string `json:"clash_secret"`
	}
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	inv, e := ReadInventory(os.Getenv("TZSING_READONLY_INVENTORY"))
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, in := range inv.Inbounds {
		for _, id := range in.AuthIDs {
			count++
			matched := false
			for _, binding := range in.RuleBindings {
				matched = matched || binding.ID == id
			}
			if !matched || in.AuthNames[id] == "" {
				t.Fatal("identity lacks proven binding or name")
			}
		}
	}
	if count != 14 {
		t.Fatal("expected 14 UUIDs", count)
	}
	c := New(cfg.URL, cfg.Secret)
	c.SetInventory(inv)
	var a, z Snapshot
	if e = c.get("/connections", &a); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	c.inboundTags(nil, &a, now)
	time.Sleep(2 * time.Second)
	if e = c.get("/connections", &z); e != nil {
		t.Fatal(e)
	}
	tags := c.inboundTags(nil, &z, now.Add(2*time.Second))
	expected := map[string]countValue{}
	previous := map[string]Connection{}
	for _, x := range a.Connections {
		previous[x.ID] = x
	}
	mapped, unmapped := 0, 0
	for _, x := range z.Connections {
		id := ""
		for _, in := range inv.Inbounds {
			if x.Metadata.Type != in.Type+"/"+in.Tag {
				continue
			}
			for rule, binding := range in.RuleBindings {
				if model.AuthID(x.Rule) == rule {
					has := false
					for _, chain := range x.Chains {
						has = has || chain == binding.Outbound
					}
					if has {
						id = binding.ID
					}
				}
			}
		}
		if id == "" {
			unmapped++
			continue
		}
		mapped++
		du, dd := x.Upload, x.Download
		if old, ok := previous[x.ID]; ok {
			du = max(0, x.Upload-old.Upload)
			dd = max(0, x.Download-old.Download)
		}
		v := expected[id]
		v.u += du
		v.d += dd
		v.active++
		expected[id] = v
	}
	found := 0
	for _, tag := range tags {
		if tag.AuthID == "" {
			continue
		}
		found++
		want := expected[tag.AuthID]
		if tag.Accounting != "rule_user_observed" || tag.Upload == nil || *tag.Upload != want.u || *tag.Download != want.d || *tag.Active != want.active {
			t.Fatal("readonly UUID totals mismatch")
		}
	}
	if found != 14 {
		t.Fatal("UUID cards lost", found)
	}
	t.Logf("14 UUID bindings ready; real snapshot %d authenticated connections mapped, %d explicitly unattributed; independent bidirectional sums match", mapped, unmapped)
}

type countValue struct {
	u, d   int64
	active int
}
