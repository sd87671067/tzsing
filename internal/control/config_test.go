package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScopedChangeRestoreKeepsAuthenticationAndSharedRoutes(t *testing.T) {
	raw := []byte(`{"inbounds":[{"type":"vless","tag":"a","users":[{"uuid":"11111111-1111-4111-8111-111111111111"}]},{"type":"vless","tag":"b"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","rules":[{"inbound":["a"],"auth_user":["denied"],"action":"reject"},{"inbound":["a","b"],"rule_set":["geo"],"outbound":"direct"},{"type":"logical","mode":"and","rules":[{"inbound":["a","b"]},{"domain":["example.org"]}],"outbound":"direct"}]}}`)
	link, _ := Parse("socks://u:synthetic-secret@example.com:1080")
	o, _ := link.Outbound(managedTag("a"))
	changed, s, e := Change(raw, "a", o, nil)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := Restore(changed, "a", s)
	if e != nil || string(canonical(canonicalJSON(restored))) != string(canonical(canonicalJSON(raw))) {
		t.Fatal("original rules not restored", e)
	}
	var base, next map[string]any
	json.Unmarshal(raw, &base)
	json.Unmarshal(changed, &next)
	if string(canonical(base["inbounds"])) != string(canonical(next["inbounds"])) {
		t.Fatal("inbound auth changed")
	}
	if !strings.Contains(string(canonical(next)), `"action":"reject"`) {
		t.Fatal("reject removed")
	}
	tampered := strings.Replace(string(changed), "synthetic-secret", "other", 1)
	if _, e = Restore([]byte(tampered), "a", s); e == nil {
		t.Fatal("overwrote external mutation")
	}
	second, ss, e := Change(changed, "b", map[string]any{"tag": managedTag("b"), "type": "direct"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	one, e := Restore(second, "a", s)
	if e != nil {
		t.Fatal(e)
	}
	zero, e := Restore(one, "b", ss)
	if e != nil || string(canonical(canonicalJSON(zero))) != string(canonical(canonicalJSON(raw))) {
		t.Fatal("independent restore changed another node", e)
	}
}
func TestMissingRouteAndRepeatedChange(t *testing.T) {
	raw := []byte(`{"inbounds":[{"type":"vless","tag":"a"}],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	o := map[string]any{"type": "direct", "tag": managedTag("a")}
	changed, s, e := Change(raw, "a", o, nil)
	if e != nil {
		t.Fatal(e)
	}
	changed, s, e = Change(changed, "a", o, &s)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := Restore(changed, "a", s)
	if e != nil || string(canonical(canonicalJSON(restored))) != string(canonical(canonicalJSON(raw))) {
		t.Fatal("original implicit route not restored", e)
	}
}
