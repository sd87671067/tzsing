package control

import (
	"reflect"
	"testing"
	"tzsingbox/internal/model"
)

func TestLiveIdentityOutboundReferences(t *testing.T) {
	const a = "11111111-1111-4111-8111-111111111111"
	const b = "22222222-2222-4222-8222-222222222222"
	config := candidateMap([]byte(`{"inbounds":[{"tag":"shared","type":"vless","listen_port":443,"users":[{"name":"alice","uuid":"` + a + `"},{"name":"bob","uuid":"` + b + `"}]}],"outbounds":[{"type":"socks","tag":"HK","detour":"JP"},{"type":"socks","tag":"JP"},{"type":"direct","tag":"Direct"},{"type":"selector","tag":"chain","outbounds":["HK","JP"]}],"route":{"rules":[{"inbound":["shared"],"auth_user":["bob"],"outbound":"JP"},{"inbound":["shared"],"auth_user":["alice"],"domain_suffix":["example.org"],"outbound":"HK"},{"type":"logical","mode":"and","rules":[{"inbound":["shared"]},{"auth_user":["alice"]}],"outbound":"chain"}],"final":"Direct"}}`))
	refs := outboundMappings(config)
	ka, kb := model.IdentityName("shared", model.UUIDAuthID(a)), model.IdentityName("shared", model.UUIDAuthID(b))
	if !reflect.DeepEqual(refs[ka], []string{"HK", "chain"}) || !reflect.DeepEqual(refs[kb], []string{"JP"}) {
		t.Fatal(refs)
	}
	// Display/auth-name changes do not alter UUID identity when real routes agree.
	in := findInbound(config, "shared")
	object(array(in["users"])[0])["name"] = "renamed"
	rules := array(object(config["route"])["rules"])
	object(rules[1])["auth_user"] = []any{"renamed"}
	object(array(object(rules[2])["rules"])[1])["auth_user"] = []any{"renamed"}
	if got := outboundMappings(config); !reflect.DeepEqual(got, refs) {
		t.Fatal("rename drift", got)
	}
	object(config["route"])["rules"] = []any{map[string]any{"auth_user": []any{"bob"}, "outbound": "JP"}}
	if got := outboundMappings(config)[ka]; !reflect.DeepEqual(got, []string{"Direct"}) {
		t.Fatal("direct fallback", got)
	}
	// Revocation is outside config: catalog calculation must be read-only, including shared references.
	before := canonical(config)
	outboundMappings(config)
	if !reflect.DeepEqual(before, canonical(config)) {
		t.Fatal("catalog mutated config")
	}
	if _, _, err := outboundCandidate(canonical(config), OutboundNodeRequest{Tag: "JP"}, "delete"); err == nil {
		t.Fatal("shared referenced outbound deleted")
	}
}
