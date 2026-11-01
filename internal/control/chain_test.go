package control

import (
	"reflect"
	"testing"
	"tzsingbox/internal/model"
)

func TestChainDependenciesDynamicAndCycles(t *testing.T) {
	out := func(kind, tag string) map[string]any {
		return map[string]any{"type": kind, "tag": tag, "server": "8.8.8.8", "server_port": 443}
	}
	a := out("vless", "exit")
	a["uuid"] = "11111111-1111-4111-8111-111111111111"
	a["detour"] = "hop"
	hop := out("http", "hop")
	hop["detour"] = "socks"
	socks := out("socks", "socks")
	sel := map[string]any{"type": "urltest", "tag": "choose", "outbounds": []any{"exit", "direct"}}
	direct := map[string]any{"type": "direct", "tag": "direct"}
	config := map[string]any{"outbounds": []any{a, hop, socks, sel, direct}}
	graph, e := probeGraph(config, sel, map[string]string{"choose": "exit"})
	if e != nil || len(graph) != 4 {
		t.Fatal(graph, e)
	}
	if text(object(graph[3])["default"]) != "exit" || text(object(graph[2])["tag"]) != "exit" {
		t.Fatal("egress replaced by transport hop")
	}
	if _, e = probeGraph(config, sel, nil); e == nil {
		t.Fatal("unknown choice guessed")
	}
	if _, e = probeGraph(config, sel, map[string]string{"choose": "other"}); e == nil {
		t.Fatal("unlisted choice")
	}
	socks["detour"] = "exit"
	if _, e = probeGraph(config, a, nil); e == nil {
		t.Fatal("cycle accepted")
	}
	delete(socks, "detour")
	hop["detour"] = "missing"
	if _, e = probeGraph(config, a, nil); e == nil {
		t.Fatal("missing hop")
	}
	hop["detour"] = "socks"
	socks["server"] = "127.0.0.1"
	if _, e = probeGraph(config, a, nil); e == nil {
		t.Fatal("private hop accepted")
	}
}
func TestChainBindingPreservesOtherUUID(t *testing.T) {
	c := candidateMap([]byte(`{"inbounds":[{"tag":"a","type":"vless"}],"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}`))
	in := findInbound(c, "a")
	in["type"] = "vless"
	in["users"] = []any{map[string]any{"name": "alice", "uuid": "11111111-1111-4111-8111-111111111111"}, map[string]any{"name": "bob", "uuid": "22222222-2222-4222-8222-222222222222"}}
	selector := map[string]any{"type": "selector", "tag": "choose", "outbounds": []any{"direct"}}
	c["outbounds"] = append(array(c["outbounds"]), selector)
	raw := canonical(c)
	next, s, e := changeIdentity(raw, "a", model.UUIDAuthID("11111111-1111-4111-8111-111111111111"), selector, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(candidateMap(next)["inbounds"], c["inbounds"]) || !reflect.DeepEqual(candidateMap(next)["outbounds"], c["outbounds"]) {
		t.Fatal("shared authentication or outbounds modified")
	}
	restored, e := RestoreIdentity(next, "a", model.UUIDAuthID("11111111-1111-4111-8111-111111111111"), s)
	if e != nil || !reflect.DeepEqual(canonicalJSON(restored), canonicalJSON(raw)) {
		t.Fatal("restore failed", e)
	}
	for _, v := range s.Rules {
		if definitelyExcludes(object(v), "a", "bob") == false && text(object(v)["type"]) != "logical" {
			t.Fatal("bob acquired alice route")
		}
	}
}
