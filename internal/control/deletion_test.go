package control

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
)

func deletionFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	raw, summary, e := UUIDCandidate(uuidFixture(), UUIDNodeRequest{Inbound: "shared", Name: "target", UUID: "22222222-2222-4222-8222-222222222222", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	return raw, text(summary["auth_id"])
}
func TestDeleteInboundProtocolIdentitiesAndListeners(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "trojan", "socks", "http", "mixed", "vmess", "hysteria2", "tuic", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			for _, listener := range []bool{false, true} {
				users := []any{map[string]any{"name": "alice", "password": "secret"}, map[string]any{"name": "bob", "password": "other"}}
				if protocol == "socks" || protocol == "http" || protocol == "mixed" {
					for _, u := range users {
						object(u)["username"] = object(u)["name"]
						delete(object(u), "name")
					}
				}
				in := map[string]any{"tag": "target", "type": protocol, "listen_port": 8388, "users": users}
				id := model.AuthID("alice")
				if listener {
					delete(in, "users")
					in["password"] = "secret"
					id = ""
				}
				c := map[string]any{"inbounds": []any{in, map[string]any{"tag": "peer", "type": "socks", "listen_port": 1080}}, "route": map[string]any{"final": "direct", "rules": []any{map[string]any{"inbound": []any{"target"}, "auth_user": []any{"alice"}, "action": "route", "outbound": "direct"}, map[string]any{"inbound": []any{"peer"}, "outbound": "direct"}}}, "outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}}}
				before := canonical(c)
				next, e := DeleteInbound(before, "target", id, nil)
				if e != nil {
					t.Fatal(e)
				}
				got := candidateMap(next)
				target := findInbound(got, "target")
				if listener {
					if target != nil {
						t.Fatal("listener survived")
					}
				} else if len(array(target["users"])) != 1 || userName(object(array(target["users"])[0])) != "bob" {
					t.Fatal("wrong user removed")
				}
				if len(array(object(got["route"])["rules"])) != 1 || !bytes.Equal(canonical(findInbound(got, "peer")), canonical(findInbound(c, "peer"))) || !reflect.DeepEqual(got["outbounds"], c["outbounds"]) {
					t.Fatal("peer/shared outbound changed")
				}
				if !bytes.Equal(canonical(c), before) {
					t.Fatal("mutated caller")
				}
			}
		})
	}
}
func TestDeleteInboundManagedBindingsAndSharedDependencies(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, shared := range []bool{false, true} {
			t.Run(map[bool]string{false: "owned", true: "existing"}[existing]+map[bool]string{false: "-private", true: "-shared"}[shared], func(t *testing.T) {
				raw, id := deletionFixture(t)
				config := candidateMap(raw)
				target := managedTag(identityKey("shared", id))
				out := map[string]any{"tag": target, "type": "direct"}
				if existing {
					target = "relay"
					out = findOutbound(config, target)
				}
				changed, s, e := changeIdentity(raw, "shared", id, out, nil, existing)
				if e != nil {
					t.Fatal(e)
				}
				config = candidateMap(changed)
				if shared {
					config["dns"] = map[string]any{"servers": []any{map[string]any{"tag": "dns", "detour": target}}}
					config["outbounds"] = append(array(config["outbounds"]), map[string]any{"tag": "selector", "type": "selector", "outbounds": []any{target}}, map[string]any{"tag": "chain", "type": "socks", "detour": target})
					object(config["route"])["rules"] = append(array(object(config["route"])["rules"]), map[string]any{"inbound": []any{"shared"}, "auth_user": []any{"existing"}, "action": "route", "outbound": target})
					// Emulate snapshots rebased by the controller after trusted peer changes.
					s.BaselineHash = snapshotBaseline(config, s)
				}
				before := canonical(config)
				next, e := DeleteInbound(before, "shared", id, map[string]Snapshot{identityKey("shared", id): s})
				if e != nil {
					t.Fatal(e)
				}
				got := candidateMap(next)
				if _, e = deletionUser(findInbound(got, "shared"), id); e == nil {
					t.Fatal("target survived")
				}
				if !reflect.DeepEqual(findInbound(got, "shared")["tls"], findInbound(config, "shared")["tls"]) || len(array(findInbound(got, "shared")["users"])) != 1 {
					t.Fatal("shared REALITY/users changed")
				}
				if (findOutbound(got, target) != nil) != (existing || shared) {
					t.Fatal("wrong shared ownership decision")
				}
				if !reflect.DeepEqual(got["dns"], config["dns"]) {
					t.Fatal("DNS changed")
				}
				for _, tag := range []string{"selector", "chain"} {
					if !reflect.DeepEqual(findOutbound(got, tag), findOutbound(config, tag)) {
						t.Fatal("chain changed")
					}
				}
			})
		}
	}
}
func TestDeleteInboundConflictsAndReservedNodes(t *testing.T) {
	raw, id := deletionFixture(t)
	out := map[string]any{"tag": managedTag(identityKey("shared", id)), "type": "direct"}
	changed, s, e := ChangeIdentity(raw, "shared", id, out, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"missing-rule", "duplicate-rule", "edited-rule", "edited-outbound", "edited-user", "missing-snapshot", "disabled-snapshot", "logical-reference"} {
		t.Run(kind, func(t *testing.T) {
			config := candidateMap(changed)
			j := map[string]Snapshot{identityKey("shared", id): s}
			route := object(config["route"])
			rules := array(route["rules"])
			switch kind {
			case "missing-rule":
				route["rules"] = rules[:len(rules)-1]
			case "duplicate-rule":
				route["rules"] = append(rules, rules[len(rules)-1])
			case "edited-rule":
				object(rules[len(rules)-1])["domain_suffix"] = []any{"external.example"}
			case "edited-outbound":
				findOutbound(config, text(out["tag"]))["inet4_bind_address"] = "127.0.0.2"
			case "edited-user":
				object(array(findInbound(config, "shared")["users"])[1])["name"] = "external"
			case "missing-snapshot":
				delete(j, identityKey("shared", id))
			case "disabled-snapshot":
				j[identityKey("shared", id)+":disabled"] = Snapshot{BaselineHash: "external"}
			case "logical-reference":
				route["rules"] = append(rules, map[string]any{"type": "logical", "mode": "or", "rules": []any{map[string]any{"auth_user": []any{userName(object(array(findInbound(config, "shared")["users"])[1]))}}}, "outbound": text(out["tag"])})
			}
			if _, e := DeleteInbound(canonical(config), "shared", id, j); e == nil {
				t.Fatal("unsafe deletion accepted")
			}
		})
	}
	if _, e = DeleteInbound(uuidFixture(), "shared", model.UUIDAuthID("11111111-1111-4111-8111-111111111111"), nil); e == nil || !strings.Contains(e.Error(), "最后一个") {
		t.Fatal("last UUID unprotected", e)
	}
	for _, typ := range []string{"tun", "tproxy", "redirect"} {
		if _, e = DeleteInbound(canonical(map[string]any{"inbounds": []any{map[string]any{"tag": "system", "type": typ}}}), "system", "", nil); e == nil {
			t.Fatal("reserved listener deleted")
		}
	}
	listener := map[string]any{"tag": "ss", "type": "shadowsocks"}
	for _, root := range []string{"inbounds", "dns", "endpoints", "outbounds"} {
		config := map[string]any{"inbounds": []any{listener}, root: []any{map[string]any{"tag": "other", "detour": "ss"}}}
		if root == "inbounds" {
			config[root] = []any{listener, map[string]any{"tag": "other", "detour": "ss"}}
		}
		if _, e = DeleteInbound(canonical(config), "ss", "", nil); e == nil {
			t.Fatal("listener reference removed", root)
		}
	}
}
func TestDeleteInboundTransactionCASExpiryRollbackAndReadback(t *testing.T) {
	for _, scenario := range []string{"success", "check", "stale", "expired", "restart", "health", "journal"} {
		t.Run(scenario, func(t *testing.T) {
			raw, id := deletionFixture(t)
			changed, s, e := ChangeIdentity(raw, "shared", id, map[string]any{"tag": managedTag(identityKey("shared", id)), "type": "direct"}, nil)
			if e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			os.WriteFile(path, changed, 0600)
			key := identityKey("shared", id)
			journals := map[string]Snapshot{key: s, "peer:disabled": {BaselineHash: "preserve"}}
			journalPath := filepath.Join(dir, "snapshots.json")
			os.WriteFile(journalPath, canonical(journals), 0600)
			activations := 0
			failCheck := false
			c := &Controller{Config: ServiceConfig{Config: path, State: dir, WriteEnabled: true}, Hooks: &ApplyHooks{Check: func([]byte) error {
				if failCheck {
					return errors.New("candidate invalid")
				}
				return nil
			}, Activate: func() error {
				activations++
				if scenario == "restart" && activations == 1 {
					return errors.New("restart failed")
				}
				return nil
			}, Healthy: func(map[string]any) error {
				if scenario == "health" && activations == 1 {
					return errors.New("unhealthy")
				}
				return nil
			}}}
			call := func(path string, v any) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				c.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(canonical(v))))
				return w
			}
			w := call("/preview", map[string]any{"tag": "shared", "auth_id": id, "action": "delete"})
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			token := text(candidateMap(w.Body.Bytes())["plan"])
			if scenario == "expired" {
				p := c.plans[auth.Digest(token)]
				p.Expires = time.Now().Add(-time.Second)
				c.plans[auth.Digest(token)] = p
			}
			expected := changed
			expectedJ := canonical(journals)
			if scenario == "stale" {
				expected = append(changed, ' ')
				os.WriteFile(path, expected, 0600)
			}
			if scenario == "journal" {
				journals["external"] = Snapshot{BaselineHash: "new"}
				expectedJ = canonical(journals)
				os.WriteFile(journalPath, expectedJ, 0600)
			}
			if scenario == "check" {
				failCheck = true
			}
			w = call("/apply", map[string]any{"tag": "shared", "auth_id": id, "plan": token})
			after, _ := os.ReadFile(path)
			afterJ, _ := os.ReadFile(journalPath)
			if scenario == "success" {
				if w.Code != 200 || activations != 1 {
					t.Fatal("delete must apply exactly once", w.Code, activations, w.Body.String())
				}
				if _, e := deletionUser(findInbound(candidateMap(after), "shared"), id); e == nil {
					t.Fatal("readback target survived")
				}
				j, _ := c.journals()
				if _, ok := j[key]; ok || !reflect.DeepEqual(j["peer:disabled"], journals["peer:disabled"]) {
					t.Fatal("snapshot cleanup", j)
				}
			} else {
				if w.Code != 409 || !bytes.Equal(after, expected) || !bytes.Equal(afterJ, expectedJ) {
					t.Fatal("unsafe rollback", w.Code, w.Body.String())
				}
				if (scenario == "restart" || scenario == "health") && activations != 2 {
					t.Fatal("rollback not activated")
				}
			}
			if w = call("/apply", map[string]any{"tag": "shared", "auth_id": id, "plan": token}); w.Code != 409 && w.Code != 403 {
				t.Fatal("replay accepted")
			}
		})
	}
}
func TestDeleteUnreferencedMultiProtocolOutbounds(t *testing.T) {
	for _, typ := range []string{"shadowsocks", "trojan", "vless", "socks", "http", "direct"} {
		raw := canonical(map[string]any{"outbounds": []any{map[string]any{"tag": "target", "type": typ}, map[string]any{"tag": "peer", "type": "direct"}}})
		next, _, e := outboundCandidate(raw, OutboundNodeRequest{Tag: "target"}, "delete")
		if e != nil || findOutbound(candidateMap(next), "target") != nil || findOutbound(candidateMap(next), "peer") == nil {
			t.Fatal(typ, e)
		}
	}
}

func TestDeleteInboundDisabledSnapshotStatsAndPeerRestoration(t *testing.T) {
	raw, id := deletionFixture(t)
	config := candidateMap(raw)
	config["experimental"] = map[string]any{"v2ray_api": map[string]any{"stats": map[string]any{"enabled": true, "users": []any{"existing", userName(object(array(findInbound(config, "shared")["users"])[1]))}}}}
	raw = canonical(config)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, raw, 0600)
	c := &Controller{Config: ServiceConfig{Config: path, State: dir}, Hooks: &ApplyHooks{Check: func([]byte) error { return nil }, Activate: func() error { return nil }, Healthy: func(map[string]any) error { return nil }, Probe: func(map[string]any) error { return nil }}}
	peerID := model.UUIDAuthID("11111111-1111-4111-8111-111111111111")
	for _, who := range []string{id, peerID} {
		before, _ := os.ReadFile(path)
		out := findOutbound(candidateMap(before), "relay")
		changed, s, e := changeIdentity(before, "shared", who, out, nil, true)
		if e != nil {
			t.Fatal(e)
		}
		if e = c.apply(plan{Hash: digest(before), Tag: "shared", AuthID: who, Candidate: changed, Snapshot: s}); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := os.ReadFile(path)
	disabled, e := IdentityMutation(before, "shared", id, "disable")
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(before), Tag: "shared", AuthID: id, Action: "disable", Candidate: disabled}); e != nil {
		t.Fatal(e)
	}
	journals, _ := c.journals()
	targetKey := identityKey("shared", id)
	if _, ok := journals[targetKey+":disabled"]; !ok {
		t.Fatal("disabled snapshot missing")
	}
	candidate, e := DeleteInbound(disabled, "shared", id, journals)
	if e != nil {
		t.Fatal(e)
	}
	auditBefore, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if e = c.apply(plan{Hash: digest(disabled), Tag: "shared", AuthID: id, Action: "delete", Candidate: candidate, JournalHash: digest(canonical(journals))}); e != nil {
		t.Fatal(e)
	}
	actual, _ := os.ReadFile(path)
	stats := object(object(object(candidateMap(actual)["experimental"])["v2ray_api"])["stats"])
	if !reflect.DeepEqual(stats["users"], []any{"existing"}) {
		t.Fatal("metering names not scoped", stats)
	}
	journals, _ = c.journals()
	for _, key := range []string{targetKey, targetKey + ":disabled"} {
		if _, ok := journals[key]; ok {
			t.Fatal("stale snapshot", key)
		}
	}
	peerSnapshot, ok := journals[identityKey("shared", peerID)]
	if !ok {
		t.Fatal("peer snapshot deleted")
	}
	restored, e := RestoreIdentity(actual, "shared", peerID, peerSnapshot)
	if e != nil {
		t.Fatal("peer cannot restore after target deletion", e)
	}
	if e = c.apply(plan{Hash: digest(actual), Tag: "shared", AuthID: peerID, Restore: true, Candidate: restored}); e != nil {
		t.Fatal(e)
	}
	auditAfter, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if !bytes.HasPrefix(auditAfter, auditBefore) {
		t.Fatal("audit history removed")
	}
}
