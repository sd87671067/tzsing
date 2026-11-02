package control

import (
	"errors"
	"reflect"
)

func identityKey(tag, id string) string { return tag + "@" + id }
func identityUser(config map[string]any, tag, id string) (map[string]any, error) {
	in, e := IdentityInbound(findInbound(config, tag), id)
	if e != nil {
		return nil, e
	}
	user := object(array(in["users"])[0])
	name := text(user["name"])
	if name == "" || !uuid(text(user["uuid"])) {
		return nil, errors.New("当前身份缺少唯一认证名称或 UUID")
	}
	// auth_user routes use names; ambiguous names cannot isolate UUIDs.
	for _, v := range array(config["inbounds"]) {
		for _, u := range array(object(v)["users"]) {
			if text(object(u)["name"]) == name && text(object(u)["uuid"]) != text(user["uuid"]) {
				return nil, ErrScope
			}
		}
	}
	return user, nil
}

func ChangeIdentity(raw []byte, tag, id string, out map[string]any, prior *Snapshot) ([]byte, Snapshot, error) {
	return changeIdentity(raw, tag, id, out, prior, false)
}
func changeIdentity(raw []byte, tag, id string, out map[string]any, prior *Snapshot, existing bool) ([]byte, Snapshot, error) {
	if prior != nil {
		base, e := RestoreIdentity(raw, tag, id, *prior)
		if e != nil {
			return nil, Snapshot{}, e
		}
		raw = base
	}
	c := candidateMap(raw)
	u, e := identityUser(c, tag, id)
	if e != nil {
		return nil, Snapshot{}, e
	}
	key := identityKey(tag, id)
	name := managedTag(key)
	if existing {
		name = text(out["tag"])
	}
	if text(out["tag"]) != name {
		return nil, Snapshot{}, ErrScope
	}
	for _, v := range array(c["outbounds"]) {
		if !existing && text(object(v)["tag"]) == name {
			return nil, Snapshot{}, ErrScope
		}
	}
	_, rp := c["route"]
	route := object(c["route"])
	_, rsp := route["rules"]
	s := Snapshot{ExistingOutbound: existing, BaselineHash: baselineHash(c), InboundHash: digest(canonical(u)), RoutePresent: rp, RulesPresent: rsp, Outbound: out}
	guard := map[string]any{"inbound": []any{tag}, "auth_user": []any{text(u["name"])}}
	rules := []any{}
	for _, v := range array(route["rules"]) {
		r := object(v)
		if text(r["outbound"]) != "" && (text(r["action"]) == "" || text(r["action"]) == "route") && !definitelyExcludes(r, tag, text(u["name"])) {
			predicate := map[string]any{}
			for k, val := range r {
				if k != "outbound" && k != "action" {
					predicate[k] = val
				}
			}
			nr := map[string]any{"type": "logical", "mode": "and", "rules": []any{guard, predicate}, "action": "route", "outbound": name}
			if len(predicate) == 0 || (len(predicate) == 2 && string(canonical(predicate["inbound"])) == string(canonical([]string{tag})) && string(canonical(predicate["auth_user"])) == string(canonical([]string{text(u["name"])}))) {
				nr = map[string]any{"inbound": []any{tag}, "auth_user": []any{text(u["name"])}, "action": "route", "outbound": name}
			}
			rules = append(rules, nr)
			s.Rules = append(s.Rules, nr)
		}
		rules = append(rules, v)
	}
	fallback := map[string]any{"inbound": []any{tag}, "auth_user": []any{text(u["name"])}, "action": "route", "outbound": name}
	rules = append(rules, fallback)
	s.Rules = append(s.Rules, fallback)
	route["rules"] = rules
	c["route"] = route
	if !existing {
		c["outbounds"] = append(array(c["outbounds"]), out)
	}
	candidate := canonical(c)
	restored, e := RestoreIdentity(candidate, tag, id, s)
	if e != nil || !reflect.DeepEqual(canonicalJSON(raw), canonicalJSON(restored)) {
		return nil, Snapshot{}, ErrScope
	}
	return candidate, s, nil
}

func RestoreIdentity(raw []byte, tag, id string, s Snapshot) ([]byte, error) {
	c := candidateMap(raw)
	u, e := identityUser(c, tag, id)
	if e != nil || digest(canonical(u)) != s.InboundHash || snapshotBaseline(c, s) != s.BaselineHash {
		return nil, ErrScope
	}
	// Reuse exact-addition restoration with a synthetic inbound key. The actual
	// listener and every authentication entry are returned byte-for-byte in JSON.
	in := findInbound(c, tag)
	originalTag := in["tag"]
	in["tag"] = identityKey(tag, id)
	s.InboundHash = digest(canonical(in))
	// baseline excludes inbounds, so the temporary tag does not alter its hash.
	restored, e := Restore(canonical(c), identityKey(tag, id), s)
	if e != nil {
		return nil, e
	}
	c = candidateMap(restored)
	findInbound(c, identityKey(tag, id))["tag"] = originalTag
	return canonical(c), nil
}

// IdentityMutation preserves credentials and other UUIDs. Disabled identities
// remain in the inventory; a first-match reject denies their authenticated data.
func IdentityMutation(raw []byte, tag, id, action string) ([]byte, error) {
	c := candidateMap(raw)
	u, e := identityUser(c, tag, id)
	if e != nil {
		return nil, e
	}
	route := object(c["route"])
	rules := array(route["rules"])
	reject := map[string]any{"inbound": []any{tag}, "auth_user": []any{text(u["name"])}, "action": "reject", "method": "default"}
	kept := []any{}
	found := false
	for _, v := range rules {
		if reflect.DeepEqual(v, reject) {
			found = true
			continue
		}
		kept = append(kept, v)
	}
	switch action {
	case "disable":
		if !found {
			kept = append([]any{reject}, kept...)
		} else {
			return nil, errors.New("该身份已停用")
		}
	case "enable":
		if !found {
			return nil, errors.New("没有本系统管理的停用规则")
		}
	case "delete":
		return DeleteInbound(raw, tag, id, nil)
	default:
		return nil, ErrScope
	}
	route["rules"] = kept
	c["route"] = route
	return canonical(c), nil
}

func impact(config map[string]any, tag, id string) map[string]any {
	in := findInbound(config, tag)
	others := len(array(in["users"]))
	if id != "" {
		others--
	}
	if others < 0 {
		others = 0
	}
	listeners := []map[string]any{}
	total := 0
	for _, v := range array(config["inbounds"]) {
		i := object(v)
		n := len(array(i["users"]))
		total += n
		listeners = append(listeners, map[string]any{"tag": text(i["tag"]), "port": i["listen_port"], "users": n})
	}
	return map[string]any{"target": tag, "auth_id": id, "restart": true, "restart_scope": "整个 sing-box 实例", "shared_listener": in["listen_port"], "other_uuids": others, "instance_users": total, "listeners": listeners, "connections": "现有连接可能中断；无法可靠估计恢复时长"}
}

func identityDisabled(c map[string]any, tag, id string) bool {
	u, e := identityUser(c, tag, id)
	if e != nil {
		return false
	}
	for _, v := range array(object(c["route"])["rules"]) {
		r := object(v)
		if text(r["action"]) == "reject" && string(canonical(r["inbound"])) == string(canonical([]string{tag})) && string(canonical(r["auth_user"])) == string(canonical([]string{text(u["name"])})) {
			return true
		}
	}
	return false
}
