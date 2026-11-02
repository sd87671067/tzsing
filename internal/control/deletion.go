package control

import (
	"fmt"
	"reflect"
	"strings"
	"tzsingbox/internal/model"
)

// Deletion resolves the real protocol identity independently of the VLESS-only
// route editor and credential exporter. No credentials are accepted from the UI.
func deletionUser(in map[string]any, id string) (map[string]any, error) {
	switch text(in["type"]) {
	case "vless", "vmess", "shadowsocks", "trojan", "socks", "http", "mixed", "hysteria", "hysteria2", "tuic", "anytls":
	default:
		return nil, fmt.Errorf("系统保留或不支持安全删除的入站协议：%s", text(in["type"]))
	}
	if id == "" {
		return nil, nil
	}
	if !model.ValidAuthID(id) {
		return nil, ErrScope
	}
	var selected map[string]any
	for _, v := range array(in["users"]) {
		u := object(v)
		match := userName(u) != "" && model.AuthID(userName(u)) == id
		if text(in["type"]) == "vless" {
			match = match || uuid(text(u["uuid"])) && model.UUIDAuthID(text(u["uuid"])) == id
		}
		if match {
			if selected != nil {
				return nil, fmt.Errorf("目标认证身份不唯一；未删除")
			}
			selected = u
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("目标认证身份已变化或不存在；未删除")
	}
	return selected, nil
}
func userName(u map[string]any) string {
	if n := text(u["name"]); n != "" {
		return n
	}
	return text(u["username"])
}
func containsString(v any, want string) bool {
	if s, ok := v.(string); ok {
		return want != "" && s == want
	}
	for _, x := range array(v) {
		if text(x) == want && want != "" {
			return true
		}
	}
	return false
}
func onlyString(v any, want string) bool {
	return want != "" && (text(v) == want || len(array(v)) == 1 && text(array(v)[0]) == want)
}

// Walk references with paths so unsupported/externally edited ownership is
// explained without exporting credentials or overwriting another writer.
func deletionRefs(v any, field, want, path string) []string {
	refs := []string{}
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == field && containsString(v, want) {
				refs = append(refs, path+"/"+k)
			}
			refs = append(refs, deletionRefs(v, field, want, path+"/"+k)...)
		}
	case []any:
		for i, v := range x {
			refs = append(refs, deletionRefs(v, field, want, fmt.Sprintf("%s/%d", path, i))...)
		}
	}
	return refs
}

// DeleteInbound produces one candidate. Snapshot additions are undone only in
// memory, never restored into production as an intermediate activation.
func DeleteInbound(raw []byte, tag, id string, journals map[string]Snapshot) ([]byte, error) {
	c := candidateMap(raw)
	in := findInbound(c, tag)
	if in == nil {
		return nil, fmt.Errorf("目标入站已不存在")
	}
	matches := 0
	for _, v := range array(c["inbounds"]) {
		if text(object(v)["tag"]) == tag {
			matches++
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("监听器标签不唯一，无法安全删除")
	}
	u, err := deletionUser(in, id)
	if err != nil {
		return nil, err
	}
	users := array(in["users"])
	if id == "" && len(users) > 0 {
		return nil, fmt.Errorf("此监听器包含认证用户，必须选择具体身份；共享监听器不可整组删除")
	}
	removeListener := id == "" || len(users) == 1
	if removeListener && text(in["type"]) == "vless" && len(users) > 0 {
		return nil, fmt.Errorf("共享 VLESS 监听器的最后一个 UUID 受保护；保留监听器及 REALITY 配置")
	}
	key := tag
	if id != "" {
		key = identityKey(tag, id)
	}
	name := userName(u)
	if name != "" {
		count := 0
		for _, v := range array(c["inbounds"]) {
			for _, q := range array(object(v)["users"]) {
				if userName(object(q)) == name {
					count++
				}
			}
		}
		if count != 1 {
			return nil, fmt.Errorf("认证名称跨用户重复，无法证明 auth_user 规则归属；未删除")
		}
	}
	owned := map[string]int{}
	s := journals[key]
	if s.Outbound == nil && findOutbound(c, managedTag(key)) != nil {
		return nil, fmt.Errorf("专属出站存在但缺少管理快照，无法证明归属；未删除")
	}
	if s.Outbound != nil {
		if !s.ExistingOutbound && text(s.Outbound["tag"]) != managedTag(key) {
			return nil, fmt.Errorf("管理快照的专属出站归属冲突；未删除")
		}
		target := in
		if id != "" {
			target = u
		}
		if digest(canonical(target)) != s.InboundHash {
			return nil, fmt.Errorf("目标身份与管理快照冲突；未删除")
		}
		if snapshotBaseline(c, s) != s.BaselineHash {
			return nil, fmt.Errorf("路由或出站与管理快照冲突；未删除")
		}
		for _, r := range s.Rules {
			owned[string(canonical(r))]++
		}
		if len(owned) == 0 {
			return nil, fmt.Errorf("管理快照缺少可证明归属的路由；未删除")
		}
		for k, n := range owned {
			count := 0
			for _, r := range array(object(c["route"])["rules"]) {
				if string(canonical(r)) == k {
					count++
				}
			}
			if count != n {
				return nil, fmt.Errorf("管理路由被外部修改或重复，无法证明归属；未删除")
			}
		}
		if !s.ExistingOutbound && !reflect.DeepEqual(findOutbound(c, text(s.Outbound["tag"])), s.Outbound) {
			return nil, fmt.Errorf("专属出站被外部修改；未删除")
		}
	}
	if d, ok := journals[key+":disabled"]; ok && d.BaselineHash != baselineHash(c) {
		return nil, fmt.Errorf("停用规则与管理快照冲突；未删除")
	}
	route := object(c["route"])
	kept := []any{}
	for i, v := range array(route["rules"]) {
		r := object(v)
		k := string(canonical(v))
		if owned[k] > 0 {
			owned[k]--
			continue
		}
		exclusive := r["invert"] != true && text(r["type"]) != "logical" && onlyString(r["inbound"], tag) && (removeListener || onlyString(r["auth_user"], name))
		if exclusive {
			continue
		}
		// Shared simple predicates survive unchanged. Complex target references need
		// explicit ownership; silently pruning a child could broaden a logical rule.
		if text(r["type"]) == "logical" && (len(deletionRefs(r, "auth_user", name, "")) > 0 || removeListener && len(deletionRefs(r, "inbound", tag, "")) > 0) || removeListener && len(deletionRefs(r, "inbound", tag, "")) > 0 {
			return nil, fmt.Errorf("route/rules/%d 引用目标，但无法证明为其独占规则；未删除", i)
		}
		kept = append(kept, v)
	}
	if _, ok := route["rules"]; ok {
		route["rules"] = kept
	}
	if removeListener {
		ins := []any{}
		for _, v := range array(c["inbounds"]) {
			if text(object(v)["tag"]) != tag {
				ins = append(ins, v)
			}
		}
		c["inbounds"] = ins
		for _, root := range []string{"route", "dns", "inbounds", "endpoints", "outbounds", "experimental"} {
			refs := deletionRefs(c[root], "inbound", tag, root)
			refs = append(refs, deletionRefs(c[root], "detour", tag, root)...)
			if len(refs) > 0 {
				return nil, fmt.Errorf("监听器仍被引用：%s；未删除", strings.Join(refs, "、"))
			}
		}
	} else {
		next := []any{}
		for _, v := range users {
			if !reflect.DeepEqual(v, u) {
				next = append(next, v)
			}
		}
		in["users"] = next
	}
	if s.Outbound != nil && !s.ExistingOutbound && len(outboundRefs(c, text(s.Outbound["tag"]))) == 0 {
		outs := []any{}
		for _, v := range array(c["outbounds"]) {
			if text(object(v)["tag"]) != text(s.Outbound["tag"]) {
				outs = append(outs, v)
			}
		}
		c["outbounds"] = outs
	}
	for _, root := range []string{"dns", "endpoints", "outbounds"} {
		if refs := deletionRefs(c[root], "auth_user", name, root); len(refs) > 0 {
			return nil, fmt.Errorf("目标认证仍有未归属引用：%s；未删除", strings.Join(refs, "、"))
		}
	}
	stats := object(object(object(c["experimental"])["v2ray_api"])["stats"])
	if name != "" {
		if _, ok := stats["users"]; ok {
			names := []any{}
			for _, v := range array(stats["users"]) {
				if text(v) != name {
					names = append(names, v)
				}
			}
			stats["users"] = names
		}
	}
	return canonical(c), nil
}
