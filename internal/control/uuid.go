package control

import (
	"crypto/rand"
	"fmt"
	"strings"
	"tzsingbox/internal/model"
)

// UUIDCandidate never edits a file or starts a process. Production activation
// deliberately has no API until interruption and external-writer gates are met.
type UUIDNodeRequest struct {
	Inbound        string `json:"inbound"`
	Name           string `json:"name"`
	UUID           string `json:"uuid,omitempty"`
	Outbound       string `json:"outbound,omitempty"`
	Quota          int64  `json:"quota"`
	UploadLimit    int64  `json:"upload_limit"`
	DownloadLimit  int64  `json:"download_limit"`
	ExpiresAt      int64  `json:"expires_at"`
	MaxConnections int    `json:"max_connections"`
	Enabled        bool   `json:"enabled"`
}

func NewUUID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func realityInbound(in map[string]any) bool {
	return text(in["type"]) == "vless" && object(in["tls"])["enabled"] == true && object(object(in["tls"])["reality"])["enabled"] == true && len(object(in["transport"])) == 0
}

// UUIDCapabilities describes executors, not editable monitoring reminders.
// No production setter exists for these fields; saving metadata cannot apply them.
func UUIDCapabilities() map[string]any {
	capabilities := map[string]any{}
	for _, v := range []struct{ key, unit, state, reason string }{
		{"quota", "GiB", "unsupported", "缺少持久、完整的 UUID 计量和超额封禁执行器；现有额度仅作提醒。0 表示不限额。"},
		{"upload_limit", "MiB/s", "unsupported", "sing-box 1.13.15 VLESS 没有逐用户上传限速；认证后的数据路径执行器尚未接入。0 表示不限速。"},
		{"download_limit", "MiB/s", "unsupported", "sing-box 1.13.15 VLESS 没有逐用户下载限速；认证后的数据路径执行器尚未接入。0 表示不限速。"},
		{"expires_at", "本地时间", "disabled", "到期认证停用执行器未接入；生产配置重载可能断流，存在外部写入冲突。当前仅有到期提醒。"},
		{"max_connections", "连接数", "unsupported", "没有认证后逐 UUID 的连接准入执行器；原生用户流量计数不提供并发连接数。0 表示不限，不代表设备数。"},
		{"enabled", "", "disabled", "生产逐 UUID 启停关闭；清单中存在不代表当前有连接或可通过所有路由策略。"},
		{"outbound", "", "disabled", "允许校验原路由、直连和中转候选；生产逐 UUID 路由写入关闭。"},
	} {
		capabilities[v.key] = map[string]any{"state": v.state, "saved": false, "effective": false, "unit": v.unit, "reason": v.reason}
	}
	return capabilities
}

func UUIDCatalog(raw []byte) map[string]any {
	config := candidateMap(raw)
	ins := []any{}
	outs := []any{}
	for _, v := range array(config["inbounds"]) {
		in := object(v)
		if !realityInbound(in) {
			continue
		}
		tls := object(in["tls"])
		reality := object(tls["reality"])
		ins = append(ins, map[string]any{"tag": text(in["tag"]), "port": in["listen_port"], "users": len(array(in["users"])), "sni": text(tls["server_name"]), "handshake_server": text(object(reality["handshake"])["server"]), "sni_shared": true})
	}
	for _, v := range array(config["outbounds"]) {
		o := object(v)
		kind, _ := model.OutboundType(text(o["type"]))
		if kind == "actual" {
			outs = append(outs, map[string]string{"tag": text(o["tag"]), "type": text(o["type"])})
		}
	}
	return map[string]any{"inbounds": ins, "outbounds": outs, "capabilities": UUIDCapabilities(), "apply": false, "bandwidth": false, "devices": false, "quota_enforced": false, "expiry_enforced": false, "reason": "生产写入关闭：配置生效会中断连接，且可能存在外部配置写入者。可校验候选，不能保存到生产。"}
}

func UUIDCandidate(raw []byte, req UUIDNodeRequest) ([]byte, map[string]any, error) {
	config := candidateMap(raw)
	in := findInbound(config, req.Inbound)
	if !realityInbound(in) || strings.TrimSpace(req.Name) == "" || len([]rune(req.Name)) > 128 {
		return nil, nil, ErrScope
	}
	// Unsupported enforcement must never silently become stored/display-only limits.
	if req.Quota != 0 || req.UploadLimit != 0 || req.DownloadLimit != 0 || req.ExpiresAt != 0 || req.MaxConnections != 0 || !req.Enabled {
		return nil, nil, fmt.Errorf("实际限制执行器未启用；只接受无限制、启用状态的候选")
	}
	if req.UUID == "" {
		var e error
		req.UUID, e = NewUUID()
		if e != nil {
			return nil, nil, e
		}
	}
	req.UUID = strings.ToLower(req.UUID)
	if len(req.UUID) != 36 || req.UUID[8] != '-' || req.UUID[13] != '-' || req.UUID[18] != '-' || req.UUID[23] != '-' || !uuid(req.UUID) {
		return nil, nil, fmt.Errorf("UUID 格式无效")
	}
	for _, v := range array(config["inbounds"]) {
		for _, u := range array(object(v)["users"]) {
			if strings.EqualFold(text(object(u)["uuid"]), req.UUID) {
				return nil, nil, fmt.Errorf("UUID 已存在；不会覆盖已有身份")
			}
		}
	}
	// Use a generated unique authentication name, never the editable display name.
	authName := "tz-" + model.UUIDAuthID(req.UUID)[:32]
	for _, v := range array(config["inbounds"]) {
		for _, u := range array(object(v)["users"]) {
			if text(object(u)["name"]) == authName {
				return nil, nil, ErrScope
			}
		}
	}
	in["users"] = append(array(in["users"]), map[string]any{"name": authName, "uuid": req.UUID, "flow": "xtls-rprx-vision"})
	if req.Outbound != "" {
		found := false
		for _, v := range array(config["outbounds"]) {
			o := object(v)
			kind, _ := model.OutboundType(text(o["type"]))
			if text(o["tag"]) == req.Outbound && kind == "actual" {
				found = true
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("必须选择已有实际出站")
		}
		// Append fallback after all original policies. If an earlier route could
		// capture this identity, reject instead of overriding security/priority.
		route := object(config["route"])
		for _, v := range array(route["rules"]) {
			rule := object(v)
			if action := text(rule["action"]); action == "sniff" || action == "resolve" || action == "route-options" {
				continue
			}
			if text(rule["action"]) == "reject" {
				continue
			}
			if !definitelyExcludes(rule, req.Inbound, authName) {
				return nil, nil, fmt.Errorf("原有路由可能优先匹配；拒绝改变原安全策略")
			}
		}
		route["rules"] = append(array(route["rules"]), map[string]any{"inbound": []string{req.Inbound}, "auth_user": []string{authName}, "action": "route", "outbound": req.Outbound})
		config["route"] = route
	}
	return canonical(config), map[string]any{"valid": true, "apply": false, "name": strings.TrimSpace(req.Name), "shared_listener": true, "new_listeners": 0, "sni_shared": true, "authentication": "新增独立 UUID；凭据仅存在候选校验内存中", "routing": "原规则优先；新增身份精确匹配", "reason": "候选校验通过不代表生产已保存；未写入配置、数据库或授权"}, nil
}

func definitelyExcludes(rule map[string]any, inbound, user string) bool {
	if rule["invert"] == true || text(rule["type"]) == "logical" {
		return false
	}
	excludes := func(v any, want string) bool {
		if s, ok := v.(string); ok {
			return s != "" && s != want
		}
		a := array(v)
		if len(a) == 0 {
			return false
		}
		for _, x := range a {
			if text(x) == want {
				return false
			}
		}
		return true
	}
	return excludes(rule["inbound"], inbound) || excludes(rule["auth_user"], user)
}
