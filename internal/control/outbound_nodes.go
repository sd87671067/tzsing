package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
)

// OutboundNodeRequest is accepted only across the authenticated Unix socket.
// No response ever contains the submitted link or proxy credentials.
type OutboundNodeRequest struct {
	Tag    string         `json:"tag"`
	Link   string         `json:"link"`
	Config map[string]any `json:"config"`
}

func outboundRefs(config map[string]any, tag string) []string {
	refs := map[string]bool{}
	var scan func(any, string)
	scan = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				if k == "outbound" || k == "final" || k == "detour" || k == "outbounds" || k == "default" {
					switch z := value.(type) {
					case string:
						if z == tag {
							refs[path] = true
						}
					case []any:
						for _, q := range z {
							if q == tag {
								refs[path] = true
							}
						}
					}
				}
				if k != "outbounds" {
					scan(value, path+"/"+k)
				}
			}
		case []any:
			for i, value := range x {
				scan(value, fmt.Sprintf("%s/%d", path, i))
			}
		}
	}
	scan(config["route"], "route")
	scan(config["dns"], "dns")
	scan(config["inbounds"], "inbounds")
	scan(config["endpoints"], "endpoints")
	for _, v := range array(config["outbounds"]) {
		o := object(v)
		if text(o["tag"]) != tag {
			scan(o, "outbound/"+text(o["tag"]))
		}
	}
	out := []string{}
	for p := range refs {
		out = append(out, p)
	}
	return out
}
func findOutbound(config map[string]any, tag string) map[string]any {
	for _, v := range array(config["outbounds"]) {
		o := object(v)
		if text(o["tag"]) == tag {
			return o
		}
	}
	return nil
}

// Only self-contained client configuration is accepted. Local file references,
// detours and listener-like fields cannot turn a client into a privileged reader.
func safeOutbound(o map[string]any) bool {
	allowed := " type tag server server_port username password version uuid flow security alter_id method tls transport obfs up_mbps down_mbps ports hop_interval congestion_control zero_rtt heartbeat network packet_encoding udp_over_tcp multiplex private_key public_key host_key host_key_algorithms client_version "
	for k := range o {
		if !strings.Contains(allowed, " "+k+" ") {
			return false
		}
	}
	var safe func(any) bool
	safe = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				if strings.Contains(k, "path") && k != "path" || strings.Contains(k, "file") || k == "detour" || k == "insecure" && v == true {
					return false
				}
				if !safe(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !safe(v) {
					return false
				}
			}
		}
		return true
	}
	return safe(o)
}
func outboundCandidate(raw []byte, v OutboundNodeRequest, action string) ([]byte, map[string]any, error) {
	config := candidateMap(raw)
	old := findOutbound(config, v.Tag)
	if action == "delete" {
		if old == nil {
			return nil, nil, ErrScope
		}
		if len(outboundRefs(config, v.Tag)) > 0 {
			return nil, nil, fmt.Errorf("出站仍被引用，请先解除或迁移绑定")
		}
		outs := []any{}
		for _, x := range array(config["outbounds"]) {
			if text(object(x)["tag"]) != v.Tag {
				outs = append(outs, x)
			}
		}
		config["outbounds"] = outs
		return canonical(config), nil, nil
	}
	tag := v.Tag
	if tag == "" {
		tag = "tz-out-" + auth.Random()[:16]
	} else if old == nil {
		return nil, nil, ErrScope
	}
	var out map[string]any
	if v.Link != "" {
		if v.Config != nil {
			return nil, nil, ErrLink
		}
		l, e := Parse(v.Link)
		if e != nil {
			return nil, nil, e
		}
		out, e = l.Outbound(tag)
		if e != nil {
			return nil, nil, e
		}
	} else {
		out = v.Config
		if out == nil {
			return nil, nil, ErrLink
		}
		out["tag"] = tag
	}
	kind := text(out["type"])
	category, _ := model.OutboundType(kind)
	if category != "actual" || !safeOutbound(out) {
		return nil, nil, ErrLink
	}
	switch kind {
	case "direct":
		if len(out) != 2 {
			return nil, nil, ErrLink
		}
	case "http", "socks", "shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "ssh", "anytls", "naive":
		if !validHost(text(out["server"])) {
			return nil, nil, ErrLink
		}
		var port float64
		switch n := out["server_port"].(type) {
		case int:
			port = float64(n)
		case float64:
			port = n
		}
		if port < 1 || port > 65535 || port != float64(int(port)) {
			return nil, nil, ErrLink
		}
	default:
		return nil, nil, ErrLink
	}
	outs := array(config["outbounds"])
	if old == nil {
		outs = append(outs, out)
	} else {
		for i, x := range outs {
			if text(object(x)["tag"]) == tag {
				outs[i] = out
			}
		}
	}
	config["outbounds"] = outs
	return canonical(config), out, nil
}
func (c *Controller) outboundNodes(w http.ResponseWriter, r *http.Request, v serviceRequest, raw []byte, writeEnabled bool) {
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
	send := func(v any) { json.NewEncoder(w).Encode(v) }
	config := candidateMap(raw)
	if r.URL.Path == "/outbound-catalog" {
		items := []any{}
		for _, x := range array(config["outbounds"]) {
			o := object(x)
			kind, _ := model.OutboundType(text(o["type"]))
			if kind != "actual" && text(o["type"]) != "selector" && text(o["type"]) != "urltest" {
				continue
			}
			items = append(items, map[string]any{"tag": text(o["tag"]), "protocol": text(o["type"]), "server": text(o["server"]), "port": o["server_port"], "tls": object(o["tls"])["enabled"] == true, "credentials_present": text(o["password"]) != "" || text(o["uuid"]) != "", "references": outboundRefs(config, text(o["tag"]))})
		}
		send(map[string]any{"items": items, "writable": writeEnabled, "mappings": outboundMappings(config)})
		return
	}
	if r.URL.Path == "/outbound-test" {
		o := findOutbound(config, v.Outbound)
		if o == nil {
			fail(404, "出站不存在")
			return
		}
		c.lastIP = ""
		if e := c.probe(o); e != nil {
			fail(422, e.Error())
			return
		}
		latest, err := os.ReadFile(c.Config.Config)
		if err != nil || digest(latest) != digest(raw) {
			fail(409, "检测期间出站配置发生变化，请重新检测")
			return
		}
		send(map[string]any{"ok": true, "ip": c.lastIP, "at": time.Now().Unix()})
		return
	}
	if !writeEnabled {
		fail(503, "生产写入未启用；未保存")
		return
	}
	if r.URL.Path == "/outbound-preview" {
		if v.OutboundNode == nil || v.Action != "save" && v.Action != "delete" {
			fail(400, "缺少出站配置或操作")
			return
		}
		candidate, out, e := outboundCandidate(raw, *v.OutboundNode, v.Action)
		if e != nil {
			fail(422, e.Error())
			return
		}
		// Persist the same public address that was validated. A creator-controlled
		// DNS name must not rebind to a management address after the preview.
		if out != nil && text(out["type"]) != "direct" && c.Hooks == nil {
			pinned, err := pinPublic(out)
			if err != nil {
				fail(422, err.Error())
				return
			}
			config := candidateMap(candidate)
			for _, v := range array(config["outbounds"]) {
				o := object(v)
				if text(o["tag"]) == text(out["tag"]) {
					for k := range o {
						delete(o, k)
					}
					for k, v := range pinned {
						o[k] = v
					}
				}
			}
			out = pinned
			candidate = canonical(config)
		}
		if e = c.check(candidate); e != nil {
			fail(422, e.Error())
			return
		}
		c.lastIP = ""
		if out != nil {
			if e = c.probe(out); e != nil {
				fail(422, e.Error())
				return
			}
		}
		if c.plans == nil {
			c.plans = map[string]plan{}
		}
		for k, p := range c.plans {
			if time.Now().After(p.Expires) {
				delete(c.plans, k)
			}
		}
		if len(c.plans) >= 128 {
			fail(429, "预览过多")
			return
		}
		token := auth.Random()
		tag := v.OutboundNode.Tag
		if out != nil {
			tag = text(out["tag"])
		}
		c.plans[auth.Digest(token)] = plan{Hash: digest(raw), Tag: tag, Action: "outbound-" + v.Action, Candidate: candidate, Snapshot: Snapshot{Outbound: out}, Expires: time.Now().Add(2 * time.Minute)}
		send(map[string]any{"plan": token, "tag": tag, "ip": c.lastIP, "restart": true, "reason": "出站保存将重启整个 sing-box，共享 443 连接可能中断；失败自动恢复原配置并验证服务。"})
		return
	}
	if r.URL.Path == "/outbound-apply" {
		p, ok := c.plans[auth.Digest(v.Plan)]
		delete(c.plans, auth.Digest(v.Plan))
		if !ok || !strings.HasPrefix(p.Action, "outbound-") || time.Now().After(p.Expires) {
			fail(409, "确认过期或已使用")
			return
		}
		if p.Snapshot.Outbound != nil {
			if e := c.probe(p.Snapshot.Outbound); e != nil {
				fail(422, e.Error())
				return
			}
		}
		if e := c.apply(p); e != nil {
			fail(409, e.Error())
			return
		}
		send(map[string]any{"ok": true, "tag": p.Tag, "ip": c.lastIP})
		return
	}
	fail(404, "未知操作")
}
