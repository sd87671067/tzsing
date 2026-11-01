package model

import "strings"

// Classification uses protocol metadata, never the user-controlled tag.
func OutboundType(protocol string) (kind, category string) {
	switch strings.ToLower(strings.ReplaceAll(protocol, "-", "")) {
	case "direct":
		return "actual", "直连"
	case "reject", "block":
		return "blocked", "拦截"
	case "selector", "urltest", "fallback", "loadbalance":
		return "logical", "逻辑选择"
	case "socks", "socks5", "http", "shadowsocks", "shadowsocksr", "ss", "ssr", "vless", "vmess", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "ssh", "naive", "anytls", "shadowtls", "tor":
		return "actual", "中转"
	default:
		return "unknown", "未知类型"
	}
}
func (t *Tag) Classify() {
	// Legacy reports without protocol metadata remain unavailable, never guessed.
	if t.Identity == "inbound" {
		t.Kind = "actual"
		_, t.Category = OutboundType(t.EgressType)
		if t.Egress == "" {
			t.Category = "当前路径未知"
		}
		t.DisplayEligible = true
		t.DisplayReason = "客户端入站"
		t.Verification = "never"
		if t.IP != nil && t.IP.Verified && t.IP.Updated > 0 && (t.IP.IPv4 != "" || t.IP.IPv6 != "") {
			t.Verification = "verified"
			if t.IP.Error != "" {
				t.Verification = "stale"
			}
		}
		return
	}
	t.Kind, t.Category = OutboundType(t.Type)
	t.DisplayEligible = false
	t.Verification = "never"
	t.DisplayReason = "尚未通过实际出口验证"
	if t.IP != nil && t.IP.Verified && t.IP.Updated > 0 && (t.IP.IPv4 != "" || t.IP.IPv6 != "") {
		t.Verification = "verified"
		if t.IP.Error != "" {
			t.Verification = "stale"
		}
	}
	if t.Kind == "actual" && (t.Category == "直连" || t.Verification != "never") {
		t.DisplayEligible = true
		t.DisplayReason = "实际出口"
	}
	if t.Kind == "logical" {
		t.DisplayReason = "逻辑节点不重复展示或计量"
	}
	if t.Kind == "blocked" {
		t.DisplayReason = "拦截出站不进入监控"
	}
}
