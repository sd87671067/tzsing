package control

import (
	"net"
	"strings"
)

// Outbound is used only by the restricted host controller, never monitoring DTOs.
// Unsupported options fail closed instead of silently losing link semantics.
func (l *Link) Outbound(tag string) (map[string]any, error) {
	if l.kind == "vmess" || l.options.Get("pinSHA256") != "" || l.options.Get("insecure") == "1" {
		return nil, ErrLink
	}
	o := map[string]any{"type": l.kind, "tag": tag, "server": l.host, "server_port": l.port}
	switch l.kind {
	case "vless":
		o["uuid"] = l.secret
		if f := l.options.Get("flow"); f != "" {
			o["flow"] = f
		}
	case "trojan", "hysteria2":
		o["password"] = l.secret
	case "ss":
		o["type"] = "shadowsocks"
		o["method"] = l.method
		o["password"] = l.secret
	case "http", "socks":
		if l.username != "" {
			o["username"] = l.username
		}
		if l.secret != "" {
			o["password"] = l.secret
		}
	default:
		return nil, ErrLink
	}
	sec := l.options.Get("security")
	if sec == "tls" || sec == "reality" || l.kind == "trojan" || l.kind == "hysteria2" {
		name := l.options.Get("sni")
		if name == "" && net.ParseIP(l.host) == nil {
			name = l.host
		}
		tls := map[string]any{"enabled": true}
		if name != "" {
			tls["server_name"] = name
		}
		if a := l.options.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		if sec == "reality" {
			if name == "" {
				return nil, ErrLink
			}
			tls["reality"] = map[string]any{"enabled": true, "public_key": l.options.Get("pbk"), "short_id": l.options.Get("sid")}
		}
		if fp := l.options.Get("fp"); fp != "" || sec == "reality" {
			if fp == "" {
				fp = "chrome"
			}
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		o["tls"] = tls
	}
	if l.kind == "hysteria2" && l.options.Get("obfs") == "salamander" {
		o["obfs"] = map[string]any{"type": "salamander", "password": l.options.Get("obfs-password")}
	}
	return o, nil
}
