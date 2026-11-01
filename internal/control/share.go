package control

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
)

type Endpoint struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Verified bool   `json:"verified"`
}
type ShareProfile struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

func text(v any) string { s, _ := v.(string); return s }
func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func array(v any) []any { a, _ := v.([]any); return a }
func profileID(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:16])
}
func Profiles(in map[string]any, ep Endpoint) []ShareProfile {
	if !ep.Verified || !validHost(ep.Host) || ep.Port < 1 || ep.Port > 65535 {
		return nil
	}
	typ := text(in["type"])
	if typ == "shadowsocks" {
		if text(in["password"]) != "" {
			return []ShareProfile{{profileID(text(in["password"])), "默认认证"}}
		}
		return nil
	}
	if typ != "vless" || len(object(in["transport"])) > 0 {
		return nil
	}
	tls := object(in["tls"])
	reality := object(tls["reality"])
	if tls["enabled"] != true || reality["enabled"] != true || text(tls["server_name"]) == "" {
		return nil
	}
	out := []ShareProfile{}
	for _, v := range array(in["users"]) {
		u := object(v)
		if uuid(text(u["uuid"])) {
			label := text(u["name"])
			if label == "" {
				label = fmt.Sprintf("认证 %d", len(out)+1)
			}
			out = append(out, ShareProfile{profileID(text(u["uuid"])), label})
		}
	}
	return out
}
func Share(in map[string]any, ep Endpoint, profile, label string) (string, error) {
	found := false
	for _, p := range Profiles(in, ep) {
		if p.ID == profile {
			found = true
		}
	}
	if !found {
		return "", ErrLink
	}
	address := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	if text(in["type"]) == "shadowsocks" {
		method, password := text(in["method"]), text(in["password"])
		switch method {
		case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return "", ErrLink
		}
		// SIP002: 2022 uses percent-encoded userinfo rather than base64.
		if len(method) > 4 && method[:4] == "2022" {
			return (&url.URL{Scheme: "ss", User: url.UserPassword(method, password), Host: address, Fragment: label}).String(), nil
		}
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(method+":"+password)) + "@" + address + "#" + url.PathEscape(label), nil
	}
	tls := object(in["tls"])
	reality := object(tls["reality"])
	b, e := base64.RawURLEncoding.DecodeString(text(reality["private_key"]))
	if e != nil {
		return "", ErrLink
	}
	key, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return "", ErrLink
	}
	q := url.Values{"encryption": {"none"}, "security": {"reality"}, "type": {"tcp"}, "sni": {text(tls["server_name"])}, "fp": {"chrome"}, "pbk": {base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())}}
	if ids := array(reality["short_id"]); len(ids) > 0 {
		q.Set("sid", text(ids[0]))
	} else if s := text(reality["short_id"]); s != "" {
		q.Set("sid", s)
	}
	for _, v := range array(in["users"]) {
		u := object(v)
		if profileID(text(u["uuid"])) == profile {
			if f := text(u["flow"]); f != "" {
				q.Set("flow", f)
			}
			return (&url.URL{Scheme: "vless", User: url.User(text(u["uuid"])), Host: address, RawQuery: q.Encode(), Fragment: label}).String(), nil
		}
	}
	return "", ErrLink
}
