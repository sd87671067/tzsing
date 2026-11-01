// Package control owns offline link validation. It has no filesystem writer,
// network client, process launcher or reference to the monitoring collector.
package control

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

var ErrLink = errors.New("链接格式或参数不支持；请使用明确的单节点分享 URI")

// Link keeps secrets private. Only Preview may be returned to a browser.
type Link struct {
	kind, host, secret, username, method string
	port                                 int
	options                              url.Values
}
type Preview struct {
	Protocol     string `json:"protocol"`
	Server       string `json:"server"`
	Port         int    `json:"port"`
	Transport    string `json:"transport"`
	Security     string `json:"security"`
	Credentials  bool   `json:"credentials_present"`
	V2rayN       string `json:"v2rayn"`
	Shadowrocket string `json:"shadowrocket"`
}

func decode64(s string) ([]byte, error) {
	for _, e := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, ErrLink
}
func uuid(s string) bool {
	b, e := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return e == nil && len(b) == 16
}
func Parse(raw string) (*Link, error) {
	if len(raw) == 0 || len(raw) > 16<<10 || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, ErrLink
	}
	if strings.HasPrefix(raw, "vmess://") {
		return parseVMess(strings.TrimPrefix(raw, "vmess://"))
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return nil, ErrLink
	}
	l := &Link{kind: strings.ToLower(u.Scheme), host: u.Hostname(), options: u.Query()}
	switch l.kind {
	case "socks5":
		l.kind = "socks"
	case "hy2":
		l.kind = "hysteria2"
	case "https":
		l.kind = "http"
		l.options.Set("security", "tls")
	}
	switch l.kind {
	case "socks", "http", "ss", "vless", "trojan", "hysteria2":
	default:
		return nil, ErrLink
	}
	if u.RawQuery != "" {
		if _, e := url.ParseQuery(u.RawQuery); e != nil {
			return nil, ErrLink
		}
	}
	if u.Path != "" && u.Path != "/" {
		return nil, ErrLink
	}
	if u.User != nil {
		l.username = u.User.Username()
		l.secret, _ = u.User.Password()
	}
	if l.kind == "ss" {
		if u.User == nil {
			return nil, ErrLink
		}
		if _, ok := u.User.Password(); !ok {
			b, e := decode64(l.username)
			if e != nil {
				return nil, ErrLink
			}
			l.method, l.secret, _ = strings.Cut(string(b), ":")
		} else {
			l.method = l.username
		}
		switch l.method {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return nil, ErrLink
		}
		if l.secret == "" {
			return nil, ErrLink
		}
	}
	l.port, _ = strconv.Atoi(u.Port())
	if u.Port() == "" {
		switch l.kind {
		case "http":
			l.port = 80
			if l.options.Get("security") == "tls" {
				l.port = 443
			}
		case "hysteria2", "trojan", "vless":
			l.port = 443
		}
	}
	if !validHost(l.host) || l.port < 1 || l.port > 65535 {
		return nil, ErrLink
	}
	allowed := map[string]string{"socks": "", "http": "", "ss": "", "vless": "type security sni alpn fp pbk sid flow encryption", "trojan": "type security sni alpn", "hysteria2": "sni insecure obfs obfs-password pinSHA256"}[l.kind]
	// HTTPS generated security is internal, not a silently accepted HTTP parameter.
	if l.kind == "http" && u.Scheme == "https" {
		allowed = "security"
	}
	for k, v := range l.options {
		if k == "" || len(v) != 1 || !strings.Contains(" "+allowed+" ", " "+k+" ") {
			return nil, ErrLink
		}
	}
	switch l.kind {
	case "vless":
		if !uuid(l.username) || l.secret != "" {
			return nil, ErrLink
		}
		l.secret = l.username
		l.username = ""
		if t := l.options.Get("type"); t != "" && t != "tcp" && t != "raw" {
			return nil, ErrLink
		}
		if v := l.options.Get("encryption"); v != "" && v != "none" {
			return nil, ErrLink
		}
		switch l.options.Get("security") {
		case "", "none", "tls":
		case "reality":
			b, e := base64.RawURLEncoding.DecodeString(l.options.Get("pbk"))
			if e != nil || len(b) != 32 {
				return nil, ErrLink
			}
			sid, e := hex.DecodeString(l.options.Get("sid"))
			if e != nil || len(sid) > 8 {
				return nil, ErrLink
			}
		default:
			return nil, ErrLink
		}
		if f := l.options.Get("flow"); f != "" && f != "xtls-rprx-vision" {
			return nil, ErrLink
		}
	case "trojan":
		if l.username == "" || l.secret != "" {
			return nil, ErrLink
		}
		l.secret = l.username
		l.username = ""
		if t := l.options.Get("type"); t != "" && t != "tcp" {
			return nil, ErrLink
		}
		if s := l.options.Get("security"); s != "" && s != "tls" {
			return nil, ErrLink
		}
	case "hysteria2":
		// URI userinfo is a single authentication value, including a literal colon.
		if u.User == nil {
			return nil, ErrLink
		}
		l.secret = l.username
		if p, ok := u.User.Password(); ok {
			l.secret += ":" + p
		}
		l.username = ""
		if l.secret == "" {
			return nil, ErrLink
		}
		if s := l.options.Get("insecure"); s != "" && s != "0" && s != "1" {
			return nil, ErrLink
		}
		if s := l.options.Get("obfs"); s != "" && (s != "salamander" || l.options.Get("obfs-password") == "") {
			return nil, ErrLink
		}
	}
	return l, nil
}
func validHost(s string) bool {
	if s == "" || strings.ContainsAny(s, "/%\\@?#") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) > 253 {
		return false
	}
	for _, p := range strings.Split(s, ".") {
		if len(p) < 1 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func parseVMess(raw string) (*Link, error) {
	b, e := decode64(raw)
	if e != nil {
		return nil, ErrLink
	}
	var v map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(b))
	if d.Decode(&v) != nil {
		return nil, ErrLink
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrLink
	}
	allowed := " v ps add port id aid scy net type host path tls sni alpn fp "
	for k := range v {
		if !strings.Contains(allowed, " "+k+" ") {
			return nil, ErrLink
		}
	}
	get := func(k string) string {
		var s string
		if json.Unmarshal(v[k], &s) == nil {
			return s
		}
		var n json.Number
		if json.Unmarshal(v[k], &n) == nil {
			return string(n)
		}
		return ""
	}
	port, _ := strconv.Atoi(get("port"))
	if get("v") != "2" || !validHost(get("add")) || port < 1 || port > 65535 || !uuid(get("id")) || (get("aid") != "" && get("aid") != "0") || get("net") != "tcp" || (get("type") != "" && get("type") != "none") || get("host") != "" || get("path") != "" {
		return nil, ErrLink
	}
	if get("tls") != "" && get("tls") != "tls" {
		return nil, ErrLink
	}
	switch get("scy") {
	case "", "auto", "aes-128-gcm", "chacha20-poly1305", "none":
	default:
		return nil, ErrLink
	}
	return &Link{kind: "vmess", host: get("add"), port: port, secret: get("id"), options: url.Values{"security": {get("tls")}, "type": {"tcp"}}}, nil
}
func (l *Link) Preview() Preview {
	t := l.options.Get("type")
	if t == "" {
		t = "tcp"
	}
	if l.kind == "hysteria2" {
		t = "quic"
	}
	s := l.options.Get("security")
	if s == "" {
		s = "none"
		if l.kind == "trojan" || l.kind == "hysteria2" {
			s = "tls"
		}
	}
	// No client support is inferred from the monitoring protocol label alone.
	v, sr := "支持此 URI 子集；未测试实际客户端", "未完成客户端协议核验，禁止自动导入"
	if l.kind == "http" {
		v = "HTTP URI 导入未核验，禁用"
	}
	return Preview{l.kind, l.host, l.port, t, s, l.secret != "", v, sr}
}
