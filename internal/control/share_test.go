package control

import (
	"crypto/ecdh"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestAuthoritativeRealitySharingAndNoPrivateKey(t *testing.T) {
	private := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	in := map[string]any{"type": "vless", "tag": "actual-in", "users": []any{map[string]any{"name": "测试用户", "uuid": "11111111-1111-4111-8111-111111111111", "flow": "xtls-rprx-vision"}}, "tls": map[string]any{"enabled": true, "server_name": "example.com", "reality": map[string]any{"enabled": true, "private_key": private, "short_id": []any{"abcd"}}}}
	ep := Endpoint{Host: "example.org", Port: 443, Verified: true}
	profiles := Profiles(in, ep)
	if len(profiles) != 1 {
		t.Fatal("profiles")
	}
	link, e := Share(in, ep, profiles[0].ID, "节点 一")
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(link)
	if e != nil || u.Scheme != "vless" || u.User.Username() != "11111111-1111-4111-8111-111111111111" || u.Query().Get("security") != "reality" || u.Query().Get("flow") != "xtls-rprx-vision" {
		t.Fatal("invalid URI")
	}
	b, _ := base64.RawURLEncoding.DecodeString(private)
	key, _ := ecdh.X25519().NewPrivateKey(b)
	if u.Query().Get("pbk") != base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) || strings.Contains(link, private) {
		t.Fatal("private key disclosure or wrong public key")
	}
	if _, e = Parse(link); e != nil {
		t.Fatal("incompatible generated URI", e)
	}
	ep.Verified = false
	if len(Profiles(in, ep)) != 0 {
		t.Fatal("unattested management listener shared")
	}
	ep.Verified = true
	if _, e = Share(in, ep, "unknown", "label"); e == nil {
		t.Fatal("profile enumeration")
	}
	in["type"] = "socks"
	if len(Profiles(in, ep)) != 0 {
		t.Fatal("internal proxy shared")
	}
}
func TestSS2022SIP002(t *testing.T) {
	password := base64.StdEncoding.EncodeToString([]byte("synthetic-key-16"))
	in := map[string]any{"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": password}
	ep := Endpoint{Host: "example.org", Port: 443, Verified: true}
	p := Profiles(in, ep)
	link, e := Share(in, ep, p[0].ID, "测试")
	u, err := url.Parse(link)
	if e != nil || err != nil {
		t.Fatal(e, err)
	}
	pass, _ := u.User.Password()
	if u.User.Username() != in["method"] || pass != password {
		t.Fatal("2022 userinfo must be percent-encoded, not base64")
	}
}
