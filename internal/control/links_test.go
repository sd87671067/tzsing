package control

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictOfflineLinks(t *testing.T) {
	vm := `{"v":"2","add":"example.com","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":"0","net":"tcp","tls":"tls"}`
	cases := map[string]string{
		"socks5://u:p@example.com:1080": "socks", "https://u:p@example.com": "http",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:private-secret")) + "@example.com:443": "ss",
		"trojan://private-secret@example.com:443?sni=example.com":                                                 "trojan",
		"vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp":                      "vless",
		"hy2://user:private-secret@example.com:443?obfs=salamander&obfs-password=secret":                          "hysteria2",
		"vmess://" + base64.RawStdEncoding.EncodeToString([]byte(vm)):                                             "vmess",
	}
	for raw, want := range cases {
		p, e := Parse(raw)
		if e != nil || p.Preview().Protocol != want {
			t.Fatal("supported fixture rejected", want, e)
		}
		b, _ := json.Marshal(p.Preview())
		if strings.Contains(string(b), "private-secret") {
			t.Fatal("credential disclosure")
		}
		b, _ = json.Marshal(p)
		if string(b) != "{}" {
			t.Fatal("private adapter serialized")
		}
	}
	for _, raw := range []string{"", "https://example.com/subscription", "socks://u:p@example.com:0", "socks://u:p@example.com:65536", "trojan://example.com:443", "hy2://example.com", "hy2://x@example.com?obfs=salamander", "hy2://x@example.com?mport=1-10", "ss://bad@example.com:443", "vless://bad@example.com:443", "socks://u:p@example.com:1080?url=http://localhost", "socks://example.com:1080\n", "socks://example.com:1080?%zz=x", "trojan://x@example.com:443?type=ws", "vmess://e30="} {
		if _, e := Parse(raw); e == nil {
			t.Fatal("unsafe fixture accepted")
		}
	}
}
func TestSBBotObservedFormatCompatibility(t *testing.T) {
	// Independently authored public fixtures for the URI subset inspected locally.
	for _, raw := range []string{"socks5://u:p@example.com:1080", "https://u:p@example.com", "hy2://user:pass@example.com?obfs=salamander&obfs-password=x%26y"} {
		if _, e := Parse(raw); e != nil {
			t.Fatal(e)
		}
	}
	// Offline parsing may describe a private endpoint but can never connect to it.
	if _, e := Parse("socks://u:p@127.0.0.1:1080"); e != nil {
		t.Fatal(e)
	}
}
