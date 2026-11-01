package model

import "testing"

func TestProtocolClassificationAndEligibility(t *testing.T) {
	for _, tt := range []struct {
		p, k, c string
		visible bool
	}{{"Direct", "actual", "直连", true}, {"SOCKS", "actual", "中转", false}, {"HTTP", "actual", "中转", false}, {"Shadowsocks", "actual", "中转", false}, {"VLESS", "actual", "中转", false}, {"Trojan", "actual", "中转", false}, {"Hysteria2", "actual", "中转", false}, {"Block", "blocked", "拦截", false}, {"Reject", "blocked", "拦截", false}, {"Selector", "logical", "逻辑选择", false}, {"URLTest", "logical", "逻辑选择", false}} {
		n := Tag{Name: "direct-block-selector", Type: tt.p}
		n.Classify()
		if n.Kind != tt.k || n.Category != tt.c || n.DisplayEligible != tt.visible {
			t.Fatalf("%s: %+v", tt.p, n)
		}
		n.IP = &Exit{IPv4: "8.8.8.8", Updated: 1, Verified: true}
		n.Classify()
		if n.DisplayEligible != (tt.k == "actual") {
			t.Fatalf("verified %s: %+v", tt.p, n)
		}
		n.IP.Error = "timeout"
		n.Classify()
		if n.Verification != "stale" {
			t.Fatal("lost last-good exit")
		}
	}
	n := Tag{Type: "SOCKS", IP: &Exit{IPv4: "8.8.8.8", Updated: 1}}
	n.Classify()
	if n.DisplayEligible {
		t.Fatal("legacy independent endpoint incorrectly trusted")
	}
}
