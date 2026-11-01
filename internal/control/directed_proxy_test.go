package control

import (
	"encoding/json"
	"os"
	"testing"
)

// No credential fixture or endpoint is committed. Explicit opt-in reads the
// root-owned source and starts disposable clients; it never edits that source.
func TestDirectedSecureProxyProtocols(t *testing.T) {
	path, tagHash := os.Getenv("TZSING_PROXY_CONFIG"), os.Getenv("TZSING_DIRECTED_TAG_SHA")
	if path == "" || tagHash == "" {
		t.Skip("root-owned secure configuration opt-in required")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("secure source unavailable")
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("invalid secure source")
	}
	var out map[string]any
	for _, v := range array(config["outbounds"]) {
		o := object(v)
		if digest([]byte(text(o["tag"]))) == tagHash {
			out = o
		}
	}
	if out == nil {
		t.Fatal("directed source not found")
	}
	c := &Controller{Config: ServiceConfig{State: t.TempDir(), Binary: os.Getenv("TZSING_TEST_SINGBOX")}}
	for _, protocol := range []string{"socks", "http"} {
		t.Run(protocol, func(t *testing.T) {
			o := map[string]any{}
			for _, key := range []string{"server", "server_port", "username", "password"} {
				if v, ok := out[key]; ok {
					o[key] = v
				}
			}
			o["type"] = protocol
			c.lastIP = ""
			e := c.probeClient(o)
			if e != nil {
				if protocol == "http" {
					t.Fatal(e)
				}
				t.Log("original SOCKS path rejected:", e)
				return
			}
			t.Log("verified HTTPS exit IP:", c.lastIP)
		})
	}
}
