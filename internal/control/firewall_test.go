package control

import (
	"os"
	"strings"
	"testing"
)

func TestIsolatedUFWPortRollback(t *testing.T) {
	if os.Getenv("TZSING_ISOLATED_FIREWALL") != "1" {
		t.Skip("requires isolated mount and network namespaces")
	}
	c := &Controller{}
	before, e := firewallRun("status")
	if e != nil {
		t.Fatal(e)
	}
	after := map[string]any{"inbounds": []any{map[string]any{"type": "vless", "listen_port": float64(49123)}}}
	ports, e := c.firewallAdditions("sbbot", map[string]any{}, after)
	if e != nil || len(ports) != 1 {
		t.Fatal("port plan", ports, e)
	}
	if e = c.openFirewall(ports); e != nil {
		t.Fatal(e)
	}
	status, e := firewallRun("status")
	if e != nil || !strings.Contains(status, "49123/tcp") || !strings.Contains(status, firewallComment) {
		t.Fatal("port not allowed", e)
	}
	if e = c.rollbackFirewall(ports); e != nil {
		t.Fatal(e)
	}
	status, e = firewallRun("status")
	if e != nil || status != before {
		t.Fatal("rollback did not preserve existing firewall", e)
	}
}
