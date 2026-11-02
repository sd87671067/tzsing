package control

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const firewallComment = "sbbot-shared-config"

func firewallRun(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "/usr/sbin/ufw", args...).CombinedOutput()
	if e != nil {
		return "", errors.New("入站防火墙更新失败")
	}
	return string(out), nil
}
func inboundPorts(config map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, v := range array(config["inbounds"]) {
		in := object(v)
		n := int(integerPort(in["listen_port"]))
		if n < 1 || n > 65535 {
			continue
		}
		proto := "tcp"
		switch text(in["type"]) {
		case "hysteria", "hysteria2", "tuic":
			proto = "udp"
		}
		out[strconv.Itoa(n)+"/"+proto] = true
	}
	return out
}
func integerPort(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		v, _ := n.Int64()
		return v
	case int:
		return int64(n)
	}
	return 0
}
func (c *Controller) firewallAdditions(action string, before, after map[string]any) ([]string, error) {
	if action != "sbbot" || c.Hooks != nil {
		return nil, nil
	}
	old, next := inboundPorts(before), inboundPorts(after)
	needed := []string{}
	for p := range next {
		if !old[p] {
			needed = append(needed, p)
		}
	}
	if len(needed) == 0 {
		return nil, nil
	}
	status, e := firewallRun("status")
	if e != nil {
		return nil, e
	}
	if !strings.HasPrefix(status, "Status: active") {
		return nil, nil
	}
	ports := []string{}
	for _, p := range needed {
		allowed := false
		for _, line := range strings.Split(status, "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && (f[0] == p || f[0] == strings.Split(p, "/")[0]) && f[1] == "ALLOW" && f[2] == "Anywhere" {
				allowed = true
			}
		}
		if !allowed {
			ports = append(ports, p)
		}
	}
	sort.Strings(ports)
	return ports, nil
}
func (c *Controller) openFirewall(ports []string) error {
	for _, p := range ports {
		if _, e := firewallRun("allow", p, "comment", firewallComment); e != nil {
			return e
		}
	}
	return nil
}
func (c *Controller) rollbackFirewall(ports []string) error {
	if len(ports) == 0 {
		return nil
	}
	status, e := firewallRun("status")
	if e != nil {
		return e
	}
	for _, p := range ports {
		owned := false
		for _, line := range strings.Split(status, "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] == p && strings.Contains(line, "# "+firewallComment) {
				owned = true
			}
		}
		if owned {
			if _, e = firewallRun("--force", "delete", "allow", p); e != nil {
				return e
			}
		}
	}
	return nil
}
