package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const haproxyPath = "/etc/haproxy/haproxy.cfg"

func (c *Controller) haproxyCandidate(sni string) ([]byte, []byte, error) {
	if sni == "" {
		return nil, nil, nil
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$`).MatchString(sni) {
		return nil, nil, ErrScope
	}
	raw, e := os.ReadFile(c.haproxyPath())
	if e != nil {
		return nil, nil, e
	}
	lines := strings.Split(string(raw), "\n")
	n := 0
	for i, line := range lines {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "acl" || !strings.Contains(line, "ssl_sni") {
			continue
		}
		if len(f) < 5 || f[2] != "req.ssl_sni" || f[3] != "-i" {
			return nil, nil, errors.New("HAProxy 存在复杂 SNI ACL")
		}
		if f[1] == "reality" {
			if len(f) != 5 {
				return nil, nil, ErrScope
			}
			lines[i] = "    acl reality req.ssl_sni -i " + sni
			n++
		} else {
			for _, name := range f[4:] {
				if strings.EqualFold(name, sni) {
					return nil, nil, errors.New("SNI 与其他服务冲突")
				}
			}
		}
	}
	if n != 1 {
		return nil, nil, ErrScope
	}
	candidate := []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n")
	if e = c.checkHaproxy(candidate); e != nil {
		return nil, nil, e
	}
	return raw, candidate, nil
}
func (c *Controller) checkHaproxy(raw []byte) error {
	if c.Hooks != nil && c.Hooks.HapCheck != nil {
		return c.Hooks.HapCheck(raw)
	}
	f, e := os.CreateTemp(filepath.Dir(c.haproxyPath()), ".sbbot-check-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(raw)
	f.Close()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/sbin/haproxy", "-c", "-f", f.Name()).Run()
}
func (c *Controller) restoreHaproxy(expected, next []byte) error {
	if len(next) == 0 {
		return nil
	}
	current, e := os.ReadFile(c.haproxyPath())
	if e != nil {
		return e
	}
	if bytes.Equal(current, next) {
		return nil
	}
	if !bytes.Equal(current, expected) {
		return errors.New("HAProxy 版本冲突；需人工恢复")
	}
	if e = c.checkHaproxy(next); e != nil {
		return e
	}
	if e = atomicFile(c.haproxyPath(), next, 0600); e != nil {
		return e
	}
	if c.Hooks != nil && c.Hooks.HapReload != nil {
		return c.Hooks.HapReload()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = exec.CommandContext(ctx, "/usr/bin/systemctl", "reload", "haproxy.service").Run(); e != nil {
		return e
	}
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "haproxy.service").Run()
}

func (c *Controller) haproxyPath() string {
	if c.Hooks != nil && c.Hooks.HapPath != "" {
		return c.Hooks.HapPath
	}
	return haproxyPath
}
