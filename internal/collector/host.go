package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"tzsingbox/internal/model"
)

type Collector struct {
	total, idle, rx, tx uint64
	last                time.Time
}

func number(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
func (c *Collector) Sample() *model.Host {
	h := &model.Host{}
	now := time.Now()
	b, _ := os.ReadFile("/proc/stat")
	lines := strings.Split(string(b), "\n")
	if len(lines) > 0 {
		f := strings.Fields(lines[0])
		if len(f) > 5 {
			var total uint64
			for i := 1; i < len(f) && i <= 8; i++ {
				total += number(f[i])
			}
			idle := number(f[4]) + number(f[5])
			if c.total > 0 && total > c.total {
				v := 100 * (1 - float64(idle-c.idle)/float64(total-c.total))
				h.CPU = &v
			}
			c.total, c.idle = total, idle
		}
	}
	b, _ = os.ReadFile("/proc/meminfo")
	var avail uint64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			h.MemoryTotal = number(f[1]) * 1024
		case "MemAvailable:":
			avail = number(f[1]) * 1024
		}
	}
	if h.MemoryTotal >= avail {
		h.MemoryUsed = h.MemoryTotal - avail
	}
	var fs syscall.Statfs_t
	if syscall.Statfs("/", &fs) == nil {
		h.DiskTotal = fs.Blocks * uint64(fs.Bsize)
		h.DiskUsed = (fs.Blocks - fs.Bfree) * uint64(fs.Bsize)
	}
	b, _ = os.ReadFile("/proc/loadavg")
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		h.Load = strings.Join(f[:3], " ")
	}
	b, _ = os.ReadFile("/proc/uptime")
	f = strings.Fields(string(b))
	if len(f) > 0 {
		h.Uptime, _ = strconv.ParseFloat(f[0], 64)
	}
	b, _ = os.ReadFile("/proc/net/dev")
	var rx, tx uint64
	for _, l := range strings.Split(string(b), "\n") {
		v := strings.SplitN(l, ":", 2)
		if len(v) != 2 {
			continue
		}
		iface := strings.TrimSpace(v[0])
		if iface == "lo" || strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "br-") || strings.HasPrefix(iface, "docker") {
			continue
		}
		f := strings.Fields(v[1])
		if len(f) >= 9 {
			rx += number(f[0])
			tx += number(f[8])
		}
	}
	if !c.last.IsZero() {
		dt := now.Sub(c.last).Seconds()
		if rx >= c.rx && tx >= c.tx && dt > 0 {
			up, down := float64(tx-c.tx)/dt, float64(rx-c.rx)/dt
			h.NetUp = &up
			h.NetDown = &down
		}
	}
	c.rx, c.tx, c.last = rx, tx, now
	entries, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, p := range entries {
		b, e := os.ReadFile(p)
		if e == nil && strings.TrimSpace(string(b)) == "sing-box" {
			h.SingBox = true
			break
		}
	}
	return h
}
