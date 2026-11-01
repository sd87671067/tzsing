package store

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
)

func (s *Store) DefaultName() string {
	var name string
	if s.QueryRow("SELECT value FROM preferences WHERE key='default_node_name'").Scan(&name) != nil || name == "" {
		return "节点"
	}
	return name
}

// Present is shared by snapshots, WebSocket and exports. Raw identity never
// leaves this boundary for viewers when disclosure is disabled.
func (s *Store) Present(u User, server string, t *model.Tag) error {
	raw := t.Name
	// Restore only attested last-good exits; old independent SOCKS probes are not trusted.
	t.Classify()
	if t.IP == nil || !t.IP.Verified || t.IP.Error != "" {
		var b []byte
		if s.QueryRow("SELECT data FROM exit_cache WHERE server=? AND tag=?", server, raw).Scan(&b) == nil {
			var old model.Exit
			if json.Unmarshal(b, &old) == nil && old.Verified {
				old.Error = "待重新验证"
				if t.IP != nil {
					old.Attempted = t.IP.Attempted
				}
				t.IP = &old
			}
		}
	}
	if t.IP != nil && t.IP.Verified {
		valid := false
		for _, v := range []string{t.IP.IPv4, t.IP.IPv6} {
			ip := net.ParseIP(v)
			if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				valid = true
			}
		}
		if !valid {
			t.IP = nil
		}
	}
	t.Classify()
	if t.Verification == "verified" && (time.Now().Unix()-t.IP.Updated > 3600 || t.State == "unknown") {
		t.Verification = "stale"
	}
	if t.Kind != "actual" {
		t.Up = nil
		t.Down = nil
		t.Upload = nil
		t.Download = nil
		t.Active = nil
		t.IP = nil
	}
	t.Quality = "observed_lower_bound"
	if t.Kind == "actual" {
		var up, down int64
		if s.QueryRow("SELECT totalup,totaldown FROM counters WHERE server=? AND tag=?", server, raw).Scan(&up, &down) == nil {
			t.Upload = &up
			t.Download = &down
		}
		s.QueryRow("SELECT upload,download FROM daily_flow WHERE server=? AND tag=? AND day=?", server, raw, time.Now().UTC().Format("2006-01-02")).Scan(&t.TodayUpload, &t.TodayDownload)
		s.QueryRow("SELECT upload,download FROM monthly_flow WHERE server=? AND tag=? AND month=?", server, raw, time.Now().UTC().Format("2006-01")).Scan(&t.MonthUpload, &t.MonthDownload)
	}

	if _, err := s.Exec("INSERT OR IGNORE INTO nodes(id,server,tag) VALUES(?,?,?)", auth.Random(), server, raw); err != nil {
		return err
	}
	var global, personal string
	var number int64
	if err := s.QueryRow("SELECT rowid,id,name,quota FROM nodes WHERE server=? AND tag=?", server, raw).Scan(&number, &t.ID, &global, &t.Quota); err != nil {
		return err
	}
	s.QueryRow("SELECT name FROM aliases WHERE user_id=? AND node_id=?", u.ID, t.ID).Scan(&personal)
	t.Name = global
	if t.Name == "" {
		t.Name = fmt.Sprintf("%s %02d", s.DefaultName(), number)
	}
	if personal != "" {
		t.Name = personal
	}
	t.FallbackName = global == "" && personal == ""
	t.RawTag = ""
	t.GlobalName = ""
	t.NeedsName = false
	show := u.Role == "admin" || s.Setting("show_raw_tag", 0) == 1
	if show {
		t.RawTag = raw
	}
	if u.Role == "admin" {
		t.GlobalName = global
		t.NeedsName = global == ""
	}
	if t.Egress != "" {
		var label, id string
		var n int64
		if err := s.QueryRow("SELECT rowid,id,name FROM nodes WHERE server=? AND tag=?", server, t.Egress).Scan(&n, &id, &label); err == nil {
			if label == "" {
				label = fmt.Sprintf("%s %02d", s.DefaultName(), n)
			}
			var own string
			s.QueryRow("SELECT name FROM aliases WHERE user_id=? AND node_id=?", u.ID, id).Scan(&own)
			if own != "" {
				label = own
			}
			t.Egress = label
		} else {
			t.Egress = ""
		}
	}
	if u.Role != "admin" {
		switch t.State {
		case "online", "unknown", "offline", "active", "idle":
		default:
			t.State = "unknown"
		}
		switch t.Quality {
		case "observed_lower_bound", "unavailable", "observed-lower-bound":
		default:
			t.Quality = ""
		}
	}
	if u.Role != "admin" {
		if s.Setting("show_expiry", 0) == 0 {
			t.ExpiresAt = 0
		}
		if s.Setting("show_quota", 1) == 0 {
			t.Quota = 0
		}
	}
	if u.Role != "admin" && t.IP != nil {
		ip := *t.IP
		if ip.Error != "" {
			ip.Error = "出口检测暂不可用"
		}
		t.IP = &ip
	}
	t.Month = time.Now().UTC().Format("2006-01")
	t.MonthUsed = nil
	if t.Kind == "actual" {
		var used int64
		if err := s.QueryRow("SELECT used FROM monthly WHERE server=? AND tag=? AND month=?", server, raw, t.Month).Scan(&used); err == nil {
			t.MonthUsed = &used
		}
	}
	t.ExpiresAt = 0
	t.BillingDay = 1
	t.Timezone = "UTC"
	t.AlertThreshold = 80
	s.QueryRow("SELECT expires_at,billing_day,timezone,alert_threshold FROM node_metadata WHERE node_id=?", t.ID).Scan(&t.ExpiresAt, &t.BillingDay, &t.Timezone, &t.AlertThreshold)
	t.PeriodStart = BillingStart(time.Now(), t.BillingDay, t.Timezone).Unix()
	if t.BillingDay != 1 || t.Timezone != "UTC" {
		var used int64
		if s.QueryRow("SELECT used FROM billing_usage WHERE server=? AND tag=? AND start=?", server, raw, t.PeriodStart).Scan(&used) == nil {
			t.MonthUsed = &used
		} else {
			t.MonthUsed = new(int64)
		}
	}
	if u.Role != "admin" {
		if s.Setting("show_expiry", 0) == 0 {
			t.ExpiresAt = 0
		}
		if s.Setting("show_quota", 1) == 0 {
			t.Quota = 0
			t.BillingDay = 0
			t.Timezone = ""
			t.AlertThreshold = 0
			t.PeriodStart = 0
		}
	}
	return nil
}

// Resolve always checks the current grant. Viewer endpoints accept only opaque IDs.
func (s *Store) Resolve(u User, id string) (server, tag string, err error) {
	err = s.QueryRow("SELECT server,tag FROM nodes WHERE id=?", id).Scan(&server, &tag)
	if err == nil && !s.Allowed(u, server, tag) {
		err = fmt.Errorf("forbidden")
	}
	return
}
