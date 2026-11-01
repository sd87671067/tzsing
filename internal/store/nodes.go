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
	configName := t.AuthName
	// Restore only attested last-good exits; old independent SOCKS probes are not trusted.
	t.Classify()
	if t.IP == nil || !t.IP.Verified || t.IP.Error != "" {
		var b []byte
		if s.QueryRow("SELECT data FROM exit_cache WHERE server=? AND tag=?", server, raw).Scan(&b) == nil {
			var old model.Exit
			if json.Unmarshal(b, &old) == nil && old.Verified && (t.Identity != "inbound" || (t.Egress != "" && old.Path == t.Egress+"@"+t.RouteVersion)) {
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
	if t.Identity == "inbound" && t.Egress == "" {
		t.IP = nil
	}
	if len(t.Egresses) == 1 && t.Egresses[0].Tag == t.Egress && t.IP != nil && t.IP.Path == t.Egress+"@"+t.RouteVersion {
		ip := *t.IP
		t.Egresses[0].IP = &ip
	}
	// Each path owns its own address; never lend a single-path fallback to a
	// multi-exit identity. Reports persist the full path list in SQLite unchanged.
	for i := range t.Egresses {
		path := &t.Egresses[i]
		var cached []byte
		if s.QueryRow("SELECT data FROM exit_cache WHERE server=? AND tag=?", server, raw+"|egress:"+path.Tag).Scan(&cached) == nil {
			var ip model.Exit
			if json.Unmarshal(cached, &ip) == nil && ip.Verified && ip.Path == path.Tag+"@"+t.RouteVersion && (path.IP == nil || (ip.Updated > path.IP.Updated || (ip.Updated == path.IP.Updated && ip.Attempted > path.IP.Attempted))) {
				path.IP = &ip
			}
		}
		if path.IP != nil {
			ip := *path.IP
			path.IP = &ip
			valid := false
			for _, v := range []string{ip.IPv4, ip.IPv6} {
				a := net.ParseIP(v)
				if a != nil && a.IsGlobalUnicast() && !a.IsPrivate() {
					valid = true
				}
			}
			if !valid || ip.Path != path.Tag+"@"+t.RouteVersion {
				path.IP = nil
			}
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
	if t.Kind == "actual" && t.Accounting != "unavailable" {
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
		t.Name = t.AuthName
	}
	if t.Name == "" {
		t.Name = fmt.Sprintf("%s %02d", s.DefaultName(), number)
	}
	if personal != "" {
		t.Name = personal
	}
	t.FallbackName = global == "" && personal == "" && t.AuthName == ""
	if t.Accounting == "unavailable" {
		t.Up = nil
		t.Down = nil
		t.Upload = nil
		t.Download = nil
		t.Active = nil
		t.MonthUsed = nil
		t.TodayUpload = 0
		t.TodayDownload = 0
		t.MonthUpload = 0
		t.MonthDownload = 0
		t.Quality = "authentication_unavailable"
	}
	t.AuthName = ""
	t.LegacyAuthID = ""
	t.AuthScheme = ""
	t.GrantTag = ""
	t.RawTag = ""
	t.GlobalName = ""
	t.NeedsName = false
	show := u.Role == "admin" || s.Setting("show_raw_tag", 0) == 1
	if show {
		t.RawTag = raw
		if t.Identity == "inbound" {
			t.RawTag = t.InboundTag
		}
	}
	if u.Role == "admin" {
		t.GrantTag = raw
		t.GlobalName = global
		t.NeedsName = global == "" && configName == ""
	}
	if t.Identity == "inbound" {
		if !show {
			t.InboundTag = ""
			t.Egress = ""
			for i := range t.Egresses {
				t.Egresses[i].Tag = ""
				if t.Egresses[i].IP != nil {
					t.Egresses[i].IP.Path = ""
				}
			}
			if t.IP != nil {
				ip := *t.IP
				ip.Path = ""
				t.IP = &ip
			}
		}
	}
	if t.Identity != "inbound" && t.Egress != "" {
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
		t.AuthID = ""
		switch t.State {
		case "online", "unknown", "offline", "active", "idle":
		default:
			t.State = "unknown"
		}
		switch t.Quality {
		case "observed_lower_bound", "unavailable", "observed-lower-bound", "authentication_unavailable":
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
	if t.Kind == "actual" && t.Accounting != "unavailable" {
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
	if t.Accounting == "unavailable" {
		t.MonthUsed = nil
	}
	t.ShowExpiry = u.Role == "admin" || s.Setting("show_expiry", 0) == 1
	t.ShowQuota = u.Role == "admin" || s.Setting("show_quota", 1) == 1
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
