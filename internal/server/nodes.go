package server

import (
	"net/http"
	"strings"
	"time"
	"tzsingbox/internal/store"
)

func (a *App) nodeSettings(w http.ResponseWriter, r *http.Request, u store.User, admin bool) {
	if r.Method != "PUT" {
		fail(w, 405)
		return
	}
	var v struct {
		ID             string `json:"node_id"`
		Name           string `json:"name"`
		Quota          int64  `json:"quota"`
		ExpiresAt      int64  `json:"expires_at"`
		BillingDay     int    `json:"billing_day"`
		Timezone       string `json:"timezone"`
		AlertThreshold int    `json:"alert_threshold"`
	}
	if !read(w, r, &v) {
		return
	}
	if v.BillingDay == 0 {
		v.BillingDay = 1
	}
	if v.Timezone == "" {
		v.Timezone = "UTC"
	}
	if v.AlertThreshold == 0 {
		v.AlertThreshold = 80
	}
	if _, e := time.LoadLocation(v.Timezone); e != nil || v.BillingDay < 1 || v.BillingDay > 31 || v.AlertThreshold < 1 || v.AlertThreshold > 100 || v.ExpiresAt < 0 || v.ExpiresAt > 253402300799 {
		fail(w, 400)
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if (v.Name != "" && !validTag(v.Name)) || v.Quota < 0 || v.Quota > 1<<60 {
		fail(w, 400)
		return
	}
	if _, _, err := a.DB.Resolve(u, v.ID); err != nil {
		fail(w, 403)
		return
	}
	tx, err := a.DB.Begin()
	if err != nil {
		fail(w, 500)
		return
	}
	defer tx.Rollback()
	if admin {
		_, err = tx.Exec("UPDATE nodes SET name=?,quota=? WHERE id=?", v.Name, v.Quota, v.ID)
		if err == nil {
			_, err = tx.Exec("INSERT INTO node_metadata VALUES(?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET expires_at=excluded.expires_at,billing_day=excluded.billing_day,timezone=excluded.timezone,alert_threshold=excluded.alert_threshold", v.ID, v.ExpiresAt, v.BillingDay, v.Timezone, v.AlertThreshold)
		}
		if err == nil && (v.BillingDay != 1 || v.Timezone != "UTC") {
			start := store.BillingStart(time.Now(), v.BillingDay, v.Timezone).Unix()
			// Seed only when this period is new; never overwrite accumulated usage on a metadata edit.
			_, err = tx.Exec("INSERT OR IGNORE INTO billing_usage SELECT n.server,n.tag,?,COALESCE((SELECT SUM(h.upload+h.download) FROM history h WHERE h.server=n.server AND h.tag=n.tag AND h.minute>=?),0) FROM nodes n WHERE n.id=?", start, start/60, v.ID)
		}
	} else {
		_, err = tx.Exec("INSERT INTO aliases VALUES(?,?,?) ON CONFLICT(user_id,node_id) DO UPDATE SET name=excluded.name", u.ID, v.ID, v.Name)
	}
	if err == nil && admin {
		_, err = tx.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "node_global_name_quota: "+v.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		fail(w, 500)
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
