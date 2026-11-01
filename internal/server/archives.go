package server

import (
	"encoding/json"
	"net/http"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

// Archived identities keep their original IDs, names, aliases, grants and history.
// They never become synthetic inbounds or eligible sharing/control targets.
func (a *App) archives(w http.ResponseWriter, r *http.Request, u store.User) {
	rows, e := a.DB.Query("SELECT n.id,n.server,n.tag,n.name,s.report FROM nodes n JOIN servers s ON s.id=n.server WHERE n.tag NOT LIKE 'inbound:%' AND s.enabled=1 ORDER BY n.rowid")
	if e != nil {
		fail(w, 500)
		return
	}
	type old struct {
		id, server, tag, name string
		report                []byte
	}
	items := []old{}
	for rows.Next() {
		var v old
		if rows.Scan(&v.id, &v.server, &v.tag, &v.name, &v.report) != nil {
			rows.Close()
			fail(w, 500)
			return
		}
		items = append(items, v)
	}
	rows.Close()
	out := []map[string]any{}
	for _, v := range items {
		if !a.DB.Allowed(u, v.server, v.tag) {
			continue
		}
		var report model.Report
		json.Unmarshal(v.report, &report)
		active := false
		for _, t := range report.Tags {
			if t.Name == v.tag {
				active = true
			}
		}
		if active {
			continue
		}
		name := v.name
		var alias string
		a.DB.QueryRow("SELECT name FROM aliases WHERE user_id=? AND node_id=?", u.ID, v.id).Scan(&alias)
		if alias != "" {
			name = alias
		}
		if name == "" {
			name = "旧出站统计"
		}
		raw := ""
		if u.Role == "admin" {
			raw = v.tag
		}
		var up, down int64
		a.DB.QueryRow("SELECT totalup,totaldown FROM counters WHERE server=? AND tag=?", v.server, v.tag).Scan(&up, &down)
		out = append(out, map[string]any{"id": v.id, "name": name, "raw_tag": raw, "upload": up, "download": down, "server": v.server})
	}
	reply(w, 200, out)
}
