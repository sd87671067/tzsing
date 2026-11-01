package server

import (
	"net/http"
	"time"
	"tzsingbox/internal/store"
)

var userActions = []string{"change", "rename", "copy", "import_shadowrocket", "import_v2rayn"}

func (a *App) operations(u store.User) map[string]bool {
	out := map[string]bool{}
	for _, action := range userActions {
		out[action] = a.controlPermission(u, action)
	}
	if u.Role != "admin" {
		var n int
		a.DB.QueryRow("SELECT count(*) FROM uuid_permissions WHERE user_id=? AND can_change=1", u.ID).Scan(&n)
		out["change"] = n > 0
		out["restore"] = n > 0
	}
	return out
}

// Called under App.mu, serializing grant changes with WebSocket snapshots.
func (a *App) operationAdmin(w http.ResponseWriter, r *http.Request, actor store.User) {
	if r.Method == "GET" {
		rows, err := a.DB.Query("SELECT user_id,action FROM user_operations ORDER BY user_id,action")
		if err != nil {
			fail(w, 500)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id int64
			var action string
			if rows.Scan(&id, &action) != nil {
				fail(w, 500)
				return
			}
			out = append(out, map[string]any{"user_id": id, "action": action})
		}
		reply(w, 200, out)
		return
	}
	if r.Method != "PUT" {
		fail(w, 405)
		return
	}
	var v struct {
		UserID  int64    `json:"user_id"`
		Actions []string `json:"actions"`
	}
	if !read(w, r, &v) {
		return
	}
	target, err := a.DB.User(v.UserID)
	if err != nil || target.Role == "admin" || len(v.Actions) > len(userActions) {
		fail(w, 400)
		return
	}
	allowed := map[string]bool{}
	for _, x := range userActions {
		allowed[x] = true
	}
	seen := map[string]bool{}
	for _, x := range v.Actions {
		if !allowed[x] || seen[x] {
			fail(w, 400)
			return
		}
		seen[x] = true
	}
	tx, err := a.DB.Begin()
	if err != nil {
		fail(w, 500)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("DELETE FROM user_operations WHERE user_id=?", v.UserID)
	for _, x := range v.Actions {
		if err == nil {
			_, err = tx.Exec("INSERT INTO user_operations VALUES(?,?)", v.UserID, x)
		}
	}
	if err == nil {
		_, err = tx.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), actor.Name, "local", "user_operations_changed:"+target.Name)
	}
	if err != nil || tx.Commit() != nil {
		fail(w, 500)
		return
	}
	a.disconnect(v.UserID)
	reply(w, 200, map[string]bool{"ok": true})
}
