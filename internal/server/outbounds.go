package server

import (
	"net/http"
	"strings"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/control"
	"tzsingbox/internal/store"
)

func (a *App) outboundAdmin(w http.ResponseWriter, r *http.Request, u store.User) {
	w.Header().Set("Cache-Control", "no-store")
	if u.Role != "admin" || !a.controlPermission(u, "change") {
		fail(w, 403)
		return
	}
	if a.ControlSocket == "" {
		reply(w, 503, map[string]string{"error": "受限控制服务未配置"})
		return
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(180 * time.Second))
	if r.Method == "GET" {
		out, status := a.hostControl(r.Context(), "outbound-catalog", map[string]string{})
		if status == 200 {
			if items, ok := out["items"].([]any); ok {
				for _, v := range items {
					o, ok := v.(map[string]any)
					if !ok {
						continue
					}
					var name string
					a.DB.QueryRow("SELECT name FROM nodes WHERE server=? AND tag=?", a.ControlServer, o["tag"]).Scan(&name)
					if name == "" {
						name, _ = o["tag"].(string)
					}
					o["name"] = name
				}
			}
		}
		reply(w, status, out)
		return
	}
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	var v struct {
		Action string                      `json:"action"`
		Name   string                      `json:"name"`
		Node   control.OutboundNodeRequest `json:"node"`
		Nonce  string                      `json:"nonce"`
	}
	if !read(w, r, &v) {
		return
	}
	if !a.rate("outbounds:"+u.Name, 30) {
		fail(w, 429)
		return
	}
	if v.Action == "rename" {
		v.Name = strings.TrimSpace(v.Name)
		if v.Name == "" || !validTag(v.Name) {
			fail(w, 422)
			return
		}
		catalog, status := a.hostControl(r.Context(), "outbound-catalog", map[string]string{})
		if status != 200 {
			reply(w, status, catalog)
			return
		}
		found := false
		if items, ok := catalog["items"].([]any); ok {
			for _, v2 := range items {
				o, ok := v2.(map[string]any)
				if ok && o["tag"] == v.Node.Tag {
					found = true
				}
			}
		}
		if !found {
			fail(w, 404)
			return
		}
		tx, e := a.DB.Begin()
		if e != nil {
			fail(w, 500)
			return
		}
		defer tx.Rollback()
		_, e = tx.Exec("INSERT INTO nodes(id,server,tag,name) VALUES(?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET name=excluded.name", auth.Random(), a.ControlServer, v.Node.Tag, v.Name)
		if e == nil {
			_, e = tx.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "outbound_rename")
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			fail(w, 500)
			return
		}
		a.DB.Exec("UPDATE outbound_registry SET name=? WHERE server=? AND tag=?", v.Name, a.ControlServer, v.Node.Tag)
		reply(w, 200, map[string]bool{"ok": true})
		return
	}
	if v.Action == "test" {
		out, status := a.hostControl(r.Context(), "outbound-test", map[string]string{"outbound": v.Node.Tag})
		reply(w, status, out)
		return
	}
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	if v.Action == "apply" {
		a.mu.Lock()
		n, ok := a.controlNonces[auth.Digest(v.Nonce)]
		delete(a.controlNonces, auth.Digest(v.Nonce))
		a.mu.Unlock()
		if !ok || n.User != u.ID || n.Session != auth.Digest(cookie.Value) || n.Action != "outbound" || time.Now().After(n.Expires) {
			fail(w, 409)
			return
		}
		out, status := a.hostControl(r.Context(), "outbound-apply", map[string]string{"plan": n.Plan})
		if status == 200 {
			tag, _ := out["tag"].(string)
			if tag != "" && out["deleted"] == true {
				_, e = a.DB.Exec("DELETE FROM nodes WHERE server=? AND tag=?", a.ControlServer, tag)
				if e != nil {
					out["warning"] = "出站已删除，显示名称清理失败"
				}
			} else if tag != "" {
				_, e = a.DB.Exec("INSERT INTO nodes(id,server,tag,name) VALUES(?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET name=excluded.name", auth.Random(), a.ControlServer, tag, n.Node)
				if e != nil {
					out["warning"] = "出站已生效，显示名称保存失败"
				}
			}
		}
		a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "outbound_apply_status:"+http.StatusText(status))
		reply(w, status, out)
		return
	}
	if v.Action != "save" && v.Action != "delete" {
		fail(w, 400)
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if v.Action == "save" && (v.Name == "" || !validTag(v.Name)) {
		reply(w, 422, map[string]string{"error": "请输入有效显示名称"})
		return
	}
	if _, e = a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "outbound_preview:"+v.Action); e != nil {
		fail(w, 500)
		return
	}
	out, status := a.hostControl(r.Context(), "outbound-preview", map[string]any{"action": v.Action, "outbound_node": v.Node})
	if status == 200 {
		plan, _ := out["plan"].(string)
		delete(out, "plan")
		if plan == "" {
			fail(w, 502)
			return
		}
		token := auth.Random()
		a.mu.Lock()
		if a.controlNonces == nil {
			a.controlNonces = map[string]controlNonce{}
		}
		for k, n := range a.controlNonces {
			if time.Now().After(n.Expires) {
				delete(a.controlNonces, k)
			}
		}
		if len(a.controlNonces) >= 1024 {
			a.mu.Unlock()
			fail(w, 429)
			return
		}
		a.controlNonces[auth.Digest(token)] = controlNonce{User: u.ID, Session: auth.Digest(cookie.Value), Action: "outbound", Node: v.Name, Plan: plan, Expires: time.Now().Add(2 * time.Minute)}
		a.mu.Unlock()
		out["nonce"] = token
	}
	reply(w, status, out)
}
