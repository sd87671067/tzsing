package server

import (
	"net/http"
	"time"
	"tzsingbox/internal/control"
	"tzsingbox/internal/store"
)

func (a *App) uuidAdmin(w http.ResponseWriter, r *http.Request, u store.User, path string) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.controlPermission(u, "change") {
		fail(w, 403)
		return
	}
	if path != "node-catalog" && path != "node-preview" {
		reply(w, 503, map[string]string{"error": "生产 UUID 写入未启用；新增、删除、启停和限制均未应用"})
		return
	}
	if a.ControlSocket == "" {
		reply(w, 503, map[string]string{"error": "受限控制服务未配置"})
		return
	}
	if path == "node-catalog" {
		if r.Method != "GET" {
			fail(w, 405)
			return
		}
		out, status := a.hostControl(r.Context(), "uuid-catalog", map[string]string{})
		if status == 200 {
			out["server_id"] = a.ControlServer
		}
		reply(w, status, out)
		return
	}
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	if !a.rate("uuid-preview:"+u.Name, 10) {
		fail(w, 429)
		return
	}
	var v struct {
		Server string                  `json:"server"`
		Node   control.UUIDNodeRequest `json:"node"`
	}
	if !read(w, r, &v) {
		return
	}
	if v.Server != a.ControlServer {
		fail(w, 403)
		return
	}
	if _, e := a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "uuid_candidate_check"); e != nil {
		fail(w, 500)
		return
	}
	out, status := a.hostControl(r.Context(), "uuid-preview", map[string]any{"node": v.Node})
	reply(w, status, out)
}
