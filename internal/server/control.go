package server

import (
	"net/http"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/control"
	"tzsingbox/internal/store"
)

type controlNonce struct {
	IdentityTag string
	Session     string
	User        int64
	Node        string
	Expires     time.Time
	Plan        string
	Action      string
	Label       string
	OutboundID  string
}

const controlDisabled = "未配置受限控制 Agent、专门分享权限及经验证的安全热更新/出口校验机制；生产写入、连接探测与凭据导出均禁用"

// No production configuration or credential source is mounted into the web app.
// Nonces bind offline previews to the current session, actor and authorized node.
func (a *App) offlineControlAPI(w http.ResponseWriter, r *http.Request, u store.User, path string) {
	if u.Role != "admin" {
		fail(w, 403)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	fresh, _, e := a.DB.Session(cookie.Value)
	if e != nil || fresh.Role != "admin" {
		fail(w, 403)
		return
	}
	if path == "status" && r.Method == "GET" {
		id := r.URL.Query().Get("node_id")
		if _, _, e := a.DB.Resolve(fresh, id); e != nil {
			fail(w, 403)
			return
		}
		if a.controlNonces == nil {
			a.controlNonces = map[string]controlNonce{}
		}
		for k, v := range a.controlNonces {
			if time.Now().After(v.Expires) || v.User == u.ID {
				delete(a.controlNonces, k)
			}
		}
		token := auth.Random()
		a.controlNonces[auth.Digest(token)] = controlNonce{Session: auth.Digest(cookie.Value), User: u.ID, Node: id, Expires: time.Now().Add(2 * time.Minute)}
		reply(w, 200, map[string]any{"preview": true, "apply": false, "restore": false, "probe": false, "share": false, "reason": controlDisabled, "nonce": token, "impact": "尚无权威配置依赖图；不能确认 Tag、路由和连接影响范围，不允许应用"})
		return
	}
	if path == "preview" && r.Method == "POST" {
		var v struct {
			Node  string `json:"node_id"`
			Link  string `json:"link"`
			Nonce string `json:"nonce"`
		}
		if !read(w, r, &v) {
			return
		}
		key := auth.Digest(v.Nonce)
		n, ok := a.controlNonces[key]
		delete(a.controlNonces, key)
		if !ok || n.Session != auth.Digest(cookie.Value) || n.User != u.ID || n.Node != v.Node || time.Now().After(n.Expires) {
			fail(w, 409)
			return
		}
		if _, _, e := a.DB.Resolve(fresh, v.Node); e != nil {
			fail(w, 403)
			return
		}
		l, e := control.Parse(v.Link)
		if e != nil {
			reply(w, 400, map[string]string{"error": control.ErrLink.Error()})
			return
		}
		_, e = a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), fresh.Name, "local", "control_offline_preview")
		if e != nil {
			fail(w, 500)
			return
		}
		reply(w, 200, l.Preview())
		return
	}
	if path == "apply" || path == "restore" || path == "probe" || path == "share" {
		if r.Method != "POST" {
			fail(w, 405)
			return
		}
		a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), fresh.Name, "local", "control_denied_gate")
	}
	reply(w, 501, map[string]string{"error": controlDisabled})
}
