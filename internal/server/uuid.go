package server

import (
	"net/http"
	"strings"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/control"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func (a *App) uuidAdmin(w http.ResponseWriter, r *http.Request, u store.User, path string) {
	w.Header().Set("Cache-Control", "no-store")
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(180 * time.Second))
	if u.Role != "admin" || !a.controlPermission(u, "change") {
		fail(w, 403)
		return
	}
	if a.ControlSocket == "" {
		reply(w, 503, map[string]string{"error": "受限控制服务未配置"})
		return
	}
	if path == "node-transaction" {
		if r.Method != "GET" {
			fail(w, 405)
			return
		}
		a.uuidOperationStatus(w, r, u)
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
			a.nameOutboundChoices(out["outbounds"])
		}
		reply(w, status, out)
		return
	}
	if path != "node-preview" && path != "node-create" {
		reply(w, 503, map[string]string{"error": "请使用单 UUID 操作菜单"})
		return
	}
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	if !a.rate("uuid:"+u.Name, 20) {
		fail(w, 429)
		return
	}
	var v struct {
		Server string                  `json:"server"`
		Node   control.UUIDNodeRequest `json:"node"`
		Nonce  string                  `json:"nonce"`
	}
	if !read(w, r, &v) {
		return
	}
	if v.Server != a.ControlServer {
		fail(w, 403)
		return
	}
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	if _, e = a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "uuid_"+path); e != nil {
		fail(w, 500)
		return
	}
	if path == "node-preview" {
		out, status := a.hostControl(r.Context(), "uuid-preview", map[string]any{"node": v.Node})
		if status == 200 {
			plan, _ := out["plan"].(string)
			identity, _ := out["auth_id"].(string)
			delete(out, "plan")
			delete(out, "auth_id")
			if plan == "" || !model.ValidAuthID(identity) {
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
			a.controlNonces[auth.Digest(token)] = controlNonce{Session: auth.Digest(cookie.Value), User: u.ID, IdentityTag: model.IdentityName(v.Node.Inbound, identity), Node: strings.TrimSpace(v.Node.Name), Plan: plan, Action: "create", Expires: time.Now().Add(2 * time.Minute)}
			a.mu.Unlock()
			out["nonce"] = token
		}
		reply(w, status, out)
		return
	}
	a.uuidMu.Lock()
	defer a.uuidMu.Unlock()
	// Check durable idempotency before consuming the in-memory confirmation.
	id := auth.Digest(v.Nonce)
	if v.Nonce == "" {
		fail(w, 400)
		return
	}
	var owner int64
	if a.DB.QueryRow("SELECT user_id FROM uuid_operations WHERE id=?", id).Scan(&owner) == nil {
		if owner != u.ID {
			fail(w, 403)
			return
		}
		a.startUUIDOperation(id)
		reply(w, 202, map[string]any{"transaction_id": v.Nonce, "state": "pending"})
		return
	}
	a.mu.Lock()
	n, ok := a.controlNonces[auth.Digest(v.Nonce)]
	delete(a.controlNonces, auth.Digest(v.Nonce))
	a.mu.Unlock()
	if !ok || n.Session != auth.Digest(cookie.Value) || n.User != u.ID || n.Action != "create" || time.Now().After(n.Expires) {
		fail(w, 409)
		return
	}
	if !strings.HasPrefix(n.IdentityTag, "identity:") {
		fail(w, 502)
		return
	}
	tx, e := a.DB.Begin()
	if e != nil {
		fail(w, 500)
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec("INSERT INTO uuid_operations(id,user_id,server,plan,name,tag,created) VALUES(?,?,?,?,?,?,?)", id, u.ID, a.ControlServer, n.Plan, n.Node, n.IdentityTag, time.Now().Unix()); e != nil {
		fail(w, 500)
		return
	}
	if _, e = tx.Exec("INSERT INTO nodes(id,server,tag,name) VALUES(?,?,?,?) ON CONFLICT(server,tag) DO UPDATE SET name=CASE WHEN nodes.name='' THEN excluded.name ELSE nodes.name END", auth.Random(), a.ControlServer, n.IdentityTag, n.Node); e != nil {
		fail(w, 500)
		return
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500)
		return
	}
	a.startUUIDOperation(id)
	reply(w, 202, map[string]any{"transaction_id": v.Nonce, "state": "pending"})
}
