package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/control"
	"tzsingbox/internal/store"
)

func (a *App) syncOutbounds(ctx context.Context) ([]store.Outbound, error) {
	out, status := a.hostControl(ctx, "outbound-catalog", map[string]string{})
	if status != 200 {
		return nil, fmt.Errorf("出站清单暂不可用")
	}
	items := []store.Outbound{}
	entries, ok := out["items"].([]any)
	if !ok {
		return nil, fmt.Errorf("出站清单响应无效")
	}
	for _, x := range entries {
		v, ok := x.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := v["tag"].(string)
		name := tag
		var alias string
		a.DB.QueryRow("SELECT name FROM nodes WHERE server=? AND tag=?", a.ControlServer, tag).Scan(&alias)
		if alias != "" {
			name = alias
		}
		o, e := a.DB.RegisterOutbound(a.ControlServer, tag, name, 0)
		if e != nil {
			return nil, e
		}
		items = append(items, o)
	}
	return items, nil
}

// Revocation policy: restore all routes applied by the affected user first.
// If restoration fails, the permission change is refused with a visible error.
func (a *App) restoreUserBindings(ctx context.Context, user int64, node string) error {
	rows, e := a.DB.Query("SELECT node_id FROM uuid_bindings WHERE user_id=? AND (?='' OR node_id=?)", user, node, node)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		t, ok := a.currentInbound(store.User{Role: "admin"}, id)
		if !ok {
			return fmt.Errorf("无法恢复已绑定 UUID；授权未撤销，请检查配置")
		}
		payload := map[string]string{"tag": t.InboundTag, "auth_id": t.AuthID}
		p, status := a.hostControl(ctx, "restore-preview", payload)
		if status != 200 {
			return fmt.Errorf("原出站恢复失败；授权未撤销，请先处理绑定")
		}
		payload["plan"], _ = p["plan"].(string)
		if _, status = a.hostControl(ctx, "apply", payload); status != 200 {
			return fmt.Errorf("恢复未通过健康检查；授权未撤销")
		}
		if _, e = a.DB.Exec("DELETE FROM uuid_bindings WHERE node_id=?", id); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) uuidPermissions(w http.ResponseWriter, r *http.Request, u store.User) {
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(180 * time.Second))
	if u.Role != "admin" {
		fail(w, 403)
		return
	}
	if r.Method == "GET" {
		items, e := a.syncOutbounds(r.Context())
		if e != nil {
			reply(w, 503, map[string]string{"error": e.Error()})
			return
		}
		rows, e := a.DB.Query("SELECT user_id,node_id FROM uuid_permissions")
		if e != nil {
			fail(w, 500)
			return
		}
		keys := [][2]any{}
		for rows.Next() {
			var user int64
			var node string
			rows.Scan(&user, &node)
			keys = append(keys, [2]any{user, node})
		}
		rows.Close()
		perms := []store.UUIDPermission{}
		for _, k := range keys {
			perms = append(perms, a.DB.UUIDPermission(k[0].(int64), k[1].(string)))
		}
		reply(w, 200, map[string]any{"outbounds": items, "permissions": perms, "revocation": "撤权前恢复该用户相关 UUID 的原始出站；恢复失败则拒绝撤权并明确报错"})
		return
	}
	if r.Method != "PUT" {
		fail(w, 405)
		return
	}
	var p store.UUIDPermission
	if !read(w, r, &p) {
		return
	}
	target, e := a.DB.User(p.User)
	server, raw, e2 := a.DB.Resolve(target, p.Node)
	if e != nil || e2 != nil || target.Role == "admin" || server != a.ControlServer || !strings.HasPrefix(raw, "identity:") || len(p.Outbounds) > 512 {
		fail(w, 403)
		return
	}
	for _, id := range p.Outbounds {
		o, e := a.DB.Outbound(id)
		if e != nil || o.Server != server {
			fail(w, 403)
			return
		}
	}
	if e = a.restoreUserBindings(r.Context(), p.User, p.Node); e != nil {
		reply(w, 409, map[string]string{"error": e.Error()})
		return
	}
	tx, e := a.DB.Begin()
	if e != nil {
		fail(w, 500)
		return
	}
	defer tx.Rollback()
	_, e = tx.Exec("INSERT INTO uuid_permissions VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,node_id) DO UPDATE SET can_change=excluded.can_change,can_add=excluded.can_add,can_edit=excluded.can_edit,can_delete=excluded.can_delete", p.User, p.Node, p.Change, p.Add, p.Edit, p.Delete)
	if e == nil {
		_, e = tx.Exec("DELETE FROM uuid_outbound_grants WHERE user_id=? AND node_id=?", p.User, p.Node)
	}
	for _, id := range p.Outbounds {
		if e == nil {
			_, e = tx.Exec("INSERT OR IGNORE INTO uuid_outbound_grants VALUES(?,?,?)", p.User, p.Node, id)
		}
	}
	if e == nil {
		_, e = tx.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "uuid_permissions_changed:"+p.Node)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500)
		return
	}
	a.mu.Lock()
	a.disconnect(p.User)
	a.mu.Unlock()
	reply(w, 200, map[string]bool{"ok": true})
}

func (a *App) personalOutbounds(w http.ResponseWriter, r *http.Request, u store.User) {
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(180 * time.Second))
	node := r.URL.Query().Get("node_id")
	var v struct {
		Node   string `json:"node_id"`
		ID     string `json:"id"`
		Action string `json:"action"`
		Name   string `json:"name"`
		Link   string `json:"link"`
		Nonce  string `json:"nonce"`
	}
	if r.Method == "POST" {
		if !read(w, r, &v) {
			return
		}
		node = v.Node
	} else if r.Method != "GET" {
		fail(w, 405)
		return
	}
	server, raw, e := a.DB.Resolve(u, node)
	if e != nil || server != a.ControlServer || !strings.HasPrefix(raw, "identity:") {
		fail(w, 403)
		return
	}
	p := a.DB.UUIDPermission(u.ID, node)
	if r.Method == "GET" {
		items, e := a.syncOutbounds(r.Context())
		if e != nil {
			fail(w, 503)
			return
		}
		visible := []store.Outbound{}
		for _, o := range items {
			if u.Role == "admin" || o.Owner == u.ID || a.DB.CanBind(u, node, o.ID) {
				visible = append(visible, o)
			}
		}
		reply(w, 200, map[string]any{"items": visible, "permission": p})
		return
	}
	if !a.rate("personal:"+u.Name, 30) {
		fail(w, 429)
		return
	}
	var o store.Outbound
	if v.ID != "" {
		o, e = a.DB.Outbound(v.ID)
		if e != nil || o.Server != server || u.Role != "admin" && o.Owner != u.ID {
			fail(w, 403)
			return
		}
	}
	allowed := func(action string) bool {
		if u.Role == "admin" {
			return true
		}
		switch action {
		case "create":
			return p.Add
		case "edit":
			return p.Edit
		case "delete":
			return p.Delete
		case "test":
			return p.Add || p.Edit || p.Change
		}
		return false
	}
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	issue := func(plan, action, id string) string {
		token := auth.Random()
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.controlNonces == nil {
			a.controlNonces = map[string]controlNonce{}
		}
		for k, n := range a.controlNonces {
			if time.Now().After(n.Expires) {
				delete(a.controlNonces, k)
			}
		}
		if len(a.controlNonces) >= 1024 {
			return ""
		}
		a.controlNonces[auth.Digest(token)] = controlNonce{User: u.ID, Session: auth.Digest(cookie.Value), Node: node, Plan: plan, Action: "personal-" + action, OutboundID: id, Label: v.Name, Expires: time.Now().Add(2 * time.Minute)}
		return token
	}
	if v.Action == "test" {
		if o.ID == "" || !allowed("test") {
			fail(w, 403)
			return
		}
		out, status := a.hostControl(r.Context(), "outbound-test", map[string]string{"outbound": o.Tag})
		reply(w, status, out)
		return
	}
	if v.Action == "apply" {
		a.mu.Lock()
		n, ok := a.controlNonces[auth.Digest(v.Nonce)]
		delete(a.controlNonces, auth.Digest(v.Nonce))
		a.mu.Unlock()
		action := strings.TrimPrefix(n.Action, "personal-")
		o, e = a.DB.Outbound(n.OutboundID)
		if !ok || n.Node != node || n.User != u.ID || n.Session != auth.Digest(cookie.Value) || time.Now().After(n.Expires) || !strings.HasPrefix(n.Action, "personal-") || !allowed(action) || e != nil || u.Role != "admin" && o.Owner != u.ID {
			fail(w, 403)
			return
		}
		if action == "delete" {
			var refs int
			a.DB.QueryRow("SELECT count(*) FROM uuid_outbound_grants WHERE outbound_id=? AND user_id<>?", o.ID, u.ID).Scan(&refs)
			if refs > 0 {
				reply(w, 409, map[string]string{"error": "出站仍获授权，请先由管理员撤销共享授权"})
				return
			}
		}
		out, status := a.hostControl(r.Context(), "outbound-apply", map[string]string{"plan": n.Plan})
		delete(out, "tag")
		if status == 200 && action == "edit" {
			a.DB.Exec("UPDATE outbound_registry SET name=? WHERE id=?", n.Label, o.ID)
		}
		if status == 200 && action == "delete" {
			a.DB.Exec("DELETE FROM outbound_registry WHERE id=?", o.ID)
		}
		a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "personal_"+action+":"+http.StatusText(status))
		reply(w, status, out)
		return
	}
	action := v.Action
	if action != "create" && action != "edit" && action != "delete" || !allowed(action) || action != "create" && o.ID == "" || action == "create" && v.ID != "" {
		fail(w, 403)
		return
	}
	if action != "delete" && (strings.TrimSpace(v.Name) == "" || !validTag(v.Name) || v.Link == "") {
		fail(w, 422)
		return
	}
	// Editing a shared or referenced node is denied even to its creator.
	if action != "create" {
		var refs int
		a.DB.QueryRow("SELECT count(*) FROM uuid_outbound_grants WHERE outbound_id=? AND user_id<>?", o.ID, u.ID).Scan(&refs)
		if refs > 0 && u.Role != "admin" {
			fail(w, 403)
			return
		}
	}
	if action == "edit" && u.Role != "admin" {
		catalog, status := a.hostControl(r.Context(), "outbound-catalog", map[string]string{})
		if status != 200 {
			fail(w, 503)
			return
		}
		for _, x := range catalog["items"].([]any) {
			v := x.(map[string]any)
			if v["tag"] == o.Tag {
				if refs, ok := v["references"].([]any); ok && len(refs) > 0 {
					reply(w, 409, map[string]string{"error": "请先恢复所有引用此出站的 UUID，再编辑"})
					return
				}
			}
		}
	}
	hostAction := "save"
	if action == "delete" {
		hostAction = "delete"
	}
	out, status := a.hostControl(r.Context(), "outbound-preview", map[string]any{"action": hostAction, "outbound_node": control.OutboundNodeRequest{Tag: o.Tag, Link: v.Link}})
	if status != 200 {
		reply(w, status, out)
		return
	}
	tag, _ := out["tag"].(string)
	if action == "create" {
		o, e = a.DB.RegisterOutbound(server, tag, v.Name, u.ID)
		if e != nil {
			fail(w, 500)
			return
		}
		// Creation grants use only on this authorized UUID, never all of the owner's UUIDs.
		if _, e = a.DB.Exec("INSERT OR IGNORE INTO uuid_outbound_grants VALUES(?,?,?)", u.ID, node, o.ID); e != nil {
			fail(w, 500)
			return
		}
	}
	plan, _ := out["plan"].(string)
	delete(out, "plan")
	delete(out, "tag")
	out["nonce"] = issue(plan, action, o.ID)
	out["id"] = o.ID
	reply(w, status, out)
}
