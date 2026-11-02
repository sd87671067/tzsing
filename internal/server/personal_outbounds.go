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
	if u.Disabled || u.Role != "admin" && !a.controlPermission(u, "change") {
		fail(w, 403)
		return
	}
	if r.Method == "GET" {
		items, e := a.syncOutbounds(r.Context())
		if e != nil {
			fail(w, 503)
			return
		}
		visible := []store.Outbound{}
		for _, o := range items {
			if u.Role == "admin" || o.Owner == u.ID {
				visible = append(visible, o)
			}
		}
		reply(w, 200, map[string]any{"items": visible})
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
		if o.ID == "" {
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
		if !ok || n.Node != node || n.User != u.ID || n.Session != auth.Digest(cookie.Value) || time.Now().After(n.Expires) || !strings.HasPrefix(n.Action, "personal-") || e != nil || u.Role != "admin" && o.Owner != u.ID {
			fail(w, 403)
			return
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
	if action != "create" && action != "edit" && action != "delete" || action != "create" && o.ID == "" || action == "create" && v.ID != "" {
		fail(w, 403)
		return
	}
	if action != "delete" && (strings.TrimSpace(v.Name) == "" || !validTag(v.Name) || v.Link == "") {
		fail(w, 422)
		return
	}
	if action == "edit" || action == "delete" {
		catalog, status := a.hostControl(r.Context(), "outbound-catalog", map[string]string{})
		if status != 200 {
			fail(w, 503)
			return
		}
		for _, x := range catalog["items"].([]any) {
			v := x.(map[string]any)
			if v["tag"] == o.Tag {
				if refs, ok := v["references"].([]any); ok && len(refs) > 0 {
					reply(w, 409, map[string]string{"error": "出站正在使用，请先将引用它的 UUID 更换到其他出站，并解除链式引用后再编辑或删除"})
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

	}
	plan, _ := out["plan"].(string)
	delete(out, "plan")
	delete(out, "tag")
	out["nonce"] = issue(plan, action, o.ID)
	out["id"] = o.ID
	reply(w, status, out)
}
