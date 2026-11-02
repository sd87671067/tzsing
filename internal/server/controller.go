package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func (a *App) controlPermission(u store.User, action string) bool {
	if u.Disabled {
		return false
	}
	if u.Role != "admin" {
		if action == "restore" || action == "view" {
			return false
		}
		var n int
		a.DB.QueryRow("SELECT count(*) FROM user_operations WHERE user_id=? AND action=?", u.ID, action).Scan(&n)
		return n == 1
	}
	if action == "rename" {
		return true
	}
	var n int
	a.DB.QueryRow("SELECT count(*) FROM control_permissions WHERE user_id=? AND action=?", u.ID, action).Scan(&n)
	return n == 1
}
func (a *App) hostControl(ctx context.Context, path string, v any) (map[string]any, int) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", a.ControlSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 175 * time.Second}
	b, _ := json.Marshal(v)
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://controller/"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return map[string]any{"error": "受限控制服务暂不可用；请重新检查状态"}, 503
	}
	defer res.Body.Close()
	var out map[string]any
	if json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out) != nil {
		return map[string]any{"error": "控制响应无效"}, 502
	}
	return out, res.StatusCode
}
func (a *App) controlAPI(w http.ResponseWriter, r *http.Request, u store.User, path string) {
	if a.ControlSocket == "" {
		a.offlineControlAPI(w, r, u, path)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(180 * time.Second))
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	fresh, _, e := a.DB.Session(cookie.Value)
	if e != nil || fresh.Disabled {
		fail(w, 403)
		return
	}
	if !a.rate("control:"+auth.Digest(cookie.Value), 60) {
		fail(w, 429)
		return
	}
	var v struct {
		Node     string `json:"node_id"`
		Outbound string `json:"outbound"`
		Link     string `json:"link"`
		Nonce    string `json:"nonce"`
		Action   string `json:"action"`
		Profile  string `json:"profile"`
	}
	if path == "status" && r.Method == "GET" {
		v.Node = r.URL.Query().Get("node_id")
	} else if r.Method != "POST" {
		fail(w, 405)
		return
	} else if !read(w, r, &v) {
		return
	}
	server, tag, e := a.DB.Resolve(fresh, v.Node)
	if e != nil || server != a.ControlServer || (!strings.HasPrefix(tag, "inbound:") && !strings.HasPrefix(tag, "identity:")) {
		fail(w, 403)
		return
	}
	authID := ""
	if strings.HasPrefix(tag, "identity:") {
		current, ok := a.currentInbound(store.User{Role: "admin"}, v.Node)
		if !ok || !model.ValidAuthID(current.AuthID) || model.IdentityName(current.InboundTag, current.AuthID) != tag {
			fail(w, 403)
			return
		}
		tag, authID = current.InboundTag, current.AuthID
		if path != "status" && path != "share" && path != "preview" && path != "apply" && path != "restore-preview" && path != "restore" {
			fail(w, 403)
			return
		}
	} else {
		tag = strings.TrimPrefix(tag, "inbound:")
	}
	if fresh.Role != "admin" && authID == "" {
		fail(w, 403)
		return
	}
	actions := map[string]bool{}
	anyPermission := false
	for _, action := range []string{"change", "restore", "copy", "import_shadowrocket", "import_v2rayn", "view"} {
		actions[action] = a.controlPermission(fresh, action)
		anyPermission = anyPermission || actions[action]
	}
	if !anyPermission {
		fail(w, 403)
		return
	}
	issue := func(plan, action string) string {
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
		token := auth.Random()
		a.controlNonces[auth.Digest(token)] = controlNonce{Session: auth.Digest(cookie.Value), User: fresh.ID, Node: v.Node, Expires: time.Now().Add(2 * time.Minute), Plan: plan, Action: action, OutboundID: v.Outbound}
		return token
	}
	payload := map[string]string{"tag": tag}
	if authID != "" {
		payload["auth_id"] = authID
	}
	if path == "status" {
		out, status := a.hostControl(r.Context(), "status", payload)
		if status == 200 {
			if fresh.Role != "admin" && actions["change"] {
				items, err := a.selectableOutbounds(r.Context(), fresh, v.Node)
				if err != nil {
					fail(w, 503)
					return
				}
				out["outbounds"] = items

			}
			if fresh.Role != "admin" && !actions["change"] {
				out["outbounds"] = []any{}
			}
			out["delete"] = fresh.Role == "admin" && actions["change"] && out["delete"] == true
			out["actions"] = actions
			out["nonce"] = issue("", "")
			out["apply"] = out["apply"] == true && actions["change"]
			out["restore"] = out["restore"] == true && actions["restore"]
			if !actions["restore"] {
				out["restore_reason"] = "当前账号缺少独立恢复权限"
			}
			out["share"] = out["share"] == true && (actions["copy"] || actions["import_shadowrocket"] || actions["import_v2rayn"] || actions["view"])
		}
		reply(w, status, out)
		return
	}
	permission := ""
	switch path {
	case "preview", "apply":
		permission = "change"
	case "restore-preview", "restore":
		permission = "restore"
	case "share":
		switch v.Action {
		case "copy", "import_shadowrocket", "import_v2rayn", "view":
			permission = v.Action
		}
	}
	if permission == "" || !actions[permission] {
		fail(w, 403)
		return
	}
	a.mu.Lock()
	n, ok := a.controlNonces[auth.Digest(v.Nonce)]
	delete(a.controlNonces, auth.Digest(v.Nonce))
	a.mu.Unlock()
	if !ok || n.Session != auth.Digest(cookie.Value) || n.User != fresh.ID || n.Node != v.Node || time.Now().After(n.Expires) {
		fail(w, 409)
		return
	}
	// A normal user's request contains an opaque outbound ID, never a raw tag
	// or a credential-bearing link. Recheck the triple on both preview and apply.
	if fresh.Role != "admin" && (path == "preview" || path == "apply") {
		id := v.Outbound
		if path == "apply" {
			id = n.OutboundID
		}
		if v.Link != "" || v.Action != "" || !a.canSelectOutbound(r.Context(), fresh, v.Node, id) {
			fail(w, 403)
			return
		}
		o, err := a.DB.Outbound(id)
		if err != nil {
			fail(w, 403)
			return
		}
		v.Outbound = id
		payload["outbound"] = o.Tag
	}
	hostPath := path
	switch path {
	case "preview":
		if n.Plan != "" {
			fail(w, 409)
			return
		}
		payload["link"] = v.Link
		if fresh.Role == "admin" {
			payload["outbound"] = v.Outbound
		}
		if v.Action != "" {
			if fresh.Role != "admin" || (v.Action != "enable" && v.Action != "disable" && v.Action != "delete") {
				fail(w, 403)
				return
			}
			payload["action"] = v.Action
		}
	case "restore-preview":
		if n.Plan != "" {
			fail(w, 409)
			return
		}
	case "apply", "restore":
		if n.Plan == "" || n.Action != permission {
			fail(w, 409)
			return
		}
		payload["plan"] = n.Plan
		hostPath = "apply"
	case "share":
		if n.Plan != "" {
			fail(w, 409)
			return
		}
		payload["profile"] = v.Profile
		payload["label"] = "节点"
	}
	// Fail closed if auditing cannot be recorded before a sensitive operation.
	if _, e = a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), fresh.Name, "local", "control_"+path+":"+v.Node+":"+permission); e != nil {
		fail(w, 500)
		return
	}
	// Persist a conservative binding intent before production apply. A crash
	// leaves a restorable route record rather than an untracked privilege.
	if path == "apply" && fresh.Role != "admin" {
		if _, err := a.DB.Exec("INSERT INTO uuid_bindings VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET user_id=excluded.user_id,outbound_id=excluded.outbound_id", v.Node, fresh.ID, n.OutboundID); err != nil {
			fail(w, 500)
			return
		}
	}
	out, status := a.hostControl(r.Context(), hostPath, payload)
	if status == 200 && (path == "restore" || path == "apply" && fresh.Role == "admin") {
		a.DB.Exec("DELETE FROM uuid_bindings WHERE node_id=?", v.Node)
	}
	if status == 200 && fresh.Role != "admin" && path == "preview" {
		// Host preview is for an authorized node, but its internal tag is private.
		out["preview"] = map[string]string{"protocol": "授权出站", "server": "已授权节点"}
	}

	if status == 200 && (path == "preview" || path == "restore-preview") {
		plan, _ := out["plan"].(string)
		delete(out, "plan")
		if plan == "" {
			fail(w, 502)
			return
		}
		out["nonce"] = issue(plan, permission)
	}
	if path == "share" && status == 200 {
		latest, _, err := a.DB.Session(cookie.Value)
		_, _, resolveErr := a.DB.Resolve(latest, v.Node)
		if err != nil || resolveErr != nil || !a.controlPermission(latest, permission) {
			fail(w, 403)
			return
		}
	}
	event := "success"
	if status != 200 {
		event = "failed"
	}
	a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), fresh.Name, "local", "control_"+path+"_"+event+":"+v.Node)
	reply(w, status, out)
}
