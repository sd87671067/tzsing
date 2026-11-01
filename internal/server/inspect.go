package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
	"tzsingbox/internal/model"
	"tzsingbox/internal/store"
)

func (a *App) inspectNode(w http.ResponseWriter, r *http.Request, u store.User) {
	if r.Method != "POST" {
		fail(w, 405)
		return
	}
	var v struct {
		Node      string `json:"node_id"`
		Action    string `json:"action"`
		Source    string `json:"source"`
		PathIndex int    `json:"path_index,omitempty"`
	}
	if !read(w, r, &v) {
		return
	}
	if (v.Action != "diagnostics" && v.Action != "intel") || (v.Action == "intel" && v.Source != "ipinfo" && v.Source != "ippure") {
		fail(w, 400)
		return
	}
	server, tag, e := a.DB.Resolve(u, v.Node)
	if e != nil || (!strings.HasPrefix(tag, "inbound:") && !strings.HasPrefix(tag, "identity:")) {
		fail(w, 403)
		return
	}
	if a.ControlSocket == "" || server != a.ControlServer {
		reply(w, 503, map[string]string{"error": "该服务器尚未提供受控检测通道"})
		return
	}
	t, ok := a.currentInbound(u, v.Node)
	if !ok {
		fail(w, 403)
		return
	}
	limit := 12
	if v.Action == "intel" {
		limit = 30
	}
	if !a.rate("inspect:"+strconv.FormatInt(u.ID, 10)+":"+v.Action, limit) || !a.rate("inspect:global", 90) {
		fail(w, 429)
		return
	}
	if _, err := a.DB.Exec("INSERT INTO audit(at,name,ip,event) VALUES(?,?,?,?)", time.Now().Unix(), u.Name, "local", "node_inspect_"+v.Action+":"+v.Node); err != nil {
		fail(w, 500)
		return
	}
	routePaths := t.Egresses
	payload := map[string]string{"tag": strings.TrimPrefix(tag, "inbound:"), "source": v.Source, "route_version": t.RouteVersion}
	if strings.HasPrefix(tag, "identity:") {
		// Resolve permission with the caller first; raw route identity is server-owned.
		raw, exists := a.currentInbound(store.User{Role: "admin"}, v.Node)
		if !exists || raw.AuthID == "" {
			fail(w, 403)
			return
		}
		if v.PathIndex < 0 || v.PathIndex >= len(raw.Egresses) {
			reply(w, 422, map[string]string{"error": "无法指定实际出站"})
			return
		}
		routePaths = raw.Egresses
		path := raw.Egresses[v.PathIndex]
		payload["tag"] = raw.InboundTag
		payload["auth_id"] = raw.AuthID
		payload["outbound"] = path.Tag
		payload["route_version"] = raw.RouteVersion
		t.IP = path.IP
	}
	if t.IP != nil && t.IP.Verified {
		payload["previous_ipv4"] = t.IP.IPv4
		payload["previous_ipv6"] = t.IP.IPv6
	}
	// Network checks have their own bounded budget without changing normal API timeouts.
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
	defer cancel()
	out, status := a.hostControl(ctx, v.Action, payload)
	// Permission and current identity are rechecked after potentially slow network
	// work. Revocation must also take effect for in-flight requests.
	cookie, e := r.Cookie("tz_session")
	if e != nil {
		fail(w, 401)
		return
	}
	fresh, _, e := a.DB.Session(cookie.Value)
	if e != nil {
		fail(w, 401)
		return
	}
	latest, ok := a.currentInbound(fresh, v.Node)
	if !ok {
		fail(w, 403)
		return
	}
	latestPaths := latest.Egresses
	if strings.HasPrefix(tag, "identity:") {
		raw, exists := a.currentInbound(store.User{Role: "admin"}, v.Node)
		if !exists {
			fail(w, 403)
			return
		}
		latestPaths = raw.Egresses
	}
	if latest.RouteVersion != t.RouteVersion || !samePaths(latestPaths, routePaths) {
		reply(w, 409, map[string]string{"error": "路由已变化，请重新检测"})
		return
	}

	if v.Action == "diagnostics" {
		outbound := payload["outbound"]
		if outbound == "" {
			outbound = t.Egress
		}
		var ip model.Exit
		if status == 200 {
			b, _ := json.Marshal(out["ip"])
			json.Unmarshal(b, &ip)
		} else {
			for _, p := range routePaths {
				if p.Tag == outbound && p.IP != nil {
					ip = *p.IP
				}
			}
			if ip.Verified {
				ip.Error = "上次检测失败，显示缓存"
				ip.Attempted = time.Now().Unix()
			}
		}
		if ip.Verified && outbound != "" && ip.Path == outbound+"@"+t.RouteVersion {
			b, _ := json.Marshal(ip)
			_, err := a.DB.Exec("INSERT INTO exit_cache(server,tag,data) VALUES(?,?,?) ON CONFLICT(server,tag) DO UPDATE SET data=excluded.data", server, tag+"|egress:"+outbound, b)
			if err != nil {
				fail(w, 500)
				return
			}
		}
	}

	if fresh.Role != "admin" && a.DB.Setting("show_raw_tag", 0) == 0 {
		if ip, ok := out["ip"].(map[string]any); ok {
			delete(ip, "path")
		}
		if raw, ok := out["outbound"].(string); ok && raw != "" {
			out["outbound"] = "关联出口（Tag 未公开）"
			if path, ok := out["path"].(map[string]any); ok {
				if detail, ok := path["detail"].(string); ok {
					path["detail"] = strings.ReplaceAll(detail, raw, "关联出口")
				}
			}
		}
	}
	reply(w, status, out)
}
func (a *App) currentInbound(u store.User, id string) (model.Tag, bool) {
	views, e := a.DB.Views(u)
	if e != nil {
		return model.Tag{}, false
	}
	for _, v := range views {
		for _, t := range v.Report.Tags {
			if t.ID == id && t.Identity == "inbound" {
				return t, true
			}
		}
	}
	return model.Tag{}, false
}

func samePaths(a, b []model.EgressPath) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Tag != b[i].Tag || a[i].Type != b[i].Type {
			return false
		}
	}
	return true
}
