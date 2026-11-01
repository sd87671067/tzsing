package server

import (
	"context"
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
		Node   string `json:"node_id"`
		Action string `json:"action"`
		Source string `json:"source"`
	}
	if !read(w, r, &v) {
		return
	}
	if (v.Action != "diagnostics" && v.Action != "intel") || (v.Action == "intel" && v.Source != "ipinfo" && v.Source != "ippure") {
		fail(w, 400)
		return
	}
	server, tag, e := a.DB.Resolve(u, v.Node)
	if e == nil && strings.HasPrefix(tag, "identity:") {
		if _, ok := a.currentInbound(u, v.Node); !ok {
			fail(w, 403)
			return
		}
		reply(w, 200, map[string]any{"source": v.Source, "message": "当前数据源无法确认该认证身份的独立路径或流量；请查看入站未归属流量。", "at": time.Now().Unix()})
		return
	}
	if e != nil || !strings.HasPrefix(tag, "inbound:") {
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
	payload := map[string]string{"tag": strings.TrimPrefix(tag, "inbound:"), "source": v.Source}
	if t.IP != nil && t.IP.Verified {
		payload["previous_ipv4"] = t.IP.IPv4
		payload["previous_ipv6"] = t.IP.IPv6
	}
	// Network checks have their own bounded budget without changing normal API timeouts.
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(60 * time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
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
	if latest.RouteVersion != t.RouteVersion {
		reply(w, 409, map[string]string{"error": "路由已变化，请重新检测"})
		return
	}
	if fresh.Role != "admin" && a.DB.Setting("show_raw_tag", 0) == 0 {
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
