package control

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"time"
	"tzsingbox/internal/adapter"
	"tzsingbox/internal/agent"
	"tzsingbox/internal/egress"
	"tzsingbox/internal/model"
)

type observedExit struct {
	hash       string
	at         time.Time
	ipv4, ipv6 string
}
type diagnostics struct {
	At        int64              `json:"at"`
	Protocol  string             `json:"protocol"`
	Outbound  string             `json:"outbound,omitempty"`
	Config    egress.Check       `json:"config"`
	Listen    egress.Check       `json:"listen"`
	Handshake egress.Check       `json:"handshake"`
	Public    egress.Check       `json:"public"`
	Path      egress.Check       `json:"path"`
	Network   *egress.PathResult `json:"network,omitempty"`
	Change    egress.Check       `json:"change"`
}

func (c *Controller) inspect(w http.ResponseWriter, r *http.Request, v serviceRequest) {
	send := func(status int, x any) { w.WriteHeader(status); json.NewEncoder(w).Encode(x) }
	fail := func(status int, msg string) { send(status, map[string]string{"error": msg}) }
	if r.URL.Path == "/intel" && v.Source != "ipinfo" && v.Source != "ippure" {
		fail(400, "不支持的数据源")
		return
	}
	now := time.Now()
	key := r.URL.Path + ":" + v.Tag + ":" + v.AuthID + ":" + v.Outbound + ":" + v.Source
	if c.inspectLast == nil {
		c.inspectLast = map[string]time.Time{}
	}
	interval := 5 * time.Second
	if r.URL.Path == "/diagnostics" {
		interval = 30 * time.Second
	}
	if now.Sub(c.inspectLast[key]) < interval {
		fail(429, "检测过于频繁，请稍后重试")
		return
	}
	if len(c.inspectLast) > 2048 {
		for k, t := range c.inspectLast {
			if now.Sub(t) > time.Minute {
				delete(c.inspectLast, k)
			}
		}
		if len(c.inspectLast) > 2048 {
			fail(429, "检测繁忙")
			return
		}
	}
	c.inspectLast[key] = now
	raw, err := os.ReadFile(c.Config.Config)
	var config map[string]any
	if err != nil || len(raw) > 4<<20 || json.Unmarshal(raw, &config) != nil {
		fail(503, "配置暂不可用")
		return
	}
	in := findInbound(config, v.Tag)
	if in == nil {
		fail(403, "入站已不存在")
		return
	}
	result := diagnostics{At: now.Unix(), Protocol: text(in["type"]), Config: egress.Check{Status: "unverified", Detail: "尚未校验"}, Listen: egress.Check{Status: "unverified", Detail: "该入站没有可验证的本机 TCP 监听"}, Handshake: egress.Check{Status: "unverified", Detail: "该协议或认证配置尚不支持受控握手"}, Public: egress.Check{Status: "unverified", Detail: "本机监听及本机握手不能证明公网可达；未执行外部网络探测"}, Path: egress.Check{Status: "unknown", Detail: "当前路径未知"}, Change: egress.Check{Status: "unverified", Detail: "暂无可比较的实际出口"}}
	acpath := c.Config.AgentConfig
	if acpath == "" {
		acpath = "/etc/tzsingbox/agent.json"
	}
	var ac agent.Config
	ab, ae := os.ReadFile(acpath)
	var t model.Tag
	var path egress.Proxy
	validPath := false
	if ae == nil && len(ab) < 256<<10 && json.Unmarshal(ab, &ac) == nil {
		inv, e := adapter.ReadInventory(ac.InventoryFile)
		if e == nil && inv.ConfigHash == digest(raw) {
			clash := adapter.New(ac.ClashURL, ac.ClashSecret)
			clash.SetInventory(inv)
			if v.AuthID != "" {
				t, e = clash.IdentityPath(v.Tag, v.AuthID, v.Outbound, v.RouteVersion)
			} else {
				t, e = clash.InboundPath(v.Tag)
			}
			if e == nil && t.Egress != "" {
				result.Outbound = t.Egress
				result.Path = egress.Check{Status: "unverified", Detail: "关联出站 " + t.Egress + "，探针路径尚未核实"}
				if inv.RoutesVerified {
					for _, p := range ac.Proxies {
						if p.Tag == t.Egress && p.Eligible && p.Mode == "singbox_route" && net.ParseIP(p.Server).IsLoopback() && p.Port > 0 && p.Port <= 65535 {
							path = p
							validPath = true
							result.Path = egress.Check{Status: "ok", Detail: "通过已核实的专用 SOCKS 路径检测出站 " + t.Egress}
							break
						}
					}
				}
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if r.URL.Path == "/intel" {
		if !validPath {
			send(200, egress.SourceResult{Source: v.Source, Message: "当前路径未知或路径证明已失效，无法查询此入站出口"})
			return
		}
		expected := v.PreviousIPv4
		if expected == "" {
			expected = v.PreviousIPv6
		}
		if observed, ok := c.inspectExits[v.Tag+":"+v.AuthID+":"+v.Outbound]; ok && observed.hash == digest(raw) && time.Since(observed.at) < 5*time.Minute {
			expected = observed.ipv4
			if expected == "" {
				expected = observed.ipv6
			}
		}
		out := egress.LookupSource(ctx, path, v.Source, expected, digest(raw)+"@"+t.Egress)
		// Never attach a result to a config which changed while the request ran.
		if v.AuthID != "" && validPath {
			clash := adapter.New(ac.ClashURL, ac.ClashSecret)
			inv, e := adapter.ReadInventory(ac.InventoryFile)
			if e != nil {
				validPath = false
			} else {
				clash.SetInventory(inv)
				_, e = clash.IdentityPath(v.Tag, v.AuthID, v.Outbound, v.RouteVersion)
				validPath = e == nil
			}
		}
		latest, e := os.ReadFile(c.Config.Config)
		if e != nil || digest(latest) != digest(raw) || (v.AuthID != "" && !validPath) {
			send(200, egress.SourceResult{Source: v.Source, Message: "检测期间路由已变化，请重新检测"})
			return
		}
		send(200, out)
		return
	}

	if !validPath {
		fail(422, "无法指定该节点的实际出站")
		return
	}
	network := egress.CheckPath(ctx, path)
	latest, e := os.ReadFile(c.Config.Config)
	if e != nil || digest(latest) != digest(raw) {
		fail(409, "路由已变化，请重新检测")
		return
	}
	// Recheck selector resolution after network work, never trust a stale proof.
	if v.AuthID != "" {
		inv, e := adapter.ReadInventory(ac.InventoryFile)
		if e != nil {
			fail(409, "路径证明已失效")
			return
		}
		clash := adapter.New(ac.ClashURL, ac.ClashSecret)
		clash.SetInventory(inv)
		if _, e = clash.IdentityPath(v.Tag, v.AuthID, v.Outbound, v.RouteVersion); e != nil {
			fail(409, "路由已变化，请重新检测")
			return
		}
	}
	if network.Successes == 0 {
		c.audit("exit_http_failed", v.Tag)
		fail(502, "出口 HTTPS 检测失败，保留上次缓存")
		return
	}
	if c.inspectExits == nil {
		c.inspectExits = map[string]observedExit{}
	}
	if len(c.inspectExits) >= 512 {
		for k := range c.inspectExits {
			delete(c.inspectExits, k)
			break
		}
	}
	c.inspectExits[v.Tag+":"+v.AuthID+":"+v.Outbound] = observedExit{hash: digest(raw), at: time.Now(), ipv4: network.IPv4.IP, ipv6: network.IPv6.IP}
	ip := model.Exit{IPv4: network.IPv4.IP, IPv6: network.IPv6.IP, Verified: true, Updated: time.Now().Unix(), Attempted: time.Now().Unix(), Source: "指定出站 HTTPS", Path: t.Egress + "@" + v.RouteVersion}
	expected := ip.IPv4
	if expected == "" {
		expected = ip.IPv6
	}
	info := egress.LookupSource(ctx, path, "ipinfo", expected, digest(raw)+"@"+t.Egress)
	if info.Data != nil {
		geo := *info.Data
		geo.IPv4 = ip.IPv4
		geo.IPv6 = ip.IPv6
		geo.Verified = true
		geo.Updated = ip.Updated
		geo.Attempted = ip.Attempted
		geo.Source = ip.Source
		geo.Path = ip.Path
		ip = geo
	}
	// Metadata lookup also uses the path; a config change invalidates its result.
	latest, e = os.ReadFile(c.Config.Config)
	if e != nil || digest(latest) != digest(raw) {
		fail(409, "路由已变化，请重新检测")
		return
	}
	c.audit("exit_http_success", v.Tag)
	send(200, map[string]any{"at": ip.Updated, "outbound": t.Egress, "network": network, "ip": ip})
}

func localAddress(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addresses, _ := net.InterfaceAddrs()
	for _, a := range addresses {
		p, _, e := net.ParseCIDR(a.String())
		if e == nil && p.Equal(ip) {
			return true
		}
	}
	return false
}
