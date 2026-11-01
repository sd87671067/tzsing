package control

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
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
	key := r.URL.Path + ":" + v.Tag + ":" + v.Source
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
			t, e = clash.InboundPath(v.Tag)
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
		if observed, ok := c.inspectExits[v.Tag]; ok && observed.hash == digest(raw) && time.Since(observed.at) < 5*time.Minute {
			expected = observed.ipv4
			if expected == "" {
				expected = observed.ipv6
			}
		}
		out := egress.LookupSource(ctx, path, v.Source, expected, digest(raw)+"@"+t.Egress)
		// Never attach a result to a config which changed while the request ran.
		latest, e := os.ReadFile(c.Config.Config)
		if e != nil || digest(latest) != digest(raw) {
			send(200, egress.SourceResult{Source: v.Source, Message: "检测期间路由已变化，请重新检测"})
			return
		}
		send(200, out)
		return
	}
	if e := c.check(raw); e == nil {
		result.Config = egress.Check{Status: "ok", Detail: "当前 sing-box 配置通过只读 check 校验"}
	} else {
		result.Config = egress.Check{Status: "error", Detail: "当前配置未通过只读校验"}
	}
	port, _ := in["listen_port"].(float64)
	host := text(in["listen"])
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	typ := text(in["type"])
	if port > 0 && port <= 65535 && typ != "hysteria" && typ != "hysteria2" && typ != "tuic" && localAddress(host) {
		start := time.Now()
		conn, e := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if e == nil {
			conn.Close()
			result.Listen = egress.Check{Status: "ok", Detail: "配置的本机 TCP 端口接受连接；不代表公网可达", Milliseconds: time.Since(start).Milliseconds()}
		} else {
			result.Listen = egress.Check{Status: "error", Detail: "配置的本机 TCP 端口未接受连接"}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				result.Listen.Status = "timeout"
			}
		}
	}
	if result.Config.Status == "ok" && result.Listen.Status == "ok" && supportsNode(in) {
		start := time.Now()
		e := c.probeNode(config, v.Tag)
		if e == nil {
			result.Handshake = egress.Check{Status: "ok", Detail: "使用配置内测试凭据完成真实协议握手及 HTTPS 请求；仅代表所测凭据", Milliseconds: time.Since(start).Milliseconds()}
		} else {
			result.Handshake = egress.Check{Status: "unverified", Detail: "测试凭据的协议与 HTTPS 联合请求未完成；可能受用户路由、凭据或上游限制，不能据此判定所有用户异常", Milliseconds: time.Since(start).Milliseconds()}
		}
	}
	if validPath {
		network := egress.CheckPath(ctx, path)
		result.Network = &network
		if network.Successes > 0 {
			if c.inspectExits == nil {
				c.inspectExits = map[string]observedExit{}
			}
			if len(c.inspectExits) >= 512 {
				for k := range c.inspectExits {
					delete(c.inspectExits, k)
					break
				}
			}
			c.inspectExits[v.Tag] = observedExit{hash: digest(raw), at: time.Now(), ipv4: network.IPv4.IP, ipv6: network.IPv6.IP}
		}
		if network.Successes == 0 {
			result.Path.Status = "error"
			result.Path.Detail = "指定路径未完成固定目标 HTTPS 请求"
			if network.IPv4.Status == "timeout" || network.IPv6.Status == "timeout" {
				result.Path.Status = "timeout"
			}
		}
		pairs := [][2]string{{v.PreviousIPv4, network.IPv4.IP}, {v.PreviousIPv6, network.IPv6.IP}}
		compared, changed := false, false
		for _, pair := range pairs {
			if pair[0] != "" && pair[1] != "" {
				compared = true
				changed = changed || pair[0] != pair[1]
			}
		}
		if compared {
			result.Change = egress.Check{Status: "ok", Detail: "与已有缓存的同地址族出口一致"}
			if changed {
				result.Change = egress.Check{Status: "ok", Detail: "检测到出口 IP 变化；来源信息需按新 IP 重新查询"}
			}
		}
	}
	latest, e := os.ReadFile(c.Config.Config)
	if e != nil || digest(latest) != digest(raw) {
		result.Path = egress.Check{Status: "unknown", Detail: "检测期间配置已变化，结果不再代表当前路径"}
		result.Network = nil
		result.Outbound = ""
	}
	send(200, result)
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
