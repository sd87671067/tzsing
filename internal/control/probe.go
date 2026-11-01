package control

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"tzsingbox/internal/auth"
)

func public(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}
func pinPublic(o map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip", text(o["server"]))
	if e != nil || len(ips) == 0 {
		return nil, errors.New("目标地址解析失败；未证明连接可用")
	}
	for _, ip := range ips {
		if !public(ip) {
			return nil, errors.New("不允许将管理地址、内网或回环地址设为外部出站")
		}
	}
	pinned := map[string]any{}
	for k, v := range o {
		pinned[k] = v
	}
	if tls := object(pinned["tls"]); tls["enabled"] == true && text(tls["server_name"]) == "" && net.ParseIP(text(o["server"])) == nil {
		tls = object(candidateMap(canonical(o))["tls"])
		tls["server_name"] = o["server"]
		pinned["tls"] = tls
	}
	pinned["server"] = ips[0].String()
	return pinned, nil
}
func (c *Controller) probe(o map[string]any) error {
	if c.Hooks != nil && c.Hooks.Probe != nil {
		return c.Hooks.Probe(o)
	}
	raw, e := os.ReadFile(c.Config.Config)
	if e != nil {
		return e
	}
	config := candidateMap(raw)
	selections, e := c.liveSelections(config, o)
	if e != nil {
		return e
	}
	outs, e := probeGraph(config, o, selections)
	if e != nil {
		return e
	}
	if e = c.probeGraphClient(outs, text(o["tag"]), config); e != nil {
		return e
	}
	after, e := c.liveSelections(config, o)
	if e != nil {
		return e
	}
	beforeJSON, _ := json.Marshal(selections)
	afterJSON, _ := json.Marshal(after)
	if string(beforeJSON) != string(afterJSON) {
		c.lastIP = ""
		return errors.New("动态成员在检测期间变化，请重新检测")
	}
	return nil
}

func (c *Controller) probeClient(o map[string]any) error {
	out := candidateMap(canonical(o))
	out["tag"] = "probe-out"
	return c.probeGraphClient([]any{out}, "probe-out", nil)
}
func (c *Controller) probeGraphClient(outs []any, final string, source map[string]any) error {
	dir, e := os.MkdirTemp(c.Config.State, "probe-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	secret := auth.Random()
	conf := map[string]any{"log": map[string]any{"level": "error", "timestamp": false}, "inbounds": []any{map[string]any{"type": "socks", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "probe", "password": secret}}}}, "outbounds": outs, "route": map[string]any{"final": final}}
	if source != nil {
		if dns, ok := source["dns"]; ok {
			conf["dns"] = dns
		}
		for _, k := range []string{"default_domain_resolver", "auto_detect_interface", "default_interface", "default_mark"} {
			if v, ok := object(source["route"])[k]; ok {
				object(conf["route"])[k] = v
			}
		}
	}

	if e = atomicFile(filepath.Join(dir, "config.json"), canonical(conf), 0600); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 42*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Config.Binary, "run", "-c", filepath.Join(dir, "config.json"))
	cmd.Dir = dir
	diagnostic := new(probeLog)
	cmd.Stderr = diagnostic
	cmd.Stdout = diagnostic
	// Child probes must never inherit the production policy ledger.
	cmd.Env = append(os.Environ(), "TZSING_POLICY_DB=")
	if cmd.Start() != nil {
		return errors.New("隔离探测实例启动失败")
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	until := time.Now().Add(3 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(until) {
			return errors.New("隔离探测未就绪：" + diagnostic.reason())
		}
		time.Sleep(50 * time.Millisecond)
	}
	d, e := proxy.SOCKS5("tcp", address, &proxy.Auth{User: "probe", Password: secret}, &net.Dialer{Timeout: 8 * time.Second})
	if e != nil {
		return errors.New("隔离探测不可用")
	}
	transport := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext, TLSHandshakeTimeout: 12 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 18 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var v struct {
		IP string `json:"ip"`
	}
	var last error
	for _, endpoint := range []string{"https://api.ip.cc", "https://api.ipify.org?format=json"} {
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		res, err := client.Do(req)
		if err != nil {
			diagnostic.Write([]byte(err.Error()))
			last = errors.New(diagnostic.reason())
			continue
		}
		v.IP = ""
		err = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&v)
		res.Body.Close()
		if res.StatusCode == 200 && err == nil && public(net.ParseIP(v.IP)) {
			last = nil
			break
		}
		last = errors.New("HTTPS 目标未返回有效公网出口 IP")
	}
	if last != nil {
		return last
	}

	c.lastIP = v.IP
	return nil
}
func supportsNode(in map[string]any) bool {
	typ := text(in["type"])
	return typ == "shadowsocks" || (typ == "vless" && object(object(in["tls"])["reality"])["enabled"] == true && len(array(in["users"])) > 0 && len(object(in["transport"])) == 0)
}
func (c *Controller) probeNode(config map[string]any, tag string) error {
	if c.Hooks != nil && c.Hooks.Probe != nil {
		return nil
	}
	in := findInbound(config, tag)
	typ := text(in["type"])
	host := text(in["listen"])
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	o := map[string]any{"type": typ, "tag": "target", "server": host, "server_port": in["listen_port"]}
	if typ == "shadowsocks" {
		o["method"] = in["method"]
		o["password"] = in["password"]
		return c.probeClient(o)
	}
	if typ != "vless" {
		return errors.New("该入站协议尚未完成实际路径校验，禁止写入")
	}
	users := array(in["users"])
	if len(users) == 0 {
		return ErrScope
	}
	user := object(users[0])
	o["uuid"] = user["uuid"]
	if flow := text(user["flow"]); flow != "" {
		o["flow"] = flow
	}
	source := object(in["tls"])
	reality := object(source["reality"])
	if reality["enabled"] != true {
		return errors.New("该入站 TLS 形式尚未完成路径校验")
	}
	b, e := base64.RawURLEncoding.DecodeString(text(reality["private_key"]))
	if e != nil {
		return ErrScope
	}
	key, e := ecdh.X25519().NewPrivateKey(b)
	if e != nil {
		return ErrScope
	}
	sid := ""
	if ids := array(reality["short_id"]); len(ids) > 0 {
		sid = text(ids[0])
	}
	o["tls"] = map[string]any{"enabled": true, "server_name": source["server_name"], "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "short_id": sid}}
	return c.probeClient(o)
}
