package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"tzsingbox/internal/model"
)

type Proxy struct {
	Tag      string `json:"tag"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Mode     string `json:"mode"`
	Eligible bool   `json:"eligible"`
}
type Detector struct {
	mu      sync.RWMutex
	cache   map[string]model.Exit
	proxies []Proxy
}

func New() *Detector { return &Detector{cache: map[string]model.Exit{}} }
func (d *Detector) Get(tag string) *model.Exit {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.cache[tag]
	if !ok {
		return nil
	}
	active := false
	for _, p := range d.proxies {
		if p.Tag == tag && p.Eligible {
			active = true
			break
		}
	}
	if !active {
		v.Error = "路径映射待重新验证"
	}
	return &v
}
func (d *Detector) SetProxies(ps []Proxy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.proxies = append([]Proxy(nil), ps...)
}
func (d *Detector) Run(ctx context.Context, ps []Proxy, interval time.Duration) {
	next := map[string]time.Time{}
	failures := map[string]int{}
	for {
		d.mu.RLock()
		ps = append([]Proxy(nil), d.proxies...)
		d.mu.RUnlock()
		for _, p := range ps {
			if !p.Eligible || time.Now().Before(next[p.Tag]) {
				continue
			}
			v := detect(ctx, p)
			delay := interval
			if v.Error != "" {
				failures[p.Tag]++
				delay = time.Duration(min(300, 30*(1<<min(failures[p.Tag], 3)))) * time.Second
			} else {
				failures[p.Tag] = 0
			}
			next[p.Tag] = time.Now().Add(delay)
			d.mu.Lock()
			if old, ok := d.cache[p.Tag]; ok && v.Error != "" && old.Verified {
				old.Error = v.Error
				old.Attempted = v.Attempted
				v = old
			}
			d.cache[p.Tag] = v
			d.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func detect(ctx context.Context, p Proxy) model.Exit {
	v := model.Exit{Attempted: time.Now().Unix()}
	var dial func(context.Context, string, string) (net.Conn, error)
	if p.Mode == "direct" {
		v.Source = "ipify · 直连拨号"
		v.Path = "direct"
		dial = (&net.Dialer{Timeout: 8 * time.Second}).DialContext
	} else if p.Mode == "singbox_route" {
		v.Source = "ipify · sing-box 指定实际出站"
		v.Path = "singbox_route"
		dialer, e := proxy.SOCKS5("tcp", net.JoinHostPort(p.Server, strconv.Itoa(p.Port)), &proxy.Auth{User: p.Username, Password: p.Password}, &net.Dialer{Timeout: 8 * time.Second})
		if e != nil {
			v.Error = "探针不可用"
			return v
		}
		cd, ok := dialer.(proxy.ContextDialer)
		if !ok {
			v.Error = "探针不支持超时"
			return v
		}
		dial = cd.DialContext
	} else {
		v.Error = "尚未配置经过实际出站的探针"
		return v
	}
	tr := &http.Transport{DialContext: dial, TLSHandshakeTimeout: 8 * time.Second, DisableKeepAlives: true, Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 16 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(url string, out any) error {
		req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
		if e != nil {
			return e
		}
		res, e := client.Do(req)
		if e != nil {
			return fmt.Errorf("probe failed")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("probe status")
		}
		return json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(out)
	}
	var a struct {
		IP string `json:"ip"`
	}
	if get("https://api.ipify.org?format=json", &a) == nil && net.ParseIP(a.IP).To4() != nil {
		v.IPv4 = a.IP
	}
	a.IP = ""
	if get("https://api6.ipify.org?format=json", &a) == nil {
		ip := net.ParseIP(a.IP)
		if ip != nil && ip.To4() == nil {
			v.IPv6 = a.IP
		}
	}
	ip := v.IPv4
	if ip == "" {
		ip = v.IPv6
	}
	if ip == "" {
		v.Error = "出口检测暂不可用"
		return v
	}
	v.Verified = true
	v.Updated = time.Now().Unix()
	metadata.enrich(ctx, client, ip, &v)
	return v
}
