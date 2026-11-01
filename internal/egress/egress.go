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
	scope   string
	mu      sync.RWMutex
	cache   map[string]model.Exit
	proxies []Proxy
}

func New() *Detector { return &Detector{cache: map[string]model.Exit{}} }

// SetScope invalidates every proof when configuration or runtime selection changes.
func (d *Detector) SetScope(scope string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.scope != scope {
		d.scope = scope
		d.cache = map[string]model.Exit{}
	}
}
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
	for _, old := range d.proxies {
		same := false
		for _, p := range ps {
			if old == p {
				same = true
				break
			}
		}
		if !same {
			delete(d.cache, old.Tag)
		}
	}
	d.proxies = append([]Proxy(nil), ps...)
}
func (d *Detector) Run(ctx context.Context, ps []Proxy, interval time.Duration) {
	next := map[string]time.Time{}
	failures := map[string]int{}
	previousScope := ""
	previousProxies := map[string]Proxy{}
	for {
		d.mu.RLock()
		ps = append([]Proxy(nil), d.proxies...)
		scope := d.scope
		d.mu.RUnlock()
		if previousScope != scope {
			next = map[string]time.Time{}
			previousScope = scope
		}
		for _, p := range ps {
			if old, ok := previousProxies[p.Tag]; !ok || old != p {
				delete(next, p.Tag)
				delete(failures, p.Tag)
				previousProxies[p.Tag] = p
			}
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
			current := false
			for _, candidate := range d.proxies {
				if candidate == p && candidate.Eligible {
					current = true
				}
			}
			if scope != d.scope || !current {
				d.mu.Unlock()
				continue
			}
			if old, ok := d.cache[p.Tag]; ok && v.Error != "" && old.Verified {
				old.Error = v.Error
				old.Attempted = v.Attempted
				v = old
			}
			d.cache[p.Tag] = v
			d.mu.Unlock()
			if v.Verified && v.Error == "" {
				go d.enrich(ctx, p, scope, v)
			}
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
	client, closeClient, err := PathClient(p)
	if err != nil {
		v.Error = "尚未配置经过实际出站的探针"
		return v
	}
	defer closeClient()
	v.Source = "ipify · sing-box 指定实际出站"
	if p.Mode == "direct" {
		v.Source = "ipify · 直连拨号"
	}
	v.Path = p.Mode
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
	if get("https://api.ipify.org?format=json", &a) == nil && publicIP(a.IP) && net.ParseIP(a.IP).To4() != nil {
		v.IPv4 = a.IP
	}
	a.IP = ""
	if get("https://api6.ipify.org?format=json", &a) == nil {
		ip := net.ParseIP(a.IP)
		if publicIP(a.IP) && ip.To4() == nil {
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
	return v
}

// PathClient is shared by scheduled exit discovery and controlled interactive
// diagnostics. A caller supplies only a server-owned, attested proxy mapping.
func PathClient(p Proxy) (*http.Client, func(), error) {
	var dial func(context.Context, string, string) (net.Conn, error)
	if p.Mode == "direct" {
		dial = (&net.Dialer{Timeout: 8 * time.Second}).DialContext
	} else if p.Mode == "singbox_route" {
		d, e := proxy.SOCKS5("tcp", net.JoinHostPort(p.Server, strconv.Itoa(p.Port)), &proxy.Auth{User: p.Username, Password: p.Password}, &net.Dialer{Timeout: 8 * time.Second})
		if e != nil {
			return nil, nil, e
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, nil, fmt.Errorf("context dial unavailable")
		}
		dial = cd.DialContext
	} else {
		return nil, nil, fmt.Errorf("unverified path")
	}
	tr := &http.Transport{DialContext: dial, TLSHandshakeTimeout: 8 * time.Second, DisableKeepAlives: true, Proxy: nil}
	return &http.Client{Transport: tr, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tr.CloseIdleConnections, nil
}

// Publish the base IP first. Provider failures cannot delay it, replace it or
// attach cached intelligence to a different route/IP after an outbound switch.
func (d *Detector) enrich(ctx context.Context, p Proxy, scope string, base model.Exit) {
	ip := base.IPv4
	if ip == "" {
		ip = base.IPv6
	}
	for _, source := range []string{"ipinfo", "ippure"} {
		out := LookupSource(ctx, p, source, ip, scope+"@"+p.Tag)
		if out.Data != nil {
			d.applyIntel(p, scope, base, source, *out.Data)
		}
	}
}
func (d *Detector) applyIntel(p Proxy, scope string, base model.Exit, source string, data model.Exit) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.scope != scope {
		return
	}
	current := false
	for _, v := range d.proxies {
		if v == p && v.Eligible {
			current = true
		}
	}
	old, ok := d.cache[p.Tag]
	if !current || !ok || old.IPv4 != base.IPv4 || old.IPv6 != base.IPv6 {
		return
	}
	if source == "ipinfo" || old.GeoSource == "" {
		copyIntel(&old, data)
		old.MetadataAt = data.MetadataAt
		old.MetadataCached = data.MetadataCached
	}
	if source == "ippure" {
		old.RiskScore = data.RiskScore
		old.QualityIP = data.QualityIP
		old.QualitySource = data.QualitySource
		old.QualityAt = data.QualityAt
		if data.Residential != nil {
			old.Residential = data.Residential
		}
	}
	d.cache[p.Tag] = old
}
