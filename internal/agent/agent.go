package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"tzsingbox/internal/adapter"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/collector"
	"tzsingbox/internal/egress"
	"tzsingbox/internal/model"
)

type Config struct {
	NativeStatsURL string         `json:"native_stats_url,omitempty"`
	ServerID       string         `json:"server_id"`
	Token          string         `json:"token"`
	URL            string         `json:"url"`
	CA             string         `json:"ca"`
	ClashURL       string         `json:"clash_url"`
	ClashSecret    string         `json:"clash_secret"`
	Proxies        []egress.Proxy `json:"proxies"`
	Sample         int            `json:"sample_seconds"`
	ExitSeconds    int            `json:"exit_seconds"`
	InventoryFile  string         `json:"inventory_file"`
}

func Run(ctx context.Context, path string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var c Config
	if e = json.Unmarshal(b, &c); e != nil {
		return fmt.Errorf("invalid agent configuration")
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "https" || len(c.Token) != 43 {
		return fmt.Errorf("agent requires HTTPS and token")
	}
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if c.CA != "" {
		b, e = os.ReadFile(c.CA)
		if e != nil {
			return e
		}
		if !pool.AppendCertsFromPEM(b) {
			return fmt.Errorf("invalid CA")
		}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clash := adapter.New(c.ClashURL, c.ClashSecret)
	if c.InventoryFile != "" {
		inv, err := adapter.ReadInventory(c.InventoryFile)
		if err != nil {
			return fmt.Errorf("outbound inventory required but unavailable")
		}
		clash.SetInventory(inv)
		if !inv.RoutesVerified {
			c.Proxies = nil
		}
	}
	var native *adapter.Native
	var nativeInv *adapter.Inventory
	if c.NativeStatsURL != "" {
		native, e = adapter.NewNative(c.NativeStatsURL)
		if e != nil {
			return e
		}
	}
	host := &collector.Collector{}
	det := egress.New()
	det.SetProxies(c.Proxies)
	go det.Run(ctx, c.Proxies, time.Duration(max(300, c.ExitSeconds))*time.Second)
	epoch := auth.Random()
	seq := int64(0)
	sample := max(2, min(c.Sample, 60))
	backoff := time.Second
	var last []model.Tag
	var checked time.Time
	routesVerified := false
	routeVersion := ""
	var appliedExit *adapter.AppliedExit
	for {
		if time.Since(checked) >= 30*time.Second {
			checked = time.Now()
			if c.InventoryFile != "" {
				inv, err := adapter.ReadInventory(c.InventoryFile)
				if err == nil {
					clash.SetInventory(inv)
					nativeInv = inv
					routesVerified = inv.RoutesVerified
					routeVersion = inv.ConfigHash
					appliedExit = inv.AppliedExit
					c.Proxies = nil
					if paths, err := egress.ReadPaths(filepath.Join(filepath.Dir(c.InventoryFile), "probe-paths.json"), inv.ConfigHash); err == nil {
						c.Proxies = paths
					}
					if inv.RoutesVerified {
						det.SetProxies(c.Proxies)
					} else {
						det.SetProxies(nil)
					}
				} else {
					nativeInv = nil
					log.Print("inventory unavailable; preserving identities with unknown routes")
					clash.InvalidateInventory()
					routesVerified = false
					routeVersion = "unavailable"
					appliedExit = nil
					det.SetProxies(nil)
				}
			}
		}
		seq++
		tags, err := clash.Collect()
		message := ""
		if err != nil {
			message = "Clash API unavailable"
			tags = clash.UnavailableTags()
			if tags == nil {
				tags = last
			}
			for i := range tags {
				tags[i].State = "unknown"
				tags[i].Up = nil
				tags[i].Down = nil
				tags[i].Upload = nil
				tags[i].Download = nil
				tags[i].Active = nil
			}
		} else {
			last = append([]model.Tag(nil), tags...)
		}
		// Native user counters do not depend on Clash snapshots being available.
		// Recover only counters attested by the inventory; routes remain unknown.
		if native != nil {
			if native.Collect(ctx, nativeInv, tags) != nil {
				if message != "" {
					message += "; "
				}
				message += "native user stats unavailable"
			}
		}
		if len(tags) > 0 {
			det.SetScope(tags[0].RouteVersion)
		}
		attachExits(tags, det.Get, routesVerified)
		for i := range tags {
			t := &tags[i]
			if t.Identity == "inbound" && t.AuthID == "" && appliedExit != nil && appliedExit.ConfigHash == routeVersion && appliedExit.Tag == t.InboundTag && t.Egress != "" && time.Now().Unix()-appliedExit.At < 3600 {
				ip := net.ParseIP(appliedExit.IP)
				if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
					v := &model.Exit{Verified: true, Updated: appliedExit.At, Source: "受限控制器 · 实际目标入站路径", Path: t.Egress + "@" + t.RouteVersion}
					if ip.To4() != nil {
						v.IPv4 = ip.String()
					} else {
						v.IPv6 = ip.String()
					}
					t.IP = v
				}
			}
		}
		report := model.Report{Discovery: clash.Discovery(len(tags)), UnattributedConnections: clash.UnattributedConnections(), ServerID: c.ServerID, Epoch: epoch, Seq: seq, At: time.Now().Unix(), Interval: sample, Host: host.Sample(), Tags: tags, Error: message}
		b, e = json.Marshal(report)
		if e != nil {
			return e
		}
		req, e := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(b))
		if e != nil {
			return fmt.Errorf("invalid report URL")
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		delay := time.Duration(sample) * time.Second
		if e == nil {
			if res.StatusCode == 200 {
				var settings struct {
					Sample int `json:"sample_seconds"`
				}
				if json.NewDecoder(res.Body).Decode(&settings) == nil && settings.Sample >= 2 && settings.Sample <= 60 {
					sample = settings.Sample
				}
				backoff = time.Second
			} else {
				e = fmt.Errorf("report rejected status=%d", res.StatusCode)
			}
			res.Body.Close()
		}
		if e != nil {
			log.Print("agent report unavailable; retrying")
			delay = backoff
			backoff = min(backoff*2, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// Outlet proofs are shared; UUID counters and connection counts remain untouched.
func attachExits(tags []model.Tag, get func(string) *model.Exit, routesVerified bool) {
	for i := range tags {
		t := &tags[i]
		if t.Kind != "actual" {
			continue
		}
		if t.Identity == "inbound" {
			if !routesVerified {
				continue
			}
			for j := range t.Egresses {
				p := &t.Egresses[j]
				p.IP = get(p.Tag)
				if p.IP != nil {
					p.IP.Path = p.Tag + "@" + t.RouteVersion
				}
			}
			if t.Egress != "" {
				t.IP = get(t.Egress)
				if t.IP != nil {
					t.IP.Path = t.Egress + "@" + t.RouteVersion
				}
			}
		} else {
			t.IP = get(t.Name)
		}
	}
}
