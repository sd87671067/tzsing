package adapter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
	"tzsingbox/internal/model"
)

type Connection struct {
	Rule       string `json:"rule"`
	Attributed string `json:"-"`
	Metadata   struct {
		Type        string `json:"type"`
		InboundUser string `json:"inboundUser,omitempty"`
	} `json:"metadata"`
	ID       string   `json:"id"`
	Chains   []string `json:"chains"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
}
type Snapshot struct {
	Connections []Connection `json:"connections"`
}
type Proxy struct {
	Type        string `json:"type"`
	InboundUser string `json:"inboundUser,omitempty"`
	Now         string `json:"now"`
}
type count struct{ up, down int64 }
type Clash struct {
	recentPaths  map[string][]model.EgressPath
	pathVersion  string
	unattributed int
	URL, Secret  string
	Client       *http.Client
	previous     map[string]Connection
	totals       map[string]count
	last         time.Time
	started      bool
	inventory    *Inventory
}

func New(url, secret string) *Clash {
	return &Clash{URL: url, Secret: secret, Client: &http.Client{Timeout: 3 * time.Second}, previous: map[string]Connection{}, totals: map[string]count{}}
}
func (c *Clash) get(path string, v any) error {
	req, e := http.NewRequest("GET", c.URL+path, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	res, e := c.Client.Do(req)
	if e != nil {
		return fmt.Errorf("clash unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("clash status %d", res.StatusCode)
	}
	return json.NewDecoder(http.MaxBytesReader(nil, res.Body, 8<<20)).Decode(v)
}
func (c *Clash) Collect() ([]model.Tag, error) {
	var p struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if e := c.get("/proxies", &p); e != nil {
		return nil, e
	}
	rawProxies := p.Proxies
	p.Proxies = c.discovered(p.Proxies)
	var snap Snapshot
	if e := c.get("/connections", &snap); e != nil {
		return nil, e
	}
	now := time.Now()
	if c.inventory != nil && c.inventory.Inbounds != nil {
		return c.inboundTags(rawProxies, &snap, now), nil
	}
	elapsed := now.Sub(c.last).Seconds()
	if elapsed <= 0 {
		elapsed = 2
	}
	delta := map[string]count{}
	active := map[string]int{}
	next := map[string]Connection{}
	for _, x := range snap.Connections {
		if len(x.Chains) == 0 || x.ID == "" || x.Upload < 0 || x.Download < 0 {
			continue
		}
		if _, ok := next[x.ID]; ok {
			continue
		}
		next[x.ID] = x
		tag := x.Chains[0]
		proxy, ok := p.Proxies[tag]
		kind, _ := model.OutboundType(proxy.Type)
		if !ok || kind != "actual" {
			continue
		}
		active[tag]++
		du, dd := int64(0), int64(0)
		if prev, ok := c.previous[x.ID]; ok {
			if len(prev.Chains) > 0 && prev.Chains[0] == tag {
				du = max(0, x.Upload-prev.Upload)
				dd = max(0, x.Download-prev.Download)
			}
		} else if c.started {
			du = x.Upload
			dd = x.Download
		}
		n := delta[tag]
		n.up += du
		n.down += dd
		delta[tag] = n
	}
	out := []model.Tag{}
	for name, proxy := range p.Proxies {
		if name == "GLOBAL" && c.inventory == nil {
			continue
		}
		t := model.Tag{Name: name, Type: proxy.Type, Kind: "actual", Egress: name, State: "online", Quality: "observed_lower_bound; polling may miss closed connections"}
		kind, _ := model.OutboundType(proxy.Type)
		t.Kind = kind
		if kind != "actual" {
			t.Kind = "logical"
			t.Egress = proxy.Now
			t.Quality = "logical selector; traffic not duplicated"
		} else {
			d := delta[name]
			n := c.totals[name]
			n.up += d.up
			n.down += d.down
			c.totals[name] = n
			up, down := float64(d.up)/elapsed, float64(d.down)/elapsed
			cnt := active[name]
			t.Up = &up
			t.Down = &down
			t.Upload = &n.up
			t.Download = &n.down
			t.Active = &cnt
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	c.previous = next
	c.last = now
	c.started = true
	return out, nil
}

// UnattributedConnections never assigns unmatched snapshot traffic to an inbound.
func (c *Clash) UnattributedConnections() int { return c.unattributed }
