package adapter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
	"tzsingbox/internal/model"
)

// Inventory contains protocol identities only, never outbound credentials.
// A privileged, read-only exporter writes this file atomically on config change.
type AppliedExit struct {
	ConfigHash string `json:"config_hash"`
	Tag        string `json:"tag"`
	Outbound   string `json:"outbound"`
	IP         string `json:"ip"`
	At         int64  `json:"at"`
}
type Inventory struct {
	AppliedExit *AppliedExit `json:"applied_exit"`
	ConfigHash  string       `json:"config_hash"`

	Inbounds       []Inbound  `json:"inbounds"`
	Outbounds      []Outbound `json:"outbounds"`
	RoutesVerified bool       `json:"routes_verified"`
}
type Inbound struct {
	Tag     string   `json:"tag"`
	Type    string   `json:"type"`
	Routes  []string `json:"routes"`
	Unknown bool     `json:"unknown"`
}
type Outbound struct {
	Members []string `json:"members"`
	Detour  string   `json:"detour"`
	Tag     string   `json:"tag"`
	Type    string   `json:"type"`
	Bound   bool     `json:"bound"`
}

func ReadInventory(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Inventory
	if len(b) > 256<<10 || json.Unmarshal(b, &v) != nil || len(v.Outbounds) > 512 {
		return nil, fmt.Errorf("invalid outbound inventory")
	}
	seenIn := map[string]bool{}
	if len(v.Inbounds) > 512 {
		return nil, fmt.Errorf("invalid inbound inventory")
	}
	for _, i := range v.Inbounds {
		if i.Tag == "" || len(i.Tag) > 128 || i.Type == "" || len(i.Type) > 64 || seenIn[i.Tag] || len(i.Routes) > 512 {
			return nil, fmt.Errorf("invalid inbound identity")
		}
		seenIn[i.Tag] = true
	}
	seen := map[string]bool{}
	for _, o := range v.Outbounds {
		if o.Tag == "" || seen[o.Tag] || len(o.Tag) > 128 || len(o.Type) > 64 {
			return nil, fmt.Errorf("invalid outbound identity")
		}
		seen[o.Tag] = true
	}
	return &v, nil
}

func (c *Clash) SetInventory(v *Inventory) { c.inventory = v }

func (c *Clash) UnavailableTags() []model.Tag {
	if c.inventory == nil {
		return nil
	}
	if c.inventory.Inbounds != nil {
		return c.inboundTags(nil, nil, time.Now())
	}
	tags := []model.Tag{}
	for tag, p := range c.discovered(nil) {
		tags = append(tags, model.Tag{Name: tag, Type: p.Type, State: "unknown"})
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].Name < tags[j].Name })
	return tags
}

func (c *Clash) discovered(api map[string]Proxy) map[string]Proxy {
	if c.inventory == nil {
		return api
	}
	out := make(map[string]Proxy, len(c.inventory.Outbounds))
	for _, o := range c.inventory.Outbounds {
		kind, category := model.OutboundType(o.Type)
		if kind == "actual" && category != "直连" && !o.Bound {
			continue
		}
		p := api[o.Tag]
		p.Type = o.Type
		out[o.Tag] = p
	}
	return out
}

func (c *Clash) InvalidateInventory() {
	if c.inventory == nil {
		return
	}
	c.inventory.ConfigHash = "unavailable"
	for i := range c.inventory.Inbounds {
		c.inventory.Inbounds[i].Unknown = true
		c.inventory.Inbounds[i].Routes = nil
	}
}
