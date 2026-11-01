package adapter

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"tzsingbox/internal/model"
)

// resolve follows runtime selector choices. An unavailable URLTest choice, cycle,
// missing dependency or conditional route remains unknown; names are never guessed.
func (c *Clash) resolve(tag string, api map[string]Proxy, seen map[string]bool) string {
	if tag == "" || seen[tag] {
		return ""
	}
	seen[tag] = true
	for _, o := range c.inventory.Outbounds {
		if o.Tag != tag {
			continue
		}
		kind, _ := model.OutboundType(o.Type)
		if kind == "logical" {
			now := api[tag].Now
			member := false
			for _, m := range o.Members {
				if m == now {
					member = true
				}
			}
			if !member {
				return ""
			}
			return c.resolve(now, api, seen)
		}
		if kind == "actual" {
			if o.Detour != "" && c.resolve(o.Detour, api, seen) == "" {
				return ""
			}
			return tag
		}
	}
	return ""
}
func (c *Clash) inboundTags(api map[string]Proxy, snap *Snapshot, now time.Time) []model.Tag {
	elapsed := now.Sub(c.last).Seconds()
	if elapsed <= 0 {
		elapsed = 2
	}
	delta := map[string]count{}
	active := map[string]int{}
	next := map[string]Connection{}
	known := map[string]string{}
	identities := map[string]map[string]string{}
	for _, in := range c.inventory.Inbounds {
		known[in.Type+"/"+in.Tag] = "inbound:" + in.Tag
		if in.UserField == "inboundUser" {
			identities[in.Type+"/"+in.Tag] = map[string]string{}
			for _, id := range in.AuthIDs {
				userKey := id
				if in.AuthScheme == "uuid-v1" {
					userKey = in.LegacyAuthIDs[id]
					if userKey == "" {
						continue
					}
				}
				identities[in.Type+"/"+in.Tag][userKey] = model.IdentityName(in.Tag, id)
			}
		}
	}
	rules := map[string]map[string]RuleBinding{}
	for _, in := range c.inventory.Inbounds {
		rules[in.Type+"/"+in.Tag] = in.RuleBindings
	}
	if snap != nil {
		c.unattributed = 0
		for _, x := range snap.Connections {
			tag, ok := known[x.Metadata.Type]
			if x.ID == "" || x.Upload < 0 || x.Download < 0 {
				continue
			}
			if _, ok := next[x.ID]; ok {
				continue
			}
			if !ok {
				c.unattributed++
				continue
			}
			if key := identities[x.Metadata.Type][model.AuthID(x.Metadata.InboundUser)]; x.Metadata.InboundUser != "" && key != "" {
				tag = key
			}
			if binding, ok := rules[x.Metadata.Type][model.AuthID(x.Rule)]; ok && slices.Contains(x.Chains, binding.Outbound) {
				// A full rule contains authenticated name plus listener. Its
				// inventory binding is a UUID, independent of the chosen exit.
				identity := model.IdentityName(strings.TrimPrefix(known[x.Metadata.Type], "inbound:"), binding.ID)
				if tag != known[x.Metadata.Type] && tag != identity {
					c.unattributed++
					continue
				}
				tag = identity
			}
			x.Attributed = tag
			if prev, ok := c.previous[x.ID]; ok && strings.HasPrefix(prev.Attributed, "identity:") && strings.HasPrefix(tag, "identity:") && prev.Attributed != tag {
				// Never lend an existing connection's baseline to a replacement
				// UUID after a config edit or recycled authentication name.
				next[x.ID] = prev
				c.unattributed++
				continue
			}
			next[x.ID] = x
			if tag == known[x.Metadata.Type] && len(rules[x.Metadata.Type]) > 0 {
				c.unattributed++
			}
			active[tag]++
			du, dd := int64(0), int64(0)
			if prev, ok := c.previous[x.ID]; ok {
				if prev.Metadata.Type == x.Metadata.Type && prev.Metadata.InboundUser == x.Metadata.InboundUser {
					du = max(0, x.Upload-prev.Upload)
					dd = max(0, x.Download-prev.Download)
				}
			} else if c.started {
				du = x.Upload
				dd = x.Download
			}
			d := delta[tag]
			d.up += du
			d.down += dd
			delta[tag] = d
		}
	}
	tags := []model.Tag{}
	for _, in := range c.inventory.Inbounds {
		t := model.Tag{Name: "inbound:" + in.Tag, InboundTag: in.Tag, Identity: "inbound", Type: in.Type, RouteVersion: c.inventory.ConfigHash, State: "unknown", RouteReason: "未知：按用户、目标或规则集分流，无法确定唯一出口"}
		resolved := ""
		unknown := in.Unknown || len(in.Routes) == 0
		for _, root := range in.Routes {
			dest := c.resolve(root, api, map[string]bool{})
			if dest == "" || (resolved != "" && resolved != dest) {
				unknown = true
			}
			resolved = dest
		}
		if !unknown {
			t.Egress = resolved
			t.RouteReason = "配置路由与运行时选择器"
			for _, o := range c.inventory.Outbounds {
				if o.Tag == resolved {
					t.EgressType = o.Type
				}
			}
		}
		variants := []model.Tag{t}
		if len(in.AuthIDs) > 0 || (in.Type == "vless" && in.AuthCount > 0) {
			variants[0].Accounting = "unattributed"
		}
		for _, id := range in.AuthIDs {
			u := t
			u.AuthID = id
			u.AuthName = in.AuthNames[id]
			u.AuthScheme = in.AuthScheme
			u.LegacyAuthID = in.LegacyAuthIDs[id]
			u.Egress = ""
			u.EgressType = ""
			u.RouteReason = "认证身份的独立出站路径未验证"
			u.Name = model.IdentityName(in.Tag, id)
			u.Accounting = "unavailable"
			u.AccountingReason = "认证身份不可归属：没有精确的认证路由规则或原生用户计数绑定"
			for _, binding := range in.RuleBindings {
				if binding.ID == id {
					u.Accounting = "rule_user_observed"
					u.AccountingReason = "完整 auth_user 路由规则映射 UUID；连接快照可能漏掉采样间结束的连接，累计为已观测下界"
					break
				}
			}
			if in.UserField == "inboundUser" {
				u.Accounting = "identity"
			}
			variants = append(variants, u)
		}
		for _, t := range variants {
			t.Classify()
			if snap != nil {
				t.State = "online"
				t.Quality = "observed_lower_bound"
				if t.Accounting != "unavailable" {
					d := delta[t.Name]
					n := c.totals[t.Name]
					n.up += d.up
					n.down += d.down
					c.totals[t.Name] = n
					up, down, cnt := float64(d.up)/elapsed, float64(d.down)/elapsed, active[t.Name]
					t.Up = &up
					t.Down = &down
					t.Upload = &n.up
					t.Download = &n.down
					t.Active = &cnt
				}
			}
			tags = append(tags, t)
		}
	}
	if snap != nil {
		c.previous = next
		c.last = now
		c.started = true
	}
	sort.Slice(tags, func(i, j int) bool { return strings.Compare(tags[i].Name, tags[j].Name) < 0 })
	return tags
}

// InboundPath resolves only the configured inbound and current selector choices.
// It never probes the network or substitutes the host default route.
func (c *Clash) InboundPath(tag string) (model.Tag, error) {
	var p struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := c.get("/proxies", &p); err != nil {
		return model.Tag{}, err
	}
	for _, t := range c.inboundTags(p.Proxies, nil, time.Now()) {
		if t.InboundTag == tag {
			return t, nil
		}
	}
	return model.Tag{}, fmt.Errorf("inbound unavailable")
}
