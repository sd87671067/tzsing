package server

import (
	"context"
	"fmt"
	"strings"
	"tzsingbox/internal/store"
)

type outboundChoice struct {
	ID      string `json:"tag"`
	Name    string `json:"name"`
	Current bool   `json:"current"`
}

// Permissions are read from authenticated monitoring grants. The host supplies
// mappings from current config, never from browser input or cached reports.
func (a *App) selectableOutbounds(ctx context.Context, u store.User, node string) ([]outboundChoice, error) {
	server, raw, err := a.DB.Resolve(u, node)
	if err != nil || server != a.ControlServer || !a.controlPermission(u, "change") {
		return nil, fmt.Errorf("无权更换出站")
	}
	catalog, status := a.hostControl(ctx, "outbound-catalog", map[string]string{})
	if status != 200 {
		return nil, fmt.Errorf("出站暂不可用")
	}
	mappings, ok := catalog["mappings"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("出站映射暂不可用")
	}
	// Resolve every configured identity through the existing monitoring authorization.
	// Report refreshes and display aliases never grant access.
	allowed := map[string]bool{}
	for identity, value := range mappings {
		if !strings.HasPrefix(identity, "identity:") || !a.DB.Allowed(u, server, identity) {
			continue
		}
		refs, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("出站映射无效")
		}
		for _, ref := range refs {
			if tag, ok := ref.(string); ok && tag != "" {
				allowed[tag] = true
			}
		}
	}
	current := map[string]bool{}
	if refs, ok := mappings[raw].([]any); ok {
		for _, ref := range refs {
			if tag, ok := ref.(string); ok {
				current[tag] = true
			}
		}
	}
	items, ok := catalog["items"].([]any)
	if !ok {
		return nil, fmt.Errorf("出站清单无效")
	}
	result := []outboundChoice{}
	for _, x := range items {
		item, ok := x.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("出站清单无效")
		}
		tag, ok := item["tag"].(string)
		if !ok || tag == "" {
			continue
		}
		o, err := a.DB.RegisterOutbound(server, tag, tag, 0)
		if err != nil {
			return nil, err
		}
		if o.Owner != 0 && o.Owner != u.ID {
			continue
		}
		if o.Owner != u.ID && !allowed[tag] {
			continue
		}
		choice := outboundChoice{ID: o.ID, Name: o.Name, Current: current[tag]}
		result = append(result, choice)
	}
	return result, nil
}
func (a *App) canSelectOutbound(ctx context.Context, u store.User, node, id string) bool {
	choices, err := a.selectableOutbounds(ctx, u, node)
	if err != nil {
		return false
	}
	for _, o := range choices {
		if o.ID == id {
			return true
		}
	}
	return false
}
