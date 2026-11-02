package control

import "testing"

func TestOutboundDeletionRejectsEveryReferenceRoot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		root  string
		value any
	}{
		{"route final", "route", map[string]any{"final": "target"}},
		{"nested route", "route", map[string]any{"rules": []any{map[string]any{"type": "logical", "mode": "or", "rules": []any{map[string]any{"outbound": "target"}}}}}},
		{"DNS detour", "dns", map[string]any{"servers": []any{map[string]any{"detour": "target"}}}},
		{"inbound detour", "inbounds", []any{map[string]any{"detour": "target"}}},
		{"endpoint detour", "endpoints", []any{map[string]any{"detour": "target"}}},
		{"selector members", "outbounds", []any{map[string]any{"tag": "selector", "type": "selector", "outbounds": []any{"target"}}}},
		{"selector default", "outbounds", []any{map[string]any{"tag": "selector", "type": "selector", "default": "target"}}},
		{"proxy detour", "outbounds", []any{map[string]any{"tag": "proxy", "type": "http", "detour": "target"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := map[string]any{"tag": "target", "type": "direct"}
			config := map[string]any{"outbounds": []any{target}}
			if tc.root == "outbounds" {
				config[tc.root] = append([]any{target}, tc.value.([]any)...)
			} else {
				config[tc.root] = tc.value
			}
			raw := canonical(config)
			if _, _, e := outboundCandidate(raw, OutboundNodeRequest{Tag: "target"}, "delete"); e == nil {
				t.Fatal("deleted a referenced outbound")
			}
			if string(canonical(config)) != string(raw) {
				t.Fatal("failed deletion mutated its input")
			}
		})
	}
}
