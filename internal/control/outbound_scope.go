package control

import "tzsingbox/internal/model"

// Identity matching distinguishes excluded, conditional and unconditional rules.
// Only unconditional terminal rules suppress later route references.
func identityMatch(r map[string]any, inbound, user string) int {
	result := 1
	if text(r["type"]) == "logical" {
		mode := text(r["mode"])
		if mode != "and" && mode != "or" {
			return 0
		}
		if mode == "or" {
			result = -1
		}
		if len(array(r["rules"])) == 0 {
			return 0
		}
		for _, child := range array(r["rules"]) {
			m := identityMatch(object(child), inbound, user)
			if mode == "and" {
				if m == -1 {
					result = -1
					break
				}
				if m == 0 {
					result = 0
				}
			} else {
				if m == 1 {
					result = 1
					break
				}
				if m == 0 {
					result = 0
				}
			}
		}
	} else {
		for k, v := range r {
			switch k {
			case "action", "outbound", "type", "invert":
			case "inbound", "auth_user":
				want := inbound
				if k == "auth_user" {
					want = user
				}
				values := array(v)
				if str, ok := v.(string); ok {
					values = []any{str}
				}
				found := false
				for _, value := range values {
					if text(value) == want {
						found = true
					}
				}
				if !found {
					result = -1
				}
			default:
				if result != -1 {
					result = 0
				}
			}
		}
	}
	if r["invert"] == true {
		result = -result
	}
	return result
}

// Export feasible top-level route references, preserving selector/detour roots.
// A conditional rule can contribute a route but cannot hide later fallbacks.
// Unknown identity predicates never become a universal identity match.
func identityOutbounds(config map[string]any, inbound, id string) []string {
	u, err := identityUser(config, inbound, id)
	if err != nil {
		return []string{}
	}
	result := []string{}
	seen := map[string]bool{}
	add := func(tag string) {
		if tag != "" && findOutbound(config, tag) != nil && !seen[tag] {
			seen[tag] = true
			result = append(result, tag)
		}
	}
	for _, v := range array(object(config["route"])["rules"]) {
		r := object(v)
		action := text(r["action"])
		if action == "sniff" || action == "resolve" || action == "route-options" {
			continue
		}
		m := identityMatch(r, inbound, text(u["name"]))
		if m == -1 {
			continue
		}
		if action == "" || action == "route" {
			add(text(r["outbound"]))
		}
		if m == 1 {
			return result
		}
	}
	if final := text(object(config["route"])["final"]); final != "" {
		add(final)
	} else {
		outs := array(config["outbounds"])
		if len(outs) > 0 {
			add(text(object(outs[0])["tag"]))
		}
	}
	return result
}

func outboundMappings(config map[string]any) map[string][]string {
	result := map[string][]string{}
	for _, v := range array(config["inbounds"]) {
		in := object(v)
		tag := text(in["tag"])
		if text(in["type"]) != "vless" {
			continue
		}
		for _, x := range array(in["users"]) {
			id := model.UUIDAuthID(text(object(x)["uuid"]))
			result[model.IdentityName(tag, id)] = identityOutbounds(config, tag, id)
		}
	}
	return result
}
