package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

var ErrScope = errors.New("配置依赖、目标范围或原始快照冲突；未应用")

func digest(b []byte) string       { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonical(v any) []byte       { b, _ := json.Marshal(historicNumbers(v)); return b }
func managedTag(tag string) string { return "tzsing-" + digest([]byte(tag))[:24] }
func findInbound(c map[string]any, tag string) map[string]any {
	for _, v := range array(c["inbounds"]) {
		in := object(v)
		if text(in["tag"]) == tag {
			return in
		}
	}
	return nil
}

type Snapshot struct {
	ExistingOutbound bool           `json:"existing_outbound,omitempty"`
	BaselineHash     string         `json:"baseline_hash"`
	RoutePresent     bool           `json:"route_present"`
	RulesPresent     bool           `json:"rules_present"`
	Rules            []any          `json:"rules"`
	Outbound         map[string]any `json:"outbound"`
	InboundHash      string         `json:"inbound_hash"`
}

// Only insert narrowly guarded routes immediately before the matching original
// route. Original rejects, auth_user conditions, rule sets and rules are untouched.
// The final fallback is appended after all existing rejects. Shared outbounds are
// never edited. Restoration removes these exact additions, not a guessed direct.
func Change(raw []byte, tag string, outbound map[string]any, prior *Snapshot) ([]byte, Snapshot, error) {
	var c map[string]any
	if decodeConfigMap(raw, &c) != nil {
		return nil, Snapshot{}, ErrScope
	}
	in := findInbound(c, tag)
	if in == nil {
		return nil, Snapshot{}, ErrScope
	}
	if prior != nil {
		base, e := Restore(raw, tag, *prior)
		if e != nil {
			return nil, Snapshot{}, e
		}
		raw = base
		c = nil
		decodeConfigMap(raw, &c)
	}
	if object(in)["type"] == "socks" || object(in)["type"] == "mixed" || object(in)["type"] == "http" {
		return nil, Snapshot{}, ErrScope
	}
	name := managedTag(tag)
	for _, o := range array(c["outbounds"]) {
		if text(object(o)["tag"]) == name {
			return nil, Snapshot{}, ErrScope
		}
	}
	if text(outbound["tag"]) != name {
		return nil, Snapshot{}, ErrScope
	}
	_, routePresent := c["route"]
	_, rulesPresent := object(c["route"])["rules"]
	snapshot := Snapshot{BaselineHash: baselineHash(c), RoutePresent: routePresent, RulesPresent: rulesPresent, Outbound: outbound, InboundHash: digest(canonical(in))}
	route := object(c["route"])
	rules := []any{}
	for _, v := range array(route["rules"]) {
		r := object(v)
		if text(r["outbound"]) != "" && (text(r["action"]) == "" || text(r["action"]) == "route") {
			// Keep the whole original predicate as a child of an AND guard.
			pred := map[string]any{}
			for k, val := range r {
				if k != "outbound" && k != "action" {
					pred[k] = val
				}
			}
			guard := map[string]any{"type": "logical", "mode": "and", "rules": []any{map[string]any{"inbound": []any{tag}}, pred}, "action": "route", "outbound": name}
			// Empty predicates become a single inbound match.
			if len(pred) == 0 {
				guard = map[string]any{"inbound": []any{tag}, "action": "route", "outbound": name}
			}
			rules = append(rules, guard)
			snapshot.Rules = append(snapshot.Rules, guard)
		}
		rules = append(rules, v)
	}
	fallback := map[string]any{"inbound": []any{tag}, "action": "route", "outbound": name}
	rules = append(rules, fallback)
	snapshot.Rules = append(snapshot.Rules, fallback)
	route["rules"] = rules
	c["route"] = route
	c["outbounds"] = append(array(c["outbounds"]), outbound)
	candidate := configBytes(c)
	restored, e := Restore(candidate, tag, snapshot)
	if e != nil || !reflect.DeepEqual(canonicalJSON(raw), canonicalJSON(restored)) {
		return nil, Snapshot{}, ErrScope
	}
	return candidate, snapshot, nil
}
func canonicalJSON(b []byte) any { var v any; json.Unmarshal(b, &v); return v }
func Restore(raw []byte, tag string, s Snapshot) ([]byte, error) {
	var c map[string]any
	if decodeConfigMap(raw, &c) != nil || digest(canonical(findInbound(c, tag))) != s.InboundHash || snapshotBaseline(c, s) != s.BaselineHash {
		return nil, ErrScope
	}
	route := object(c["route"])
	rules := array(route["rules"])
	counts := map[string]int{}
	for _, r := range s.Rules {
		counts[string(canonical(r))]++
	}
	kept := []any{}
	for _, r := range rules {
		key := string(canonical(r))
		if counts[key] > 0 {
			counts[key]--
		} else {
			kept = append(kept, r)
		}
	}
	for _, n := range counts {
		if n != 0 {
			return nil, ErrScope
		}
	}
	outs := []any{}
	found := 0
	for _, o := range array(c["outbounds"]) {
		if !s.ExistingOutbound && text(object(o)["tag"]) == managedTag(tag) {
			if string(canonical(o)) != string(canonical(s.Outbound)) {
				return nil, ErrScope
			}
			found++
		} else {
			outs = append(outs, o)
		}
	}
	if !s.ExistingOutbound && found != 1 {
		return nil, ErrScope
	}
	if !s.RulesPresent && len(kept) == 0 {
		delete(route, "rules")
	} else {
		route["rules"] = kept
	}
	if !s.RoutePresent && len(route) == 0 {
		delete(c, "route")
	} else {
		c["route"] = route
	}
	c["outbounds"] = outs
	return configBytes(c), nil
}

func baselineHash(c map[string]any) string {
	route := map[string]any{}
	for k, v := range object(c["route"]) {
		if k != "rules" {
			route[k] = v
		}
	}
	rules := []any{}
	for _, r := range array(object(c["route"])["rules"]) {
		if !strings.HasPrefix(text(object(r)["outbound"]), "tzsing-") {
			rules = append(rules, r)
		}
	}
	if len(rules) > 0 {
		route["rules"] = rules
	}
	outs := []any{}
	for _, o := range array(c["outbounds"]) {
		if !strings.HasPrefix(text(object(o)["tag"]), "tzsing-") {
			outs = append(outs, o)
		}
	}
	return digest(canonical(map[string]any{"route": route, "outbounds": outs}))
}

// Existing outbound bindings own only their exact guarded route additions.
func snapshotBaseline(config map[string]any, s Snapshot) string {
	if !s.ExistingOutbound {
		return baselineHash(config)
	}
	c := candidateMap(documentBytes(config))
	route := object(c["route"])
	rules := []any{}
	owned := map[string]int{}
	for _, r := range s.Rules {
		owned[string(canonical(r))]++
	}
	for _, r := range array(route["rules"]) {
		k := string(canonical(r))
		if owned[k] > 0 {
			owned[k]--
		} else {
			rules = append(rules, r)
		}
	}
	route["rules"] = rules
	c["route"] = route
	return baselineHash(c)
}
