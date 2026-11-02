package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// Three-way merging never guesses the order of concurrently reordered arrays.
// Only tagged entities, named/UUID users and unambiguous route predicates merge.
func mergeConfig(base, desired, latest []byte) ([]byte, error) {
	decode := func(raw []byte) (any, error) {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var v any
		e := d.Decode(&v)
		if !json.Valid(raw) {
			return nil, ErrScope
		}
		return v, e
	}
	b, e := decode(base)
	if e != nil {
		return nil, e
	}
	d, e := decode(desired)
	if e != nil {
		return nil, e
	}
	l, e := decode(latest)
	if e != nil {
		return nil, e
	}
	v, e := mergeValue(b, d, l, "")
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return formatConfig(raw)
}
func conflict(path string) error {
	return errors.New("配置目标存在并发冲突，请刷新后重新编辑；未覆盖其他管理端修改")
}
func mergeValue(b, d, l any, path string) (any, error) {
	if reflect.DeepEqual(b, d) {
		return l, nil
	}
	if reflect.DeepEqual(b, l) || reflect.DeepEqual(d, l) {
		return d, nil
	}
	bm, bok := b.(map[string]any)
	dm, dok := d.(map[string]any)
	lm, lok := l.(map[string]any)
	if bok && dok && lok {
		out := map[string]any{}
		for k, v := range lm {
			out[k] = v
		}
		keys := map[string]bool{}
		for k := range bm {
			keys[k] = true
		}
		for k := range dm {
			keys[k] = true
		}
		for k := range keys {
			bv, bp := bm[k]
			dv, dp := dm[k]
			lv, lp := lm[k]
			if bp == dp && reflect.DeepEqual(bv, dv) {
				continue
			}
			if bp != lp {
				if dp == lp && reflect.DeepEqual(dv, lv) {
					continue
				}
				return nil, conflict(path + "/" + k)
			}
			if !dp {
				if !reflect.DeepEqual(bv, lv) {
					return nil, conflict(path + "/" + k)
				}
				delete(out, k)
				continue
			}
			if !bp {
				if lp && !reflect.DeepEqual(dv, lv) {
					return nil, conflict(path + "/" + k)
				}
				out[k] = dv
				continue
			}
			v, e := mergeValue(bv, dv, lv, path+"/"+k)
			if e != nil {
				return nil, e
			}
			out[k] = v
		}
		return out, nil
	}
	ba, bok := b.([]any)
	da, dok := d.([]any)
	la, lok := l.([]any)
	if bok && dok && lok && (path == "/inbounds" || path == "/outbounds" || strings.HasSuffix(path, "/users") || path == "/route/rules") {
		return mergeArray(ba, da, la, path)
	}
	return nil, conflict(path)
}
func entityKey(v any, path string) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if path == "/inbounds" || path == "/outbounds" {
		s, _ := m["tag"].(string)
		return s
	}
	if strings.HasSuffix(path, "/users") {
		for _, k := range []string{"name", "uuid", "username", "password"} {
			if s, ok := m[k].(string); ok && s != "" {
				return k + ":" + s
			}
		}
		return ""
	}
	pred := map[string]any{}
	action, _ := m["action"].(string)
	if action == "" {
		action = "route"
	}
	pred["__action_kind"] = action
	for k, v := range m {
		if k != "action" && k != "outbound" {
			pred[k] = v
		}
	}
	raw, _ := json.Marshal(pred)
	return string(raw)
}
func mergeArray(b, d, l []any, path string) (any, error) {
	index := func(a []any) (map[string]any, []string, error) {
		m := map[string]any{}
		order := []string{}
		for _, v := range a {
			k := entityKey(v, path)
			if k == "" {
				return nil, nil, conflict(path)
			}
			if _, ok := m[k]; ok {
				return nil, nil, conflict(path)
			}
			m[k] = v
			order = append(order, k)
		}
		return m, order, nil
	}
	bm, bo, e := index(b)
	if e != nil {
		return nil, e
	}
	dm, do, e := index(d)
	if e != nil {
		return nil, e
	}
	lm, lo, e := index(l)
	if e != nil {
		return nil, e
	}
	// A concurrent reorder cannot be inferred safely. Retain latest order and
	// anchor new desired elements immediately before their next surviving peer.
	common := func(order []string) []string {
		r := []string{}
		for _, k := range order {
			if _, ok := bm[k]; ok {
				if _, ok = dm[k]; ok {
					if _, ok = lm[k]; ok {
						r = append(r, k)
					}
				}
			}
		}
		return r
	}
	if !reflect.DeepEqual(common(bo), common(do)) || !reflect.DeepEqual(common(bo), common(lo)) {
		return nil, conflict(path + "/order")
	}
	merged, e := mergeValue(bm, dm, lm, path+"/entities")
	if e != nil {
		return nil, e
	}
	mm := merged.(map[string]any)
	order := append([]string{}, lo...)
	for i, k := range do {
		if _, ok := lm[k]; ok {
			continue
		}
		pos := len(order)
		for _, next := range do[i+1:] {
			found := false
			for j, have := range order {
				if have == next {
					pos = j
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		order = append(order, "")
		copy(order[pos+1:], order[pos:])
		order[pos] = k
	}
	out := []any{}
	for _, k := range order {
		if v, ok := mm[k]; ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func preciseJSON(raw []byte) any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	d.Decode(&v)
	return v
}
