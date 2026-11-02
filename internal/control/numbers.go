package control

import (
	"bytes"
	"encoding/json"
)

func decodeConfigMap(raw []byte, out *map[string]any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(out)
}
func documentBytes(v any) []byte { b, _ := json.Marshal(v); return b }

// Retain historic float64 normalization for hashes while document generation
// preserves original number tokens. Ordinary generated integer fields are intact.
func historicNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		f, e := x.Float64()
		if e == nil {
			return f
		}
		return x
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			out[k] = historicNumbers(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = historicNumbers(v)
		}
		return out
	case map[string]Snapshot:
		out := map[string]any{}
		for k, v := range x {
			out[k] = historicNumbers(v)
		}
		return out
	case Snapshot:
		var m map[string]any
		decodeConfigMap(documentBytes(x), &m)
		return historicNumbers(m)
	}
	return v
}
