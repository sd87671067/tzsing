package egress

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReadPaths accepts only the root-owned supervisor's current configuration proof.
func ReadPaths(path, hash string) ([]Proxy, error) {
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 256<<10 {
		return nil, fmt.Errorf("probe paths unavailable")
	}
	var v struct {
		Hash    string  `json:"config_hash"`
		Proxies []Proxy `json:"proxies"`
	}
	if json.Unmarshal(b, &v) != nil || v.Hash != hash {
		return nil, fmt.Errorf("probe paths changed")
	}
	return v.Proxies, nil
}
