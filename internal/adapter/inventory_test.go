package adapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInventoryDiscoversCollapsedDirectsAndConfigChanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]Proxy{"DIRECT": {Type: "Direct"}, "helper": {Type: "Direct"}, "relay": {Type: "SOCKS"}}})
			return
		}
		json.NewEncoder(w).Encode(Snapshot{})
	}))
	defer srv.Close()
	c := New(srv.URL, "")
	c.SetInventory(&Inventory{Outbounds: []Outbound{{Tag: "direct-a", Type: "direct"}, {Tag: "direct-b", Type: "direct"}, {Tag: "GLOBAL", Type: "direct"}, {Tag: "unused", Type: "socks"}, {Tag: "relay", Type: "socks", Bound: true}}})
	tags, e := c.Collect()
	if e != nil {
		t.Fatal(e)
	}
	if len(tags) != 4 {
		t.Fatal("collapsed or helper identities leaked", tags)
	}
	for _, n := range tags {
		if n.Name == "helper" || n.Name == "DIRECT" || n.Name == "unused" {
			t.Fatal("synthetic/unbound tag displayed")
		}
		if n.Upload == nil || *n.Upload != 0 {
			t.Fatal("idle direct disappeared")
		}
	}
	c.SetInventory(&Inventory{Outbounds: []Outbound{{Tag: "direct-b", Type: "direct"}, {Tag: "direct-new", Type: "direct"}}})
	tags, e = c.Collect()
	if e != nil || len(tags) != 2 || tags[0].Name != "direct-b" || tags[1].Name != "direct-new" {
		t.Fatal("inventory did not synchronize", tags, e)
	}
}
