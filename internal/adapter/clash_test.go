package adapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLowerBoundSingleAttribution(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutating method")
		}
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("authentication missing")
		}
		if r.URL.Path == "/proxies" {
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"physical": Proxy{Type: "SOCKS"}, "selector": Proxy{Type: "Selector", Now: "physical"}}})
			return
		}
		n++
		cs := []Connection{{ID: "a", Chains: []string{"physical", "selector"}, Upload: int64(100 * n), Download: int64(200 * n)}}
		if n == 3 {
			cs = append(cs, Connection{ID: "new", Chains: []string{"physical", "selector"}, Upload: 50, Download: 80})
		}
		json.NewEncoder(w).Encode(Snapshot{Connections: cs})
	}))
	defer srv.Close()
	a := New(srv.URL, "fixture")
	for i := 0; i < 3; i++ {
		tags, e := a.Collect()
		if e != nil {
			t.Fatal(e)
		}
		for _, tag := range tags {
			if tag.Kind == "logical" && tag.Upload != nil {
				t.Fatal("logical traffic duplicated")
			}
			if tag.Kind == "actual" {
				want := int64(i * 100)
				if i == 2 {
					want += 50
				}
				if *tag.Upload != want {
					t.Fatalf("sample %d: %d want %d", i, *tag.Upload, want)
				}
			}
		}
	}
}

func TestMultipleDirectCountersNeverMerge(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]Proxy{"a": {Type: "Direct"}, "b": {Type: "Direct"}, "logical": {Type: "Selector", Now: "a"}, "reject": {Type: "Reject"}}})
			return
		}
		n++
		json.NewEncoder(w).Encode(Snapshot{Connections: []Connection{{ID: "one", Chains: []string{"a", "logical"}, Upload: int64(n * 10), Download: int64(n * 20)}, {ID: "two", Chains: []string{"b"}, Upload: int64(n * 30), Download: int64(n * 40)}}})
	}))
	defer srv.Close()
	c := New(srv.URL, "")
	c.Collect()
	tags, e := c.Collect()
	if e != nil {
		t.Fatal(e)
	}
	for _, tag := range tags {
		switch tag.Name {
		case "a":
			if *tag.Upload != 10 || *tag.Download != 20 {
				t.Fatal("direct a", tag)
			}
		case "b":
			if *tag.Upload != 30 || *tag.Download != 40 {
				t.Fatal("direct b", tag)
			}
		default:
			if tag.Upload != nil || tag.Download != nil {
				t.Fatal("logical/block counted", tag)
			}
		}
	}
}
