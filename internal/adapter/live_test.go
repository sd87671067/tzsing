package adapter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestLiveSnapshotAttribution(t *testing.T) {
	if os.Getenv("TZ_LIVE") != "1" {
		t.Skip("explicit live opt-in")
	}
	b, e := os.ReadFile("/etc/tzsingbox/agent.json")
	if e != nil {
		t.Fatal(e)
	}
	var cfg struct {
		URL    string `json:"clash_url"`
		Secret string `json:"clash_secret"`
	}
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	fetch := func(path string) []byte {
		req, _ := http.NewRequest("GET", cfg.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+cfg.Secret)
		r, e := client.Do(req)
		if e != nil {
			t.Fatal("Clash unavailable")
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			t.Fatal("Clash status", r.StatusCode)
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		return b
	}
	proxies := fetch("/proxies")
	first := fetch("/connections")
	time.Sleep(2 * time.Second)
	second := fetch("/connections")
	var p struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	var a, z Snapshot
	json.Unmarshal(proxies, &p)
	json.Unmarshal(first, &a)
	json.Unmarshal(second, &z)
	previous := map[string]Connection{}
	for _, c := range a.Connections {
		previous[c.ID] = c
	}
	expected := map[string]int64{}
	for _, c := range z.Connections {
		if len(c.Chains) == 0 {
			continue
		}
		name := c.Chains[0]
		if pp, ok := p.Proxies[name]; !ok || pp.Now != "" {
			continue
		}
		du := c.Upload
		if old, ok := previous[c.ID]; ok {
			du = 0
			if len(old.Chains) > 0 && old.Chains[0] == name {
				du = max(0, c.Upload-old.Upload)
			}
		}
		expected[name] += du
	}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxies" {
			w.Write(proxies)
			return
		}
		n++
		if n == 1 {
			w.Write(first)
		} else {
			w.Write(second)
		}
	}))
	defer srv.Close()
	adapter := New(srv.URL, "")
	if _, e = adapter.Collect(); e != nil {
		t.Fatal(e)
	}
	tags, e := adapter.Collect()
	if e != nil {
		t.Fatal(e)
	}
	actual := 0
	for _, tag := range tags {
		if tag.Kind != "actual" {
			if tag.Upload != nil {
				t.Fatal("logical double attribution")
			}
			continue
		}
		actual++
		if tag.Upload == nil || *tag.Upload != expected[tag.Name] {
			t.Fatal("actual snapshot attribution mismatch", tag.Name)
		}
	}
	t.Logf("real snapshots: %d / %d connections; %d actual tags matched independent connection-ID delta calculation; no claim of complete closed-connection accounting", len(a.Connections), len(z.Connections), actual)
}
