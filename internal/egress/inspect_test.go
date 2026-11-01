package egress

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type inspectTransport func(*http.Request) (*http.Response, error)

func (f inspectTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestIndependentSourceCacheAuthenticFieldsAndIPMismatch(t *testing.T) {
	sources.Lock()
	sources.entries = map[string]sourceEntry{}
	sources.Unlock()
	original := metadata
	defer func() { metadata = original }()
	metadata = &ipinfo{token: "synthetic-secret", endpoint: "https://ipinfo.io/", state: intelState{Entries: map[string]intelEntry{}}}
	calls := map[string]int{}
	wrongIP := false
	client := &http.Client{Transport: inspectTransport(func(r *http.Request) (*http.Response, error) {
		calls[r.URL.Host]++
		body := ""
		if r.URL.Host == "ipinfo.io" {
			if r.Header.Get("Authorization") != "Bearer synthetic-secret" || r.URL.RawQuery != "" {
				t.Error("credential boundary")
			}
			body = `{"ip":"8.8.8.8","org":"AS15169 Example","country":"US"}`
		} else if r.URL.String() == "https://my.ippure.com/v1/info" {
			if r.Header.Get("Authorization") != "" {
				t.Error("token crossed provider boundary")
			}
			body = `{"ip":"8.8.8.8","asn":15169,"isResidential":false,"fraudScore":0,"isBroadcast":true}`
			if wrongIP {
				body = `{"ip":"1.1.1.1","fraudScore":99}`
			}
		} else {
			t.Fatal("unexpected target", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	for n := 0; n < 2; n++ {
		a := lookupSource(context.Background(), Proxy{}, "ipinfo", "8.8.8.8", "route", client)
		b := lookupSource(context.Background(), Proxy{}, "ippure", "8.8.8.8", "route", client)
		if a.Data == nil || a.Data.RiskScore != nil || a.Data.Residential != nil {
			t.Fatal("fabricated IPinfo fields", a)
		}
		if b.Data == nil || b.Data.RiskScore == nil || *b.Data.RiskScore != 0 || b.Data.Residential == nil || *b.Data.Residential || b.Data.Datacenter != nil {
			t.Fatal("source fields lost/invented", b)
		}
		if n == 1 && (!a.Cached || !b.Cached) {
			t.Fatal("missing independent cache")
		}
	}
	if calls["ipinfo.io"] != 1 || calls["my.ippure.com"] != 1 {
		t.Fatal("repeated cached source requests", calls)
	}
	wrongIP = true
	b := lookupSource(context.Background(), Proxy{}, "ippure", "8.8.8.8", "different-route", client)
	if b.Data != nil || b.Message == "" {
		t.Fatal("wrong exit metadata attached")
	}
	for _, source := range []string{"ippure", "http://127.0.0.1"} {
		a := lookupSource(context.Background(), Proxy{}, source, "127.0.0.1", "route", client)
		if a.Data != nil {
			t.Fatal("invalid target accepted")
		}
	}
}
func TestSourceFailureBackoffIsIndependent(t *testing.T) {
	sources.Lock()
	sources.entries = map[string]sourceEntry{}
	sources.Unlock()
	calls := 0
	client := &http.Client{Transport: inspectTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, context.DeadlineExceeded })}
	for n := 0; n < 2; n++ {
		out := lookupSource(context.Background(), Proxy{}, "ippure", "1.1.1.1", "failure", client)
		if out.Data != nil || out.Message == "" {
			t.Fatal(out)
		}
	}
	if calls != 1 || status(context.DeadlineExceeded) != "timeout" {
		t.Fatal("failure cache/timeout")
	}
}
