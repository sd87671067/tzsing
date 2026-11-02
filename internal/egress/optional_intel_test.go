package egress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"tzsingbox/internal/model"
)

func TestProviderOptionalFieldCombinations(t *testing.T) {
	original := metadata
	defer func() { metadata = original }()
	for _, source := range []string{"ipinfo", "ippure"} {
		for _, isp := range []bool{false, true} {
			for _, typed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/isp=%v/type=%v", source, isp, typed), func(t *testing.T) {
					sources.entries = map[string]sourceEntry{}
					metadata = &ipinfo{token: "private-key", endpoint: "https://ipinfo.io/", state: intelState{Entries: map[string]intelEntry{}}}
					extra := ""
					if isp {
						extra += `,"isp":"Explicit ISP"`
					}
					if typed {
						if source == "ipinfo" {
							extra += `,"is_hosting":true`
						} else {
							extra += `,"isResidential":true`
						}
					}
					client := &http.Client{Transport: inspectTransport(func(r *http.Request) (*http.Response, error) {
						if source == "ippure" && r.Header.Get("Authorization") != "" {
							t.Fatal("credential leak")
						}
						body := `{"ip":"8.8.8.8","org":"AS1 Residential Hosting ISP","asOrganization":"Residential Hosting ISP","asn":1,"city":"City"` + extra + `}`
						return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					v := lookupSource(context.Background(), Proxy{}, source, "8.8.8.8", "fixture", client)
					if v.Data == nil {
						t.Fatal(v)
					}
					if (v.Data.ISP != "") != isp || (v.Data.IPType != "") != typed {
						t.Fatalf("optional fields: %+v", v.Data)
					}
					if typed {
						want := "机房"
						if source == "ippure" {
							want = "住宅"
						}
						if v.Data.IPType != want {
							t.Fatal(v.Data.IPType)
						}
					}
				})
			}
		}
	}
}
func TestOptionalIntelUnknownFalseConflictAndCacheReset(t *testing.T) {
	yes, no := true, false
	for _, placeholder := range []string{"", "unknown", "N/A", "null", "undefined", "未知", "  "} {
		v := model.Exit{ISP: placeholder, IPType: "互联网接入服务商", Residential: &no, Datacenter: &no}
		normalizeOptionalIntel(&v)
		if v.ISP != "" || v.IPType != "" {
			t.Fatal(v)
		}
	}
	v := model.Exit{ISP: "stale", Residential: &yes, Datacenter: &yes}
	normalizeOptionalIntel(&v)
	if v.IPType != "" {
		t.Fatal("conflicting classification", v)
	}
	copyIntel(&v, model.Exit{})
	if v.ISP != "" || v.IPType != "" || v.Residential != nil || v.Datacenter != nil {
		t.Fatal("stale cache fields", v)
	}
}
func TestIPinfoExplicitISPClassification(t *testing.T) {
	for _, kind := range []string{"isp", "hosting", "business", "education", "unknown"} {
		m := &ipinfo{token: "fixture", endpoint: "https://ipinfo.io/", state: intelState{Entries: map[string]intelEntry{}}}
		client := &http.Client{Transport: inspectTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"ip":"8.8.8.8","asn":{"asn":"AS1","name":"Example","type":"` + kind + `"}}`))}, nil
		})}
		v := model.Exit{}
		m.enrich(context.Background(), client, "8.8.8.8", &v)
		if (v.ISP != "") != (kind == "isp") || v.IPType != "" {
			t.Fatalf("classification is not IP type: %s %+v", kind, v)
		}
	}
}

func TestProviderMalformedOptionalFieldsRetainLocation(t *testing.T) {
	original := metadata
	defer func() { metadata = original }()
	for _, source := range []string{"ipinfo", "ippure"} {
		for _, value := range []string{`null`, `"unknown"`, `"N/A"`, `42`, `{}`} {
			sources.entries = map[string]sourceEntry{}
			metadata = &ipinfo{token: "fixture", endpoint: "https://ipinfo.io/", state: intelState{Entries: map[string]intelEntry{}}}
			client := &http.Client{Transport: inspectTransport(func(r *http.Request) (*http.Response, error) {
				body := `{"ip":"8.8.8.8","city":"Kept City","isp":` + value + `,"is_hosting":` + value + `,"isResidential":` + value + `,"isDatacenter":` + value + `,"isNative":` + value + `}`
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			v := lookupSource(context.Background(), Proxy{}, source, "8.8.8.8", "fixture", client)
			if v.Data == nil || v.Data.City != "Kept City" || v.Data.ISP != "" || v.Data.IPType != "" || v.Data.Native != nil {
				t.Fatalf("%s %s %+v", source, value, v)
			}
		}
	}
}
