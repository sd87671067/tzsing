package egress

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"tzsingbox/internal/model"
)

type intelEntry struct {
	At    int64      `json:"at"`
	Value model.Exit `json:"value"`
}
type intelState struct {
	Entries map[string]intelEntry `json:"entries"`
	Day     string                `json:"day"`
	Month   string                `json:"month"`
	Daily   int                   `json:"daily"`
	Monthly int                   `json:"monthly"`
}
type ipinfo struct {
	mu                    sync.Mutex
	token, endpoint, file string
	state                 intelState
	next                  time.Time
	failures              int
}

// Credentials are never part of reports, persisted cache, URLs or errors.
func newIPinfo() *ipinfo {
	token := os.Getenv("IPINFO_TOKEN")
	if f := os.Getenv("IPINFO_TOKEN_FILE"); f != "" {
		if b, e := os.ReadFile(f); e == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	m := &ipinfo{token: token, endpoint: "https://ipinfo.io/", file: os.Getenv("IPINFO_CACHE_FILE")}
	if m.file != "" {
		if b, e := os.ReadFile(m.file); e == nil && len(b) <= 2<<20 {
			_ = json.Unmarshal(b, &m.state)
		}
	}
	if m.state.Entries == nil {
		m.state.Entries = map[string]intelEntry{}
	}
	return m
}

var metadata = newIPinfo()

func (m *ipinfo) save() {
	if m.file == "" {
		return
	}
	b, e := json.Marshal(m.state)
	if e != nil {
		return
	}
	tmp := m.file + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, m.file)
	}
}

func (m *ipinfo) enrich(ctx context.Context, client *http.Client, ip string, dst *model.Exit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	old, found := m.state.Entries[ip]
	if found {
		copyIntel(dst, old.Value)
		dst.MetadataAt = old.At
		dst.MetadataCached = true
	}
	if m.token == "" || (found && now.Unix()-old.At < 86400) || now.Before(m.next) {
		return
	}
	day, month := now.UTC().Format("2006-01-02"), now.UTC().Format("2006-01")
	if m.state.Day != day {
		m.state.Day = day
		m.state.Daily = 0
	}
	if m.state.Month != month {
		m.state.Month = month
		m.state.Monthly = 0
	}
	// Conservative hard budgets, persisted before the request, including failures.
	if m.state.Daily >= 400 || m.state.Monthly >= 8000 {
		return
	}
	m.state.Daily++
	m.state.Monthly++
	m.next = now.Add(time.Second)
	m.save()
	req, e := http.NewRequestWithContext(ctx, "GET", m.endpoint+ip+"/json", nil)
	if e != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Accept", "application/json")
	res, e := client.Do(req)
	if e != nil {
		m.failed(now)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		m.failed(now)
		if res.StatusCode == 429 {
			m.next = now.Add(24 * time.Hour)
		}
		if res.StatusCode == 401 || res.StatusCode == 403 {
			m.next = now.Add(time.Hour)
		}
		return
	}
	var v struct {
		IP          string          `json:"ip"`
		Country     string          `json:"country"`
		CountryCode string          `json:"country_code"`
		City        string          `json:"city"`
		Org         string          `json:"org"`
		ASN         json.RawMessage `json:"asn"`
		Geo         struct {
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
		} `json:"geo"`
		Company struct {
			Type string `json:"type"`
		} `json:"company"`
		Privacy struct {
			Hosting *bool `json:"hosting"`
		} `json:"privacy"`
		Hosting *bool `json:"is_hosting"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(&v) != nil || net.ParseIP(v.IP) == nil || !net.ParseIP(v.IP).Equal(net.ParseIP(ip)) {
		m.failed(now)
		return
	}
	// Clear old optional values before accepting a fresh source response.
	fresh := model.Exit{GeoSource: "IPinfo · 已验证出口的归属信息", MetadataAt: now.Unix()}
	fresh.Country = v.Country
	fresh.CountryCode = v.CountryCode
	fresh.City = v.City
	if len(v.Country) == 2 && v.CountryCode == "" {
		fresh.CountryCode = v.Country
		fresh.Country = ""
	}
	if v.Geo.Country != "" {
		fresh.Country = v.Geo.Country
	}
	if v.Geo.CountryCode != "" {
		fresh.CountryCode = v.Geo.CountryCode
	}
	if v.Geo.City != "" {
		fresh.City = v.Geo.City
	}
	parts := strings.SplitN(v.Org, " ", 2)
	if len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
		fresh.ASN = parts[0]
		if len(parts) == 2 {
			fresh.Org = parts[1]
		}
	} else {
		fresh.Org = v.Org
	}
	var asn string
	if json.Unmarshal(v.ASN, &asn) == nil {
		fresh.ASN = asn
	} else {
		var obj struct{ ASN, Name, Type string }
		if json.Unmarshal(v.ASN, &obj) == nil {
			fresh.ASN = obj.ASN
			if obj.Name != "" {
				fresh.Org = obj.Name
			}
			fresh.IPType = ipType(obj.Type)
		}
	}
	if fresh.IPType == "" {
		fresh.IPType = ipType(v.Company.Type)
	}
	fresh.Datacenter = v.Privacy.Hosting
	if v.Hosting != nil {
		fresh.Datacenter = v.Hosting
	}
	if fresh.Datacenter != nil {
		fresh.QualitySource = "IPinfo · 来源明确返回的托管属性"
		fresh.QualityIP = ip
		fresh.QualityAt = now.Unix()
	}
	copyIntel(dst, fresh)
	dst.MetadataAt = fresh.MetadataAt
	dst.MetadataCached = false
	if len(m.state.Entries) >= 512 && !found {
		var key string
		var at int64
		for k, v := range m.state.Entries {
			if key == "" || v.At < at {
				key = k
				at = v.At
			}
		}
		delete(m.state.Entries, key)
	}
	m.state.Entries[ip] = intelEntry{At: now.Unix(), Value: fresh}
	m.failures = 0
	m.save()
}
func (m *ipinfo) failed(now time.Time) {
	m.failures = min(m.failures+1, 6)
	m.next = now.Add(time.Duration(30*(1<<m.failures)) * time.Second)
}
func ipType(v string) string {
	switch v {
	case "isp":
		return "互联网接入服务商"
	case "hosting":
		return "托管网络"
	case "business":
		return "企业网络"
	case "education":
		return "教育网络"
	}
	return ""
}
func copyIntel(dst *model.Exit, src model.Exit) {
	dst.Country = src.Country
	dst.CountryCode = src.CountryCode
	dst.City = src.City
	dst.ASN = src.ASN
	dst.Org = src.Org
	dst.GeoSource = src.GeoSource
	dst.IPType = src.IPType
	dst.Residential = src.Residential
	dst.Datacenter = src.Datacenter
	dst.RiskScore = src.RiskScore
	dst.QualitySource = src.QualitySource
	dst.QualityAt = src.QualityAt
	dst.QualityIP = src.QualityIP
	dst.QualityError = src.QualityError
}
