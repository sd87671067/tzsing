package egress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"tzsingbox/internal/model"
)

type Check struct {
	Status       string `json:"status"`
	Detail       string `json:"detail"`
	Milliseconds int64  `json:"milliseconds,omitempty"`
	IP           string `json:"ip,omitempty"`
}
type PathResult struct {
	IPv4      Check `json:"ipv4"`
	IPv6      Check `json:"ipv6"`
	Attempts  int   `json:"attempts"`
	Successes int   `json:"successes"`
}

func fixedJSON(ctx context.Context, client *http.Client, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("provider unavailable")
	}
	return json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(dst)
}
func status(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "error"
}
func publicIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// Fixed HTTPS targets, one attempt per family, no caller-supplied host or URL.
func CheckPath(ctx context.Context, p Proxy) PathResult {
	result := PathResult{}
	client, closeClient, err := PathClient(p)
	if err != nil {
		result.IPv4 = Check{Status: "unverified", Detail: "没有已核实的专用路径"}
		result.IPv6 = result.IPv4
		return result
	}
	defer closeClient()
	client.Timeout = 6 * time.Second
	for _, family := range []int{4, 6} {
		out := Check{Status: "error", Detail: "固定 HTTPS 目标连接失败"}
		endpoint := "https://api.ipify.org?format=json"
		if family == 6 {
			endpoint = "https://api6.ipify.org?format=json"
		}
		success := 0
		var elapsed int64
		var timedout bool
		for n := 0; n < 1; n++ {
			result.Attempts++
			start := time.Now()
			var v struct {
				IP string `json:"ip"`
			}
			err := fixedJSON(ctx, client, endpoint, &v)
			elapsed += time.Since(start).Milliseconds()
			if err == nil && publicIP(v.IP) && ((net.ParseIP(v.IP).To4() != nil) == (family == 4)) {
				success++
				result.Successes++
				out.IP = v.IP
			} else if status(err) == "timeout" {
				timedout = true
			}
		}
		out.Milliseconds = elapsed
		if success > 0 {
			out.Status = "ok"
			out.Detail = strconv.Itoa(success) + "/1 次 HTTPS 请求成功"
		} else if timedout {
			out.Status = "timeout"
			out.Detail = "固定 HTTPS 目标连接超时；未证明该地址族可用"
		}
		if family == 4 {
			result.IPv4 = out
		} else {
			result.IPv6 = out
		}
	}
	return result
}

type SourceResult struct {
	Source  string      `json:"source"`
	At      int64       `json:"at,omitempty"`
	Cached  bool        `json:"cached"`
	IP      string      `json:"ip,omitempty"`
	Data    *model.Exit `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}
type sourceEntry struct {
	until time.Time
	value SourceResult
}

var sources = struct {
	sync.Mutex
	entries map[string]sourceEntry
}{entries: map[string]sourceEntry{}}

// Independent provider caches; failures also get a short cache to stop repeated
// source toggles from hammering an unavailable service. Caller serializes probes.
func LookupSource(ctx context.Context, p Proxy, source, expected, path string) SourceResult {
	return lookupSource(ctx, p, source, expected, path, nil)
}
func lookupSource(ctx context.Context, p Proxy, source, expected, path string, override *http.Client) SourceResult {
	out := SourceResult{Source: source}
	if source != "ipinfo" && source != "ippure" {
		out.Message = "不支持的数据源"
		return out
	}
	if !publicIP(expected) {
		out.Message = "尚无经当前路径验证的出口 IP，请先检测"
		return out
	}
	key := source + "|" + expected
	if source == "ippure" {
		key += "|" + path
	}
	sources.Lock()
	entry, found := sources.entries[key]
	sources.Unlock()
	if found && time.Now().Before(entry.until) {
		out = entry.value
		out.Cached = true
		return out
	}
	client, closeClient, err := PathClient(p)
	if override != nil {
		client = override
		closeClient = func() {}
		err = nil
	}
	if err != nil {
		out.Message = "当前路径未知，无法查询该出口"
		return out
	}
	defer closeClient()
	client.Timeout = 8 * time.Second
	now := time.Now()
	ttl := time.Minute
	out.IP = expected
	if source == "ipinfo" {
		dst := model.Exit{}
		metadata.enrich(ctx, client, expected, &dst)
		if dst.MetadataAt > 0 {
			out.At = dst.MetadataAt
			out.Data = &dst
			out.Cached = dst.MetadataCached
			ttl = 24 * time.Hour
			if now.Unix()-out.At >= 86400 {
				ttl = time.Minute
				out.Message = "IPinfo 暂不可用，显示上次缓存"
			}
		} else {
			out.Message = "IPinfo 暂不可用或当前凭据未提供此数据"
		}
	} else {
		// Official https://ippure.com/MyIP-Info-API: this endpoint reports
		// the caller's IP only. Never request arbitrary-IP pages or bypass controls.
		var v struct {
			IP          string `json:"ip"`
			ASN         int64  `json:"asn"`
			Org         string `json:"asOrganization"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
			City        string `json:"city"`
			Fraud       *int   `json:"fraudScore"`
			Residential *bool  `json:"isResidential"`
			Broadcast   *bool  `json:"isBroadcast"`
		}
		err = fixedJSON(ctx, client, "https://my.ippure.com/v1/info", &v)
		if err != nil {
			out.Message = "IPPure 官方接口暂不可用，请稍后重试；IPinfo 仍可使用"
		} else if !publicIP(v.IP) || !net.ParseIP(v.IP).Equal(net.ParseIP(expected)) {
			out.Message = "IPPure 返回的出口与当前缓存不一致；未关联质量信息，请重新检测"
		} else {
			dst := model.Exit{Country: v.Country, CountryCode: v.CountryCode, City: v.City, Org: v.Org, Residential: v.Residential, GeoSource: "IPPure 官方公开 API", MetadataAt: now.Unix()}
			if v.ASN > 0 {
				dst.ASN = "AS" + strconv.FormatInt(v.ASN, 10)
			}
			if v.Fraud != nil && *v.Fraud >= 0 && *v.Fraud <= 100 {
				dst.RiskScore = v.Fraud
				dst.QualityIP = expected
				dst.QualitySource = "IPPure fraudScore（来源值）"
				dst.QualityAt = now.Unix()
			}
			// isBroadcast is not a residential, native or datacenter assertion.
			out.Data = &dst
			out.At = now.Unix()
			ttl = 24 * time.Hour
		}
	}
	sources.Lock()
	defer sources.Unlock()
	if len(sources.entries) >= 512 {
		for k, v := range sources.entries {
			if now.After(v.until) {
				delete(sources.entries, k)
			}
		}
		if len(sources.entries) >= 512 {
			for k := range sources.entries {
				delete(sources.entries, k)
				break
			}
		}
	}
	sources.entries[key] = sourceEntry{until: now.Add(ttl), value: out}
	return out
}
