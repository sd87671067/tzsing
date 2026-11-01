package adapter

// The optional native adapter reads sing-box 1.13 V2Ray StatsService over local
// h2c. It never resets counters. No new daemon, credentials or public API port.
import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"tzsingbox/internal/model"
)

type Native struct {
	client           *http.Client
	endpoint         string
	previous, totals map[string]count
	last             time.Time
}

func NewNative(endpoint string) (*Native, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.Port() == "" {
		return nil, fmt.Errorf("native stats requires explicit loopback HTTP endpoint")
	}
	tr := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, addr)
	}}
	return &Native{endpoint: strings.TrimRight(endpoint, "/"), client: &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, previous: map[string]count{}, totals: map[string]count{}}, nil
}

// Small bounded decoder for the upstream Stat{name=1,value=2} wire contract.
// Unknown protobuf fields are skipped, malformed lengths/types are rejected.
func varint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0, fmt.Errorf("invalid stats varint")
	}
	return v, n, nil
}
func fields(b []byte, visit func(int, int, []byte, uint64) error) error {
	for len(b) > 0 {
		key, n, e := varint(b)
		if e != nil {
			return e
		}
		b = b[n:]
		num, wire := int(key>>3), int(key&7)
		if num == 0 {
			return fmt.Errorf("invalid stats field")
		}
		var data []byte
		var v uint64
		switch wire {
		case 0:
			v, n, e = varint(b)
			if e != nil {
				return e
			}
			b = b[n:]
		case 2:
			v, n, e = varint(b)
			if e != nil || v > uint64(len(b)-n) {
				return fmt.Errorf("invalid stats length")
			}
			data = b[n : n+int(v)]
			b = b[n+int(v):]
		case 1:
			if len(b) < 8 {
				return io.ErrUnexpectedEOF
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return io.ErrUnexpectedEOF
			}
			b = b[4:]
		default:
			return fmt.Errorf("invalid stats wire type")
		}
		if e = visit(num, wire, data, v); e != nil {
			return e
		}
	}
	return nil
}
func decodeStats(b []byte) (map[string]int64, error) {
	out := map[string]int64{}
	e := fields(b, func(num, wire int, data []byte, _ uint64) error {
		if num != 1 {
			return nil
		}
		if wire != 2 {
			return fmt.Errorf("invalid stat")
		}
		name := ""
		var value int64
		e := fields(data, func(n, w int, d []byte, v uint64) error {
			switch n {
			case 1:
				if w != 2 || len(d) > 512 {
					return fmt.Errorf("invalid stat name")
				}
				name = string(d)
			case 2:
				if w != 0 || v > 1<<63-1 {
					return fmt.Errorf("invalid stat value")
				}
				value = int64(v)
			}
			return nil
		})
		if e != nil {
			return e
		}
		if name == "" {
			return fmt.Errorf("missing stat name")
		}
		if _, exists := out[name]; exists {
			return fmt.Errorf("duplicate stat")
		}
		out[name] = value
		return nil
	})
	return out, e
}
func (n *Native) Read(ctx context.Context) (map[string]int64, error) {
	// Empty QueryStatsRequest requests all counters with reset=false.
	req, e := http.NewRequestWithContext(ctx, "POST", n.endpoint+"/v2ray.core.app.stats.command.StatsService/QueryStats", bytes.NewReader(make([]byte, 5)))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	res, e := n.client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("native stats unavailable")
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if e != nil || len(b) > 2<<20 || res.StatusCode != 200 || len(b) < 5 || b[0] != 0 || int(binary.BigEndian.Uint32(b[1:5])) != len(b)-5 {
		return nil, fmt.Errorf("invalid native response")
	}
	status := res.Trailer.Get("Grpc-Status")
	if status == "" {
		status = res.Header.Get("Grpc-Status")
	}
	if status != "0" {
		return nil, fmt.Errorf("native stats RPC failed")
	}
	return decodeStats(b[5:])
}

func (n *Native) Collect(ctx context.Context, inv *Inventory, tags []model.Tag) error {
	values, e := n.Read(ctx)
	if e != nil {
		return e
	}
	now := time.Now()
	elapsed := now.Sub(n.last).Seconds()
	// The exporter attests that each username is globally unique and explicitly
	// enabled in stats.users. The API key is authenticated metadata.User, not a guess.
	byHash := map[string]count{}
	for key, value := range values {
		parts := strings.Split(key, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		id := model.AuthID(parts[1])
		c := byHash[id]
		if parts[3] == "uplink" {
			c.up = value
		} else if parts[3] == "downlink" {
			c.down = value
		}
		byHash[id] = c
	}
	bindings := map[string]string{}
	if inv != nil {
		for _, in := range inv.Inbounds {
			for id, userHash := range in.NativeUsers {
				bindings[model.IdentityName(in.Tag, id)] = userHash
			}
		}
	}
	for i := range tags {
		t := &tags[i]
		hash, ok := bindings[t.Name]
		if !ok || t.AuthID == "" {
			continue
		}
		raw := byHash[hash]
		prev, seen := n.previous[t.Name]
		du, dd := int64(0), int64(0)
		// Start/reset is a baseline, never a guessed bill. Native counters include
		// finished short connections, but unpersisted process/crash tails may be lost.
		if seen && raw.up >= prev.up && raw.down >= prev.down {
			du = raw.up - prev.up
			dd = raw.down - prev.down
		}
		n.previous[t.Name] = raw
		total := n.totals[t.Name]
		total.up += du
		total.down += dd
		n.totals[t.Name] = total
		up, down := float64(0), float64(0)
		if seen && elapsed > 0 {
			up = float64(du) / elapsed
			down = float64(dd) / elapsed
		}
		t.Accounting = "native_user_observed"
		t.Up = &up
		t.Down = &down
		t.Upload = &total.up
		t.Download = &total.down
		t.Active = nil
	}
	n.last = now
	return nil
}
