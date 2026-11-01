package adapter

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
	"net/http/httptest"
	"testing"
	"tzsingbox/internal/model"
)

func TestNativeRejectsRemoteRedirectAndMalformedCounters(t *testing.T) {
	for _, u := range []string{"http://example.com:8080", "https://127.0.0.1:8080", "http://127.0.0.1", "http://user:pass@127.0.0.1:8080", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080/?token=secret"} {
		if _, e := NewNative(u); e == nil {
			t.Fatal("unsafe native endpoint accepted")
		}
	}
	for _, b := range [][]byte{{0}, {0x0a, 0xff}, {0x0a, 0x02, 0x0a, 0xff}, {0x0a, 0x02, 0x10, 0x01}, {0x0a, 0x03, 0x0a, 1, 'x', 0x0a, 0x03, 0x0a, 1, 'x'}} {
		if _, e := decodeStats(b); e == nil {
			t.Fatal("bad stats accepted", b)
		}
	}
	name := "user>>>fixture>>>traffic>>>uplink"
	v := []byte{0x0a, byte(len(name))}
	v = append(v, []byte(name)...)
	v = append(v, 0x10)
	v = binary.AppendUvarint(v, 123456)
	b := []byte{0x0a, byte(len(v))}
	b = append(b, v...)
	out, e := decodeStats(b)
	if e != nil || out[name] != 123456 {
		t.Fatal("valid native protobuf failed", e)
	}
}

// Real h2c transport with controlled upstream counter responses. These fixtures
// validate error handling; payload attribution is separately exercised over REALITY.
func TestNativeMissingPairRecoveryAndBindingChange(t *testing.T) {
	values := map[string]int64{}
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		for name, value := range values {
			stat := []byte{0x0a}
			stat = binary.AppendUvarint(stat, uint64(len(name)))
			stat = append(stat, []byte(name)...)
			stat = append(stat, 0x10)
			stat = binary.AppendUvarint(stat, uint64(value))
			payload = append(payload, 0x0a)
			payload = binary.AppendUvarint(payload, uint64(len(stat)))
			payload = append(payload, stat...)
		}
		frame := make([]byte, 5)
		binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(append(frame, payload...))
		w.Header().Set("Grpc-Status", "0")
	}), &http2.Server{}))
	defer server.Close()
	n, e := NewNative(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	id := model.UUIDAuthID("00000000-0000-4000-8000-000000000001")
	key := model.IdentityName("shared", id)
	inv := &Inventory{ConfigHash: "config-a", Inbounds: []Inbound{{Tag: "shared", NativeUsers: map[string]string{id: model.AuthID("fixture")}}}}
	tags := []model.Tag{{Name: key, AuthID: id, Accounting: "unavailable", State: "unknown"}}
	collect := func() {
		t.Helper()
		if e := n.Collect(context.Background(), inv, tags); e != nil {
			t.Fatal(e)
		}
	}
	collect()
	if tags[0].Up != nil || tags[0].Accounting != "unavailable" {
		t.Fatal("empty API claimed verified zero")
	}
	values["user>>>fixture>>>traffic>>>uplink"] = 100
	collect()
	if tags[0].Upload != nil {
		t.Fatal("partial counter became valid")
	}
	values["user>>>fixture>>>traffic>>>downlink"] = 200
	collect()
	if tags[0].Upload == nil || *tags[0].Upload != 100 || *tags[0].Download != 200 || tags[0].Active != nil || tags[0].State != "online" {
		t.Fatal("recovery or unknown active count")
	}
	delete(values, "user>>>fixture>>>traffic>>>downlink")
	values["user>>>fixture>>>traffic>>>uplink"] = 150
	collect()
	if tags[0].Up != nil || tags[0].Upload != nil {
		t.Fatal("partial read exposed counters")
	}
	values["user>>>fixture>>>traffic>>>downlink"] = 300
	collect()
	if *tags[0].Upload != 150 || *tags[0].Download != 300 {
		t.Fatal("partial response advanced baseline")
	}
	inv.ConfigHash = "config-b"
	values["user>>>fixture>>>traffic>>>uplink"] = 1000
	values["user>>>fixture>>>traffic>>>downlink"] = 2000
	collect()
	if *tags[0].Upload != 150 || *tags[0].Download != 300 {
		t.Fatal("config switch invented usage")
	}
	inv.Inbounds = nil
	collect()
	inv.Inbounds = []Inbound{{Tag: "shared", NativeUsers: map[string]string{id: model.AuthID("fixture")}}}
	values["user>>>fixture>>>traffic>>>uplink"] = 5000
	collect()
	if *tags[0].Upload != 150 {
		t.Fatal("removed binding reused baseline")
	}
}
