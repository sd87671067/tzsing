package adapter

import (
	"encoding/binary"
	"testing"
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
