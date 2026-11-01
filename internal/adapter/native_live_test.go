package adapter

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

// Explicit opt-in, synthetic config only. Run the test binary in its own network
// namespace so a shared REALITY listener can actually bind 443 safely.
func TestNativeTwelveUUIDRealityRoutingAndClosedTraffic(t *testing.T) {
	binaryPath := os.Getenv("TZSING_NATIVE_TEST_BINARY")
	if binaryPath == "" {
		t.Skip("isolated native binary required")
	}
	if os.Getenv("TZSING_ISOLATED_NETNS") != "1" {
		t.Fatal("isolated network namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("handshake")) }))
	hs.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	hs.StartTLS()
	defer hs.Close()
	handshakeHost, handshakePort, _ := net.SplitHostPort(hs.Listener.Addr().String())
	var hp int
	fmt.Sscan(handshakePort, &hp)
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	port := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	statsPort, clashPort := port(), port()
	users := []any{}
	names := []string{}
	clientIns, clientOuts, rules, clientRules := []any{}, []any{}, []any{}, []any{}
	ports := []int{}
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("fixture-%02d", i)
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1)
		names = append(names, name)
		users = append(users, map[string]any{"name": name, "uuid": id, "flow": "xtls-rprx-vision"})
		p := port()
		ports = append(ports, p)
		tag := fmt.Sprintf("client-%d", i)
		clientIns = append(clientIns, map[string]any{"type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": p})
		clientOuts = append(clientOuts, map[string]any{"type": "vless", "tag": tag, "server": "127.0.0.1", "server_port": 443, "uuid": id, "flow": "xtls-rprx-vision", "tls": map[string]any{"enabled": true, "server_name": "localhost", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "short_id": "0123456789abcdef"}}})
		rules = append(rules, map[string]any{"inbound": []string{"shared"}, "auth_user": []string{name}, "action": "route", "outbound": fmt.Sprintf("direct-%d", i%2)})
		clientRules = append(clientRules, map[string]any{"inbound": []string{tag}, "action": "route", "outbound": tag})
	}
	server := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": 443, "users": users, "tls": map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": handshakeHost, "server_port": hp}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct-0", "inet4_bind_address": "127.0.0.2"}, map[string]any{"type": "direct", "tag": "direct-1", "inet4_bind_address": "127.0.0.3"}}, "route": map[string]any{"rules": rules}, "experimental": map[string]any{"v2ray_api": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", statsPort), "stats": map[string]any{"enabled": true, "users": names}}, "clash_api": map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", clashPort)}}}
	client := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": clientIns, "outbounds": clientOuts, "route": map[string]any{"rules": clientRules}}
	start := func(config any, name string) {
		b, _ := json.Marshal(config)
		path := filepath.Join(t.TempDir(), name+".json")
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		check := exec.CommandContext(ctx, binaryPath, "check", "-c", path)
		if out, e := check.CombinedOutput(); e != nil {
			t.Fatalf("synthetic check: %v %s", e, out)
		}
		cmd := exec.CommandContext(ctx, binaryPath, "run", "-c", path)
		var log bytes.Buffer
		cmd.Stderr = &log
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			cmd.Process.Kill()
			cmd.Wait()
			if t.Failed() {
				t.Log(log.String())
			}
		})
	}
	start(server, "server")
	start(client, "client")
	wait := func(p int) {
		for i := 0; i < 100; i++ {
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 50*time.Millisecond)
			if e == nil {
				c.Close()
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("isolated listener not ready")
	}
	wait(statsPort)
	wait(ports[0])
	meter, e := NewNative(fmt.Sprintf("http://127.0.0.1:%d", statsPort))
	if e != nil {
		t.Fatal(e)
	}
	inv := &Inventory{Inbounds: []Inbound{{Tag: "shared", NativeUsers: map[string]string{}}}}
	tags := []model.Tag{}
	for i, name := range names {
		id := model.UUIDAuthID(fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1))
		inv.Inbounds[0].NativeUsers[id] = model.AuthID(name)
		tags = append(tags, model.Tag{Name: model.IdentityName("shared", id), AuthID: id, AuthScheme: "uuid-v1", InboundTag: "shared", Identity: "inbound", Type: "vless", Accounting: "unavailable"})
	}
	if e = meter.Collect(ctx, inv, tags); e != nil {
		t.Fatal(e)
	}
	for i, p := range ports {
		origin, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() {
			c, e := origin.Accept()
			if e != nil {
				done <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			want := fmt.Sprintf("127.0.0.%d", 2+i%2)
			if !strings.HasPrefix(c.RemoteAddr().String(), want+":") {
				done <- fmt.Errorf("wrong routed peer %s", c.RemoteAddr())
				return
			}
			b := make([]byte, 32768+i*1024)
			if _, e = io.ReadFull(c, b); e == nil {
				_, e = c.Write(bytes.Repeat([]byte{7}, 65536+i*2048))
			}
			done <- e
		}()
		dialer, e := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", p), nil, &net.Dialer{Timeout: 5 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		c, e := dialer.Dial("tcp", origin.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = c.Write(bytes.Repeat([]byte{3}, 32768+i*1024)); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(c, make([]byte, 65536+i*2048)); e != nil {
			t.Fatal(e)
		}
		c.Close()
		if e = <-done; e != nil {
			t.Fatal(e)
		}
		origin.Close()
		if e = meter.Collect(ctx, inv, tags); e != nil {
			t.Fatal(e)
		}
		for j, tag := range tags {
			wantUp, wantDown := int64(0), int64(0)
			if j <= i {
				wantUp = int64(32768 + j*1024)
				wantDown = int64(65536 + j*2048)
			}
			if j > i {
				if tag.Upload != nil || tag.Accounting != "unavailable" {
					t.Fatal("idle identity claimed verified traffic")
				}
				continue
			}
			if tag.Upload == nil || *tag.Upload != wantUp || tag.Download == nil || *tag.Download != wantDown || (j == i && (tag.Up == nil || *tag.Up <= 0)) {
				t.Fatalf("independent real transfer %d affected identity %d", i, j)
			}
		}
	}
	if path := os.Getenv("TZSING_NATIVE_REPORT_FILE"); path != "" {
		b, e := json.Marshal(tags)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	time.Sleep(100 * time.Millisecond)
	stats, e := meter.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for i, name := range names {
		if u, d := stats["user>>>"+name+">>>traffic>>>uplink"], stats["user>>>"+name+">>>traffic>>>downlink"]; u != int64(32768+i*1024) || d != int64(65536+i*2048) {
			t.Fatalf("per-user exact payload %s: up=%d down=%d", name, u, d)
		}
	}
	if e = meter.Collect(ctx, inv, tags); e != nil {
		t.Fatal(e)
	}
	for i, tag := range tags {
		if tag.Upload == nil || *tag.Upload != int64(32768+i*1024) || tag.Download == nil || *tag.Download != int64(65536+i*2048) || tag.Accounting != "native_user_observed" {
			t.Fatal("native adapter attribution failed")
		}
	}
	t.Log("12 REALITY UUIDs, one 443 listener, two independently verified outbound paths; distinct per-user closed-connection payloads exactly matched, no copying of totals")
}
