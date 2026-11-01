package control

import (
	"bytes"
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
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"tzsingbox/policy"
)

// Real payload test, not a Clash snapshot fixture. Runs only in a new network
// namespace; its 443, REALITY keys, identities and SQLite files are disposable.
func TestIsolatedPolicyFourteenUUIDRealityPayload(t *testing.T) {
	if os.Getenv("TZSING_ISOLATED_NETNS") != "1" {
		t.Skip("isolated network namespace required")
	}
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Skip("explicit experimental binary required")
	}
	dir := t.TempDir()
	defer func() {
		if t.Failed() {
			for _, name := range []string{"server", "clients"} {
				b, _ := os.ReadFile(filepath.Join(dir, name+".log"))
				if len(b) > 4000 {
					b = b[len(b)-4000:]
				}
				t.Log(name, string(b))
			}
		}
	}()
	dbpath := filepath.Join(dir, "policy.sqlite")
	ledger, e := policy.Open(dbpath)
	if e != nil {
		t.Fatal(e)
	}
	defer ledger.Close()
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	hs := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "handshake") }))
	hs.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	hs.StartTLS()
	defer hs.Close()
	hh, hp, _ := net.SplitHostPort(hs.Listener.Addr().String())
	hport, _ := strconv.Atoi(hp)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientTLS := map[string]any{"enabled": true, "server_name": "localhost", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "short_id": "0123456789abcdef"}}
	users := []any{}
	ins := []any{}
	outs := []any{}
	rules := []any{}
	ids := []string{}
	ports := []int{}
	for i := 0; i < 14; i++ {
		id := fmt.Sprintf("%08x-1111-4111-8111-%012x", i+1, i+1)
		ids = append(ids, id)
		port := freePort(t)
		ports = append(ports, port)
		tag := fmt.Sprintf("client-%d", i)
		users = append(users, map[string]any{"name": fmt.Sprintf("u-%d", i), "uuid": id, "flow": "xtls-rprx-vision"})
		if e = ledger.Set("shared", policy.UUIDKey(id), policy.Limit{Quota: 1 << 20}); e != nil {
			t.Fatal(e)
		}
		ins = append(ins, map[string]any{"type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port})
		outs = append(outs, map[string]any{"type": "vless", "tag": tag, "server": "127.0.0.1", "server_port": 443, "uuid": id, "flow": "xtls-rprx-vision", "tls": clientTLS})
		rules = append(rules, map[string]any{"inbound": []string{tag}, "action": "route", "outbound": tag})
	}
	udpEcho, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 65536)
		for {
			n, a, e := udpEcho.ReadFrom(b)
			if e != nil {
				return
			}
			udpEcho.WriteTo(b[:n], a)
		}
	}()
	udpPort := freePort(t)
	_, udpTarget, _ := net.SplitHostPort(udpEcho.LocalAddr().String())
	udpTargetPort, _ := strconv.Atoi(udpTarget)
	ins = append(ins, map[string]any{"type": "direct", "tag": "udp-client", "listen": "127.0.0.1", "listen_port": udpPort, "network": "udp", "override_address": "127.0.0.1", "override_port": udpTargetPort})
	rules = append(rules, map[string]any{"inbound": []string{"udp-client"}, "action": "route", "outbound": "client-6"})
	server := map[string]any{"log": map[string]any{"level": "debug"}, "inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": 443, "users": users, "tls": map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": hh, "server_port": hport}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
	client := map[string]any{"log": map[string]any{"level": "debug"}, "inbounds": ins, "outbounds": outs, "route": map[string]any{"rules": rules}}
	start := func(name string, c map[string]any, meter bool) *exec.Cmd {
		path := filepath.Join(dir, name+".json")
		if e := os.WriteFile(path, canonical(c), 0600); e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(binary, "run", "-c", path)
		cmd.Env = append(os.Environ(), "TZSING_POLICY_DB=")
		if meter {
			cmd.Env = append(cmd.Env, "TZSING_POLICY_DB="+dbpath)
		}
		log, e := os.Create(filepath.Join(dir, name+".log"))
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
		return cmd
	}
	serverProcess := start("server", server, true)
	start("clients", client, false)
	for _, port := range append(ports, 443) {
		until := time.Now().Add(5 * time.Second)
		for {
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
			if e == nil {
				c.Close()
				break
			}
			if time.Now().After(until) {
				t.Fatal("isolated listener unavailable", port)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 14; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			dial, e := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", ports[i]), nil, &net.Dialer{Timeout: 3 * time.Second})
			if e != nil {
				t.Error(e)
				return
			}
			for j := 0; j < 8; j++ {
				c, e := dial.Dial("tcp", echo.Addr().String())
				if e != nil {
					t.Error(e)
					return
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte{byte(i + 1)}, 64+i*3)
				_, e = c.Write(payload)
				if e != nil {
					c.Close()
					t.Error(e)
					return
				}
				got := make([]byte, len(payload))
				_, e = io.ReadFull(c, got)
				c.Close()
				if e != nil || !bytes.Equal(got, payload) {
					t.Errorf("UUID %d payload mismatch: %v", i, e)
					return
				}
			}
		}()
	}
	wg.Wait()
	until := time.Now().Add(3 * time.Second)
	for {
		ok := true
		for i, id := range ids {
			s, e := ledger.State("shared", policy.UUIDKey(id))
			expected := int64(8 * (64 + i*3))
			if e != nil {
				t.Fatal(e)
			}
			if s.Upload != expected || s.Download != expected || s.Used != 2*expected || s.Reserved != 0 {
				ok = false
				if time.Now().After(until) {
					t.Errorf("UUID %d expected up/down=%d: %+v", i, expected, s)
				}
			}
		}
		if ok || time.Now().After(until) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !t.Failed() {
		t.Log("14 UUIDs concurrently shared REALITY 443; 112 short connections; exact authenticated upload/download totals")
	}
	// Exercise Vision's TLS path with a response large enough to enter its
	// optimized copy mode. Compare the gate with ciphertext on the target socket.
	ledger.Set("shared", policy.UUIDKey(ids[5]), policy.Limit{})
	tlsUp, tlsDown := new(atomic.Int64), new(atomic.Int64)
	payload := bytes.Repeat([]byte("large-tls-payload"), 65536)
	tlsTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	tlsTarget.Listener = &payloadListener{Listener: tlsTarget.Listener, up: tlsUp, down: tlsDown}
	tlsTarget.StartTLS()
	defer tlsTarget.Close()
	beforeTLS, _ := ledger.State("shared", policy.UUIDKey(ids[5]))
	d, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", ports[5]), nil, &net.Dialer{Timeout: time.Second})
	tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	res, e := hc.Get(tlsTarget.URL)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(res.Body)
	res.Body.Close()
	tr.CloseIdleConnections()
	if e != nil || !bytes.Equal(payload, got) {
		t.Fatal("large TLS payload mismatch", e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		state, _ := ledger.State("shared", policy.UUIDKey(ids[5]))
		if state.Upload-beforeTLS.Upload == tlsUp.Load() && state.Download-beforeTLS.Download == tlsDown.Load() && state.Reserved == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS ciphertext meter mismatch gate=%d/%d target=%d/%d", state.Upload-beforeTLS.Upload, state.Download-beforeTLS.Download, tlsUp.Load(), tlsDown.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	beforeUDP, _ := ledger.State("shared", policy.UUIDKey(ids[6]))
	uc, e := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if e != nil {
		t.Fatal(e)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(3 * time.Second))
	udpPayload := bytes.Repeat([]byte{63}, 137)
	uc.Write(udpPayload)
	udpGot := make([]byte, 65536)
	n, e := uc.Read(udpGot)
	if e != nil || !bytes.Equal(udpPayload, udpGot[:n]) {
		t.Fatal("UDP payload mismatch", e)
	}
	deadline = time.Now().Add(time.Second)
	for {
		state, _ := ledger.State("shared", policy.UUIDKey(ids[6]))
		if state.Upload-beforeUDP.Upload == 137 && state.Download-beforeUDP.Download == 137 && state.Reserved == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP metering mismatch", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
	ledger.Set("shared", policy.UUIDKey(ids[6]), policy.Limit{ExpiresAt: time.Now().Unix() - 1})
	uc.SetDeadline(time.Now().Add(300 * time.Millisecond))
	uc.Write(udpPayload)
	if _, e = uc.Read(udpGot); e == nil {
		t.Fatal("expired UDP admitted")
	}
	uc.Close()
	t.Log("large Vision TLS ciphertext counters and real UDP datagram counters verified; UDP expiry enforced")
	transfer := func(index, size int) (net.Conn, error) {
		d, e := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", ports[index]), nil, &net.Dialer{Timeout: time.Second})
		if e != nil {
			return nil, e
		}
		c, e := d.Dial("tcp", echo.Addr().String())
		if e != nil {
			return nil, e
		}
		c.SetDeadline(time.Now().Add(time.Second))
		payload := bytes.Repeat([]byte{42}, size)
		if _, e = c.Write(payload); e == nil {
			got := make([]byte, size)
			_, e = io.ReadFull(c, got)
			if e == nil && !bytes.Equal(payload, got) {
				e = fmt.Errorf("payload mismatch")
			}
		}
		if e != nil {
			c.Close()
			return nil, e
		}
		return c, nil
	}
	policyController := &Controller{Config: ServiceConfig{Config: filepath.Join(dir, "server.json"), State: dir, PolicyDB: dbpath, WriteEnabled: true}, Hooks: &ApplyHooks{}}
	set := func(index int, limit policy.Limit) {
		t.Helper()
		id := policy.UUIDKey(ids[index])
		request := func(path string, v any) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			policyController.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(canonical(v))))
			return w
		}
		w := request("/policy-preview", map[string]any{"tag": "shared", "auth_id": id, "policy": limit})
		if w.Code != 200 {
			t.Fatal("policy preview", w.Code, w.Body.String())
		}
		var p map[string]any
		json.Unmarshal(w.Body.Bytes(), &p)
		w = request("/policy-apply", map[string]any{"tag": "shared", "auth_id": id, "plan": p["plan"]})
		if w.Code != 200 {
			t.Fatal("policy apply", w.Code, w.Body.String())
		}
	}

	set(0, policy.Limit{ExpiresAt: time.Now().Unix() - 1})
	if c, e := transfer(0, 1); e == nil {
		c.Close()
		t.Fatal("expired UUID admitted")
	}
	set(0, policy.Limit{})
	if c, e := transfer(0, 16); e != nil {
		t.Fatal("extension did not restore", e)
	} else {
		c.Close()
	}
	state, e := ledger.State("shared", policy.UUIDKey(ids[1]))
	if e != nil {
		t.Fatal(e)
	}
	set(1, policy.Limit{Quota: state.Used})
	if c, e := transfer(1, 1); e == nil {
		c.Close()
		t.Fatal("exhausted UUID admitted")
	}
	set(1, policy.Limit{Quota: state.Used + 1<<20})
	if c, e := transfer(1, 16); e != nil {
		t.Fatal("quota edit did not restore", e)
	} else {
		c.Close()
	}
	if c, e := transfer(2, 16); e != nil {
		t.Fatal("peer UUID affected", e)
	} else {
		c.Close()
	}
	// Create a fifteenth UUID with an already-expired policy through the real
	// controller transaction. Deliberate rejection must not be called bad health.
	fresh := "ffffffff-1111-4111-8111-ffffffffffff"
	freshPort := freePort(t)
	start("fresh-client", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": freshPort}}, "outbounds": []any{map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": 443, "uuid": fresh, "flow": "xtls-rprx-vision", "tls": clientTLS}}}, false)
	ids = append(ids, fresh)
	ports = append(ports, freshPort)
	waitShared := func(map[string]any) error {
		until := time.Now().Add(3 * time.Second)
		for {
			c, e := net.DialTimeout("tcp", "127.0.0.1:443", 50*time.Millisecond)
			if e == nil {
				c.Close()
				return nil
			}
			if time.Now().After(until) {
				return fmt.Errorf("listener not ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	policyController.Hooks = &ApplyHooks{Check: func(raw []byte) error {
		p := filepath.Join(dir, "validation.json")
		os.WriteFile(p, raw, 0600)
		return exec.Command(binary, "check", "-c", p).Run()
	}, Activate: func() error {
		serverProcess.Process.Kill()
		serverProcess.Wait()
		b, e := os.ReadFile(filepath.Join(dir, "server.json"))
		if e != nil {
			return e
		}
		server = candidateMap(b)
		serverProcess = start(fmt.Sprintf("server-applied-%d", time.Now().UnixNano()), server, true)
		return nil
	}, Healthy: waitShared, Probe: func(map[string]any) error { return nil }}
	req := func(path string, v any) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		policyController.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(canonical(v))))
		return w
	}
	w := req("/uuid-preview", map[string]any{"node": UUIDNodeRequest{Inbound: "shared", Name: "新限额节点", UUID: fresh, Enabled: true, Quota: 2, ExpiresAt: time.Now().Unix() - 1}})
	if w.Code != 200 {
		t.Fatal("limited create preview", w.Code, w.Body.String())
	}
	preview := candidateMap(w.Body.Bytes())
	w = req("/uuid-apply", map[string]any{"plan": preview["plan"]})
	if w.Code != 200 {
		t.Fatal("limited UUID create", w.Code, w.Body.String())
	}
	if c, e := transfer(14, 1); e == nil {
		c.Close()
		t.Fatal("new expired UUID admitted")
	}
	set(14, policy.Limit{Quota: 2})
	if c, e := transfer(14, 1); e != nil {
		t.Fatal("new quota not restored", e)
	} else {
		c.Close()
	}
	time.Sleep(30 * time.Millisecond)
	if c, e := transfer(14, 1); e == nil {
		c.Close()
		t.Fatal("new quota not enforced")
	}
	if c, e := transfer(4, 16); e != nil {
		t.Fatal("create affected peer", e)
	} else {
		c.Close()
	}
	t.Log("new UUID created on existing 443 with expired policy; policy edit restored it and 2-byte quota blocked the next connection")
	// Idle reads no longer hold quota reservations. A normal process restart
	// must restore the same UUID policy and totals without blocking idle users.
	held, e := transfer(3, 16)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	time.Sleep(100 * time.Millisecond)
	state, e = ledger.State("shared", policy.UUIDKey(ids[3]))
	if e != nil {
		t.Fatal(e)
	}
	if state.Reserved != 0 {
		t.Fatal("idle read reserved allowance", state)
	}
	beforeUsed := state.Used
	if e = serverProcess.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	serverProcess.Wait()
	serverProcess = start("server-restarted", server, true)
	until = time.Now().Add(3 * time.Second)
	for {
		c, e := net.DialTimeout("tcp", "127.0.0.1:443", 50*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(until) {
			t.Fatal("isolated restart unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	state, e = ledger.State("shared", policy.UUIDKey(ids[3]))
	if e != nil || state.Used != beforeUsed || state.Reserved != 0 {
		t.Fatal("restart lost settled payload", state, e)
	}
	if c, e := transfer(3, 1); e != nil {
		t.Fatal("restarted UUID failed", e)
	} else {
		c.Close()
	}
	if c, e := transfer(4, 16); e != nil {
		t.Fatal("peer UUID blocked after crash", e)
	} else {
		c.Close()
	}
	t.Log("real expiry reject/extension, quota reject/edit, idle-read safety and SIGKILL restart recovery verified")

}

type payloadListener struct {
	net.Listener
	up, down *atomic.Int64
}

func (l *payloadListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &payloadConn{Conn: c, up: l.up, down: l.down}, nil
}

type payloadConn struct {
	net.Conn
	up, down *atomic.Int64
}

func (c *payloadConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.up.Add(int64(n))
	return n, e
}
func (c *payloadConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.down.Add(int64(n))
	return n, e
}
