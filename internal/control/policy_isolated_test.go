package control

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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
	server := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": 443, "users": users, "tls": map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": hh, "server_port": hport}}}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "experimental": map[string]any{"clash_api": map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", freePort(t))}}}
	client := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": ins, "outbounds": outs, "route": map[string]any{"rules": rules}}
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
	set := func(index int, limit policy.Limit) {
		t.Helper()
		if e := ledger.Set("shared", policy.UUIDKey(ids[index]), limit); e != nil {
			t.Fatal(e)
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
	// Leave a real authenticated connection waiting for more payload, then SIGKILL.
	// The durable reservation survives separately; restart refuses to guess usage.
	held, e := transfer(3, 16)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	until = time.Now().Add(time.Second)
	for {
		state, e = ledger.State("shared", policy.UUIDKey(ids[3]))
		if e != nil {
			t.Fatal(e)
		}
		if state.Reserved > 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("pending authenticated read missing")
		}
		time.Sleep(10 * time.Millisecond)
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
	if e != nil || state.Used != beforeUsed || state.Reserved == 0 || !state.Uncertain {
		t.Fatal("crash reservation misrepresented", state, e)
	}
	if c, e := transfer(3, 1); e == nil {
		c.Close()
		t.Fatal("unreconciled crash allowed payload")
	}
	if c, e := transfer(4, 16); e != nil {
		t.Fatal("peer UUID blocked after crash", e)
	} else {
		c.Close()
	}
	t.Log("real expiry reject/extension, quota reject/edit, SIGKILL unresolved reservation isolation verified; automatic exact crash reconciliation remains unqualified")

}
