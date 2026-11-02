package control

import (
	"errors"
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
	"testing"
	"time"
	"tzsingbox/internal/model"
)

// Runs only disposable sing-box processes with synthetic credentials and ports.
// Real authentication succeeds before deletion; the target fails afterwards
// while the other identity and a separate listener still pass traffic.
func TestIsolatedDeleteProtocolNodes(t *testing.T) {
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Skip("explicit isolated binary required")
	}
	for _, typ := range []string{"shadowsocks-user", "shadowsocks-listener", "trojan", "socks", "http"} {
		t.Run(typ, func(t *testing.T) {
			dir := t.TempDir()
			port, peer, ca, cb := freePort(t), freePort(t), freePort(t), freePort(t)
			protocol := typ
			if typ == "shadowsocks-user" || typ == "shadowsocks-listener" {
				protocol = "shadowsocks"
			}
			first, second := "synthetic-alice", "synthetic-bob"
			inbound := map[string]any{"type": protocol, "tag": "target", "listen": "127.0.0.1", "listen_port": port}
			outbound := func(password string) map[string]any {
				return map[string]any{"type": protocol, "server": "127.0.0.1", "server_port": port, "password": password}
			}
			users := []any{map[string]any{"name": "alice", "password": first}, map[string]any{"name": "bob", "password": second}}
			if typ == "shadowsocks-user" {
				first = "AQEBAQEBAQEBAQEBAQEBAQ=="
				second = "AgICAgICAgICAgICAgICAg=="
				object(users[0])["password"] = first
				object(users[1])["password"] = second
				inbound["method"] = "2022-blake3-aes-128-gcm"
				inbound["password"] = "AwMDAwMDAwMDAwMDAwMDAw=="
			}
			inbound["users"] = users
			if typ == "shadowsocks-listener" {
				delete(inbound, "users")
				inbound["method"] = "aes-128-gcm"
				inbound["password"] = first
			}
			if protocol == "socks" || protocol == "http" {
				for _, v := range users {
					u := object(v)
					u["username"] = u["name"]
					delete(u, "name")
				}
			}
			client := func(who string) map[string]any {
				password := first
				name := "alice"
				if who == "bob" {
					password = second
					name = "bob"
				}
				out := outbound(password)
				if protocol == "shadowsocks" {
					out["method"] = inbound["method"]
					if typ == "shadowsocks-user" {
						out["password"] = text(inbound["password"]) + ":" + password
					}
				}
				if protocol == "socks" || protocol == "http" {
					out["username"] = name
				}
				return out
			}
			socks := func(tag string, p int) map[string]any {
				return map[string]any{"type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": p}
			}
			main := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{inbound, socks("peer", peer)}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}}
			path := filepath.Join(dir, "main.json")
			raw := canonical(main)
			os.WriteFile(path, raw, 0600)
			check := func(b []byte) error {
				p := filepath.Join(dir, "check.json")
				os.WriteFile(p, b, 0600)
				if output, e := exec.Command(binary, "check", "-c", p).CombinedOutput(); e != nil {
					return fmt.Errorf("sing-box check: %s", output)
				}
				return nil
			}
			if e := check(raw); e != nil {
				t.Fatal(e)
			}
			web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "alive") }))
			defer web.Close()
			request := func(p int) error {
				d, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), nil, &net.Dialer{Timeout: time.Second})
				if e != nil {
					return e
				}
				tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
				defer tr.CloseIdleConnections()
				res, e := (&http.Client{Transport: tr, Timeout: 500 * time.Millisecond}).Get(web.URL)
				if e != nil {
					return e
				}
				defer res.Body.Close()
				b, e := io.ReadAll(res.Body)
				if string(b) != "alive" {
					return errors.New("wrong response")
				}
				return e
			}
			wait := func(p int) error {
				until := time.Now().Add(4 * time.Second)
				for time.Now().Before(until) {
					if e := request(p); e == nil {
						return nil
					}
					time.Sleep(25 * time.Millisecond)
				}
				return errors.New("authenticated path unavailable")
			}
			startClient := func(who string, p int) {
				file := filepath.Join(dir, who+".json")
				os.WriteFile(file, canonical(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(who, p)}, "outbounds": []any{client(who)}}), 0600)
				cmd := exec.Command(binary, "run", "-c", file)
				if e := cmd.Start(); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
			}
			startClient("alice", ca)
			if typ != "shadowsocks-listener" {
				startClient("bob", cb)
			}
			var current *exec.Cmd
			activations := 0
			activate := func() error {
				activations++
				if current != nil {
					current.Process.Kill()
					current.Wait()
				}
				current = exec.Command(binary, "run", "-c", path)
				return current.Start()
			}
			defer func() {
				if current != nil {
					current.Process.Kill()
					current.Wait()
				}
			}()
			if e := activate(); e != nil {
				t.Fatal(e)
			}
			if e := wait(ca); e != nil {
				t.Fatal("target before deletion", e)
			}
			if typ != "shadowsocks-listener" {
				if e := wait(cb); e != nil {
					t.Fatal("peer before deletion", e)
				}
			}
			id := model.AuthID("alice")
			if typ == "shadowsocks-listener" {
				id = ""
			}
			candidate, e := DeleteInbound(raw, "target", id, nil)
			if e != nil {
				t.Fatal(e)
			}
			c := &Controller{Config: ServiceConfig{Config: path, State: dir}, Hooks: &ApplyHooks{Check: check, Activate: activate, Healthy: func(map[string]any) error { return wait(peer) }}}
			if e = c.apply(plan{Hash: digest(raw), Tag: "target", AuthID: id, Action: "delete", Candidate: candidate}); e != nil {
				t.Fatal(e)
			}
			if activations != 2 {
				t.Fatal("expected one deletion activation")
			}
			actual, _ := os.ReadFile(path)
			target := findInbound(candidateMap(actual), "target")
			if id == "" && target != nil {
				t.Fatal("listener survived readback")
			}
			if id != "" {
				if _, e := deletionUser(target, id); e == nil {
					t.Fatal("user survived readback")
				}
			}
			if e = request(ca); e == nil {
				t.Fatal("deleted identity still authenticates")
			}
			if typ != "shadowsocks-listener" {
				if e = wait(cb); e != nil {
					t.Fatal("other identity lost", e)
				}
			}
		})
	}
}
