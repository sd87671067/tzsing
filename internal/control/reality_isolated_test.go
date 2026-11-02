package control

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

// No host service commands: the only activations are disposable subprocesses.
func TestIsolatedRealityCreateShared443AndRollback(t *testing.T) {
	if os.Getenv("TZSING_ISOLATED_NETNS") != "1" {
		t.Skip("isolated netns required")
	}
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Skip("explicit isolated binary required")
	}
	dir := t.TempDir()
	shared, upstream, ca, cb := 443, freePort(t), freePort(t), freePort(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		io.WriteString(w, host)
	}))
	defer web.Close()
	socks := func(port int) map[string]any {
		return map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port}
	}
	direct := func(bind string) map[string]any {
		return map[string]any{"type": "direct", "tag": "direct", "inet4_bind_address": bind}
	}
	// Check installed sing-box option spelling before any subprocess is started.
	alice := "11111111-1111-4111-8111-111111111111"
	bob := "22222222-2222-4222-8222-222222222222"
	id := model.UUIDAuthID(alice)
	main := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "tag": "shared", "listen": "127.0.0.1", "listen_port": shared, "users": []any{map[string]any{"name": "alice", "uuid": alice}, map[string]any{"name": "bob", "uuid": bob}}}}, "outbounds": []any{direct("127.0.0.2")}, "route": map[string]any{"final": "direct", "rules": []any{}}}
	handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "handshake") }))
	handshake.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	handshake.StartTLS()
	defer handshake.Close()
	hh, hp, _ := net.SplitHostPort(handshake.Listener.Addr().String())
	hport, _ := strconv.Atoi(hp)
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	in := findInbound(main, "shared")
	in["tls"] = map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": hh, "server_port": hport}}}
	for _, v := range array(in["users"]) {
		object(v)["flow"] = "xtls-rprx-vision"
	}
	clientTLS := map[string]any{"enabled": true, "server_name": "localhost", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "short_id": "0123456789abcdef"}}
	path := filepath.Join(dir, "main.json")
	raw := canonical(main)
	os.WriteFile(path, raw, 0600)
	check := func(b []byte) error {
		p := filepath.Join(dir, "check.json")
		if e := os.WriteFile(p, b, 0600); e != nil {
			return e
		}
		cmd := exec.Command(binary, "check", "-c", p)
		if out, e := cmd.CombinedOutput(); e != nil {
			return errors.New(string(out))
		}
		return nil
	}
	if e := check(raw); e != nil {
		t.Fatal(e)
	}
	start := func(name string, c map[string]any) {
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, canonical(c), 0600)
		cmd := exec.Command(binary, "run", "-c", p)
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	start("upstream", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(upstream)}, "outbounds": []any{direct("127.0.0.3")}})
	for _, c := range []struct {
		uuid string
		port int
	}{{alice, ca}, {bob, cb}} {
		start(strconv.Itoa(c.port), map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(c.port)}, "outbounds": []any{map[string]any{"type": "vless", "tag": "remote", "server": "127.0.0.1", "server_port": shared, "uuid": c.uuid, "flow": "xtls-rprx-vision", "tls": clientTLS}}})
	}
	var current *exec.Cmd
	activations := 0
	failRestart, failHealth := false, false
	healthActivation := 0
	activate := func() error {
		activations++
		if current != nil {
			current.Process.Kill()
			current.Wait()
			current = nil
		}
		if failRestart {
			failRestart = false
			return errors.New("injected restart failure")
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
	request := func(port int) (string, error) {
		d, e := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, &net.Dialer{Timeout: time.Second})
		if e != nil {
			return "", e
		}
		tr := &http.Transport{DialContext: d.(proxy.ContextDialer).DialContext}
		defer tr.CloseIdleConnections()
		res, e := (&http.Client{Transport: tr, Timeout: 500 * time.Millisecond}).Get(web.URL)
		if e != nil {
			return "", e
		}
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		return string(b), e
	}
	wait := func(port int, want string) error {
		until := time.Now().Add(4 * time.Second)
		for time.Now().Before(until) {
			s, e := request(port)
			if e == nil && s == want {
				return nil
			}
			time.Sleep(30 * time.Millisecond)
		}
		return errors.New("isolated path did not match " + want)
	}
	healthy := func(config map[string]any) error {
		if failHealth && activations == healthActivation {
			failHealth = false
			return errors.New("injected health failure")
		}
		want := "127.0.0.2"
		for _, v := range array(object(config["route"])["rules"]) {
			rule := object(v)
			if string(canonical(rule["auth_user"])) == `["bob"]` {
				switch text(findOutbound(config, text(rule["outbound"]))["type"]) {
				case "shadowsocks":
					want = "127.0.0.4"
				case "socks":
					want = "127.0.0.3"
				case "http":
					want = "127.0.0.5"
				}
				break
			}
		}
		return wait(cb, want)
	}
	if e := activate(); e != nil {
		t.Fatal(e)
	}
	if e := wait(ca, "127.0.0.2"); e != nil {
		t.Fatal(e)
	}
	if e := wait(cb, "127.0.0.2"); e != nil {
		t.Fatal(e)
	}
	c := &Controller{Config: ServiceConfig{Config: path, State: dir}, Hooks: &ApplyHooks{Check: check, Activate: activate, Healthy: healthy, Probe: func(map[string]any) error { return nil }}}

	c.Config.WriteEnabled = true
	applyIdentity := id
	callNode := func(endpoint string, body any, status int) map[string]any {
		if endpoint == "/preview" || endpoint == "/restore-preview" {
			applyIdentity = text(body.(map[string]any)["auth_id"])
		}
		if endpoint == "/apply" {
			body.(map[string]any)["tag"] = "shared"
			body.(map[string]any)["auth_id"] = applyIdentity
		}
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", endpoint, strings.NewReader(string(canonical(body)))))
		if w.Code != status {
			t.Fatalf("%s: %d %s", endpoint, w.Code, w.Body.String())
		}
		return candidateMap(w.Body.Bytes())
	}
	ssPort, httpPort := freePort(t), freePort(t)
	secret := "synthetic @:#% password"
	start("ss-remote", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ssPort, "method": "aes-128-gcm", "password": secret}}, "outbounds": []any{direct("127.0.0.4")}})
	start("http-remote", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "http", "listen": "127.0.0.1", "listen_port": httpPort, "users": []any{map[string]any{"username": "test @#%", "password": secret}}}}, "outbounds": []any{direct("127.0.0.5")}})
	configs := []map[string]any{
		{"type": "shadowsocks", "server": "127.0.0.1", "server_port": ssPort, "method": "aes-128-gcm", "password": secret},
		{"type": "socks", "server": "127.0.0.1", "server_port": upstream},
		{"type": "http", "server": "127.0.0.1", "server_port": httpPort, "username": "test @#%", "password": secret},
		{"type": "direct"},
	}
	tags := []string{}
	for _, conf := range configs {
		preview := callNode("/outbound-preview", map[string]any{"action": "save", "outbound_node": map[string]any{"config": conf}}, 200)
		saved := callNode("/outbound-apply", map[string]any{"plan": preview["plan"]}, 200)
		tag := text(saved["tag"])
		tags = append(tags, tag)
		loaded, _ := os.ReadFile(path)
		if findOutbound(candidateMap(loaded), tag) == nil {
			t.Fatal("outbound not committed")
		}
	}
	// The same authenticated SS endpoint also round-trips through a node link.
	ssLink := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+secret)) + "@127.0.0.1:" + strconv.Itoa(ssPort)
	linked := callNode("/outbound-preview", map[string]any{"action": "save", "outbound_node": map[string]any{"link": ssLink}}, 200)
	linkedSaved := callNode("/outbound-apply", map[string]any{"plan": linked["plan"]}, 200)
	tags = append(tags, text(linkedSaved["tag"]))
	for i, want := range []string{"127.0.0.4", "127.0.0.3", "127.0.0.5"} {
		preview := callNode("/preview", map[string]any{"tag": "shared", "auth_id": id, "outbound": tags[i]}, 200)
		callNode("/apply", map[string]any{"plan": preview["plan"]}, 200)
		if e := wait(ca, want); e != nil {
			t.Fatal("UUID A", e)
		}
		if e := wait(cb, "127.0.0.2"); e != nil {
			t.Fatal("UUID B affected", e)
		}
		if i == 0 {
			denied := callNode("/outbound-preview", map[string]any{"action": "delete", "outbound_node": map[string]any{"tag": tags[i]}}, 422)
			if !strings.Contains(text(denied["error"]), "route/rules/") {
				t.Fatal("reference location missing")
			}
		}
		t.Logf("UUID A %s actual exit %s; UUID B 127.0.0.2", text(configs[i]["type"]), want)
	}
	previewRestore := callNode("/restore-preview", map[string]any{"tag": "shared", "auth_id": id}, 200)
	callNode("/apply", map[string]any{"plan": previewRestore["plan"]}, 200)
	if e := wait(ca, "127.0.0.2"); e != nil {
		t.Fatal("restore", e)
	}
	for _, uid := range []string{id, model.UUIDAuthID(bob)} {
		p := callNode("/preview", map[string]any{"tag": "shared", "auth_id": uid, "outbound": tags[0]}, 200)
		callNode("/apply", map[string]any{"plan": p["plan"]}, 200)
	}
	for _, port := range []int{ca, cb} {
		if e := wait(port, "127.0.0.4"); e != nil {
			t.Fatal(e)
		}
	}
	for _, uid := range []string{model.UUIDAuthID(bob), id} {
		p := callNode("/restore-preview", map[string]any{"tag": "shared", "auth_id": uid}, 200)
		callNode("/apply", map[string]any{"plan": p["plan"]}, 200)
	}
	for _, tag := range tags {
		p := callNode("/outbound-preview", map[string]any{"action": "delete", "outbound_node": map[string]any{"tag": tag}}, 200)
		callNode("/outbound-apply", map[string]any{"plan": p["plan"]}, 200)
		loaded, _ := os.ReadFile(path)
		if findOutbound(candidateMap(loaded), tag) != nil {
			t.Fatal("deleted tag still loaded")
		}
		for _, port := range []int{ca, cb} {
			if e := wait(port, "127.0.0.2"); e != nil {
				t.Fatal(e)
			}
		}
	}
	raw, _ = os.ReadFile(path)
	t.Log("outbound creation/deletion, SS/SOCKS/HTTP switches, shared binding and restoration verified by real UUID connections")
	out := map[string]any{"type": "socks", "tag": managedTag(identityKey("shared", id)), "server": "127.0.0.1", "server_port": upstream}
	changed, s, e := ChangeIdentity(raw, "shared", id, out, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(raw), Tag: "shared", AuthID: id, Candidate: changed, Snapshot: s}); e != nil {
		t.Fatal(e)
	}
	if e = wait(ca, "127.0.0.3"); e != nil {
		t.Fatal("target actual exit did not change", e)
	}
	if e = wait(cb, "127.0.0.2"); e != nil {
		t.Fatal("peer changed", e)
	}
	restored, e := RestoreIdentity(changed, "shared", id, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.apply(plan{Hash: digest(changed), Tag: "shared", AuthID: id, Candidate: restored, Restore: true}); e != nil {
		t.Fatal(e)
	}
	if e = wait(ca, "127.0.0.2"); e != nil {
		t.Fatal("original path did not return", e)
	}
	base, _ := os.ReadFile(path)
	for _, mode := range []string{"restart", "health"} {
		changed, s, e = ChangeIdentity(base, "shared", id, out, nil)
		if e != nil {
			t.Fatal(e)
		}
		if mode == "restart" {
			failRestart = true
		} else {
			failHealth = true
			healthActivation = activations + 1
		}
		e = c.apply(plan{Hash: digest(base), Tag: "shared", AuthID: id, Candidate: changed, Snapshot: s})
		if e == nil || !strings.Contains(e.Error(), "已恢复") {
			t.Fatal(mode, e)
		}
		after, _ := os.ReadFile(path)
		if digest(after) != digest(base) {
			t.Fatal("rollback bytes differ")
		}
		if e = wait(ca, "127.0.0.2"); e != nil {
			t.Fatal(e)
		}
		if e = wait(cb, "127.0.0.2"); e != nil {
			t.Fatal(e)
		}
	}
	// Use the actual UUID preview/apply APIs, not just candidate helpers.
	c.Config.WriteEnabled = true
	call := func(path string, body any) map[string]any {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(string(canonical(body)))))
		if w.Code != 200 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body.String())
		}
		return candidateMap(w.Body.Bytes())
	}
	beforeCreate, _ := os.ReadFile(path)
	fresh := "33333333-3333-4333-8333-333333333333"
	preview := call("/uuid-preview", map[string]any{"node": UUIDNodeRequest{Inbound: "shared", Name: "new", UUID: fresh, Outbound: "direct", Enabled: true}})
	call("/uuid-apply", map[string]any{"plan": preview["plan"]})
	replay := httptest.NewRecorder()
	c.ServeHTTP(replay, httptest.NewRequest("POST", "/uuid-apply", strings.NewReader(string(canonical(map[string]any{"plan": preview["plan"]})))))
	if replay.Code != 409 {
		t.Fatal("create token replay")
	}
	afterCreate, _ := os.ReadFile(path)
	if !reflect.DeepEqual(findInbound(candidateMap(beforeCreate), "shared")["tls"], findInbound(candidateMap(afterCreate), "shared")["tls"]) {
		t.Fatal("shared REALITY changed")
	}
	cc := freePort(t)
	start("new-client", map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{socks(cc)}, "outbounds": []any{map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": 443, "uuid": fresh, "flow": "xtls-rprx-vision", "tls": clientTLS}}})
	if e = wait(cc, "127.0.0.2"); e != nil {
		t.Fatal("new real REALITY UUID cannot connect", e)
	}
	if e = wait(cb, "127.0.0.2"); e != nil {
		t.Fatal("peer after creation", e)
	}

	// Bind the newly created UUID, then delete it without a restore activation.
	freshID := model.UUIDAuthID(fresh)
	freshOut := candidateMap(canonical(out))
	freshOut["tag"] = managedTag(identityKey("shared", freshID))
	switched, snapshot, err := ChangeIdentity(afterCreate, "shared", freshID, freshOut, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.apply(plan{Hash: digest(afterCreate), Tag: "shared", AuthID: freshID, Candidate: switched, Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	if err = wait(cc, "127.0.0.3"); err != nil {
		t.Fatal(err)
	}
	beforeDeleteActivations := activations
	deletionPreview := call("/preview", map[string]any{"tag": "shared", "auth_id": freshID, "action": "delete"})
	call("/apply", map[string]any{"tag": "shared", "auth_id": freshID, "plan": deletionPreview["plan"]})
	if activations != beforeDeleteActivations+1 {
		t.Fatal("deletion must activate once")
	}
	afterDelete, _ := os.ReadFile(path)
	actual := findInbound(candidateMap(afterDelete), "shared")
	if _, err = deletionUser(actual, freshID); err == nil {
		t.Fatal("deleted identity still in running config")
	}
	if actual["listen_port"] != float64(443) || !reflect.DeepEqual(actual["tls"], findInbound(candidateMap(afterCreate), "shared")["tls"]) {
		t.Fatal("443 or REALITY changed")
	}
	journals, _ := c.journals()
	if _, ok := journals[identityKey("shared", freshID)]; ok {
		t.Fatal("stale management snapshot")
	}

	if _, e = request(cc); e == nil {
		t.Fatal("deleted UUID still connects")
	}
	if e = wait(cb, "127.0.0.2"); e != nil {
		t.Fatal("peer after deletion", e)
	}
	for _, action := range []string{"disable", "enable", "delete"} {
		before, _ := os.ReadFile(path)
		candidate, e := IdentityMutation(before, "shared", id, action)
		if e != nil {
			t.Fatal(action, e)
		}
		if e = c.apply(plan{Hash: digest(before), Tag: "shared", AuthID: id, Action: action, Candidate: candidate}); e != nil {
			t.Fatal(action, e)
		}
		if e = wait(cb, "127.0.0.2"); e != nil {
			t.Fatal("peer lost", e)
		}
		if action == "enable" {
			if e = wait(ca, "127.0.0.2"); e != nil {
				t.Fatal(e)
			}
		} else {
			if _, e = request(ca); e == nil {
				t.Fatal("disabled/deleted identity still works")
			}
		}
	}
}
