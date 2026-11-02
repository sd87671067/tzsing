package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestConfigFormattingLosslessAndIdempotent(t *testing.T) {
	// Includes ordered routing/DNS/selector/urltest arrays, opaque credentials,
	// extension fields and integers beyond float64's exact range.
	raw := []byte(`{"z-extension":{"integer":9007199254740993,"decimal":1.2300e+40,"escaped":"\u4e2d","url":"https://example.invalid/a//b"},"inbounds":[{"type":"vless","users":[{"uuid":"opaque-uuid"}],"tls":{"reality":{"private_key":"opaque-key"},"certificate_path":"/keep/cert"}},{"type":"socks"}],"outbounds":[{"type":"selector","outbounds":["b","a"]},{"type":"urltest","outbounds":["a","b"]}],"route":{"rules":[{"action":"reject"},{"outbound":"a"}]},"dns":{"rules":[{"server":"b"},{"server":"a"}]}}`)
	pretty, err := formatConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err = json.Compact(&compact, pretty); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compact.Bytes(), raw) {
		t.Fatal("formatting changed JSON tokens or their order")
	}
	again, err := formatConfig(pretty)
	if err != nil || !bytes.Equal(pretty, again) {
		t.Fatal("formatting is not idempotent", err)
	}
	if !bytes.Contains(pretty, []byte("\n  \"inbounds\": [\n    {\n")) || !bytes.HasSuffix(pretty, []byte("\n")) {
		t.Fatal("missing two-space object layout or final newline")
	}
	// Formatting must never change the historic compact hash used by snapshots.
	before := candidateMap(raw)
	after := candidateMap(pretty)
	if !reflect.DeepEqual(before, after) || digest(canonical(before)) != digest(canonical(after)) {
		t.Fatal("snapshot hash changed")
	}
	if digest(raw) == digest(pretty) {
		t.Fatal("CAS should still distinguish actual file bytes")
	}
	if !bytes.Equal(canonical(map[string]any{"z": 1, "a": 2}), []byte(`{"a":2,"z":1}`)) {
		t.Fatal("historic canonical encoding changed")
	}
	if !bytes.Equal(configBytes(before), configBytes(after)) {
		t.Fatal("generated field order is unstable")
	}
}

func TestConfigFormattingRejectsJSONC(t *testing.T) {
	for _, raw := range []string{`{/* retain me */ "inbounds":[]}`, "{\n// retain me\n\"inbounds\":[]}", `{"inbounds":[],}`} {
		original := []byte(raw)
		if out, err := formatConfig(original); err == nil || out != nil {
			t.Fatal("unsupported comment or trailing comma silently discarded")
		}
		if string(original) != raw {
			t.Fatal("input was modified")
		}
	}
}

// Run only with an explicit binary. All listeners, configs and processes are
// synthetic and local; no production service or config is touched.
func TestFormattedSingBoxBehavior(t *testing.T) {
	binary := os.Getenv("TZSING_TEST_SINGBOX")
	if binary == "" {
		t.Skip("requires explicit isolated sing-box binary")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "format-equivalent") }))
	defer target.Close()
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("reject rule was bypassed") }))
	defer blocked.Close()
	targetURL, _ := url.Parse(target.URL)
	_, port, _ := net.SplitHostPort(targetURL.Host)
	allowedPort, _ := strconv.Atoi(port)
	for _, pretty := range []bool{false, true} {
		t.Run(strconv.FormatBool(pretty), func(t *testing.T) {
			listener := freePort(t)
			config := map[string]any{
				"log":       map[string]any{"disabled": true},
				"inbounds":  []any{map[string]any{"type": "http", "tag": "test", "listen": "127.0.0.1", "listen_port": listener}},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
				"route":     map[string]any{"rules": []any{map[string]any{"port": allowedPort, "action": "route", "outbound": "direct"}, map[string]any{"action": "reject"}}},
			}
			raw := canonical(config)
			if pretty {
				var err error
				raw, err = formatConfig(raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
				t.Fatalf("sing-box check: %v %s", err, out)
			}
			cmd := exec.Command(binary, "run", "-c", path)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listener))
			ready := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
				if err == nil {
					c.Close()
					ready = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("isolated listener did not start")
			}
			proxyURL, _ := url.Parse("http://" + addr)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			resp, err := client.Get(target.URL)
			if err != nil {
				t.Fatal("allowed route failed", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "format-equivalent" {
				t.Fatal("allowed route changed", err)
			}
			resp, err = client.Get(blocked.URL)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 400 {
					t.Fatal("reject rule did not reject")
				}
			}
		})
	}
}

func TestFormattedTransactionHashesAndExactRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			raw := []byte("{\n\t\"inbounds\": [{\"type\":\"vless\",\"tag\":\"a\"}],\n\t\"outbounds\": [{\"tag\":\"direct\",\"type\":\"direct\"}]\n}\n")
			candidate, snapshot, err := Change(raw, "a", map[string]any{"tag": managedTag("a"), "type": "direct"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate a compact candidate preview from an older controller.
			var compact bytes.Buffer
			if err = json.Compact(&compact, candidate); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			activations := 0
			c := Controller{Config: ServiceConfig{Config: path, State: dir}, Hooks: &ApplyHooks{
				Check: func(b []byte) error {
					if !json.Valid(b) {
						return io.ErrUnexpectedEOF
					}
					return nil
				},
				Healthy: func(map[string]any) error { return nil },
				Probe:   func(map[string]any) error { return nil },
				Activate: func() error {
					activations++
					if activations == 1 {
						current, e := os.ReadFile(path)
						if e != nil {
							t.Fatal(e)
						}
						if !bytes.Equal(current, candidate) {
							t.Fatal("final candidate is not formatted")
						}
						txRaw, e := os.ReadFile(filepath.Join(dir, "transaction.json"))
						if e != nil {
							t.Fatal(e)
						}
						var tx transaction
						if e = json.Unmarshal(txRaw, &tx); e != nil {
							t.Fatal(e)
						}
						if tx.Hash != digest(raw) || tx.After != digest(current) || !bytes.Equal(tx.Before, raw) {
							t.Fatal("transaction hashes or original bytes changed")
						}
						if fail {
							return io.ErrUnexpectedEOF
						}
					}
					return nil
				},
			}}
			err = c.apply(plan{Hash: digest(raw), Tag: "a", Candidate: compact.Bytes(), Snapshot: snapshot})
			after, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if fail {
				if err == nil || activations != 2 || !bytes.Equal(after, raw) {
					t.Fatal("rollback did not restore exact original bytes", err)
				}
			} else {
				if err != nil || !bytes.Equal(after, candidate) {
					t.Fatal("apply failed", err)
				}
				journals, e := c.journals()
				if e != nil {
					t.Fatal(e)
				}
				restored, e := Restore(after, "a", journals["a"])
				if e != nil || !reflect.DeepEqual(canonicalJSON(restored), canonicalJSON(raw)) {
					t.Fatal("historic compact snapshot hashes incompatible", e)
				}
			}
		})
	}
}

func TestConfigGenerationPreservesNumericExtensionsAndHistoricHash(t *testing.T) {
	raw := []byte(`{"inbounds":[{"tag":"a","type":"vless"}],"outbounds":[{"tag":"direct","type":"direct"}],"extension":{"integer":9007199254740993,"exponent":1.2300e+40}}`)
	precise := candidateMap(raw)
	var historic map[string]any
	json.Unmarshal(raw, &historic)
	oldHash := digest(documentBytes(historic))
	if digest(canonical(precise)) != oldHash {
		t.Fatal("historic hash contract changed")
	}
	candidate, s, e := Change(raw, "a", map[string]any{"type": "direct", "tag": managedTag("a")}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(candidate, []byte("9007199254740993")) || !bytes.Contains(candidate, []byte("1.2300e+40")) {
		t.Fatal("generation rounded unknown extensions")
	}
	restored, e := Restore(candidate, "a", s)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(preciseJSON(restored), preciseJSON(raw)) {
		t.Fatal("restoration changed extension tokens")
	}
}
