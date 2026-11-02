package control

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSharedActualBotAndWebUnixSocket(t *testing.T) {
	binary := os.Getenv("SBBOT_TEST_BINARY")
	if binary == "" {
		t.Skip("requires explicit isolated Bot test binary")
	}
	c, path, _ := newSyncController(t)
	raw := []byte(`{"inbounds":[{"tag":"a","type":"vless"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"relay","server":"1.1.1.1","server_port":1080}],"extension":{"precise":9007199254740993},"route":{"rules":[]}}`)
	os.WriteFile(path, raw, 0600)
	socket := filepath.Join(c.Config.State, "control.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	call := func(route string, body any) (map[string]any, int) {
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("POST", route, bytes.NewReader(documentBytes(body))))
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out, w.Code
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integration-web-save" && r.URL.Path != "/integration-web-edit" {
			c.ServeHTTP(w, r)
			return
		}
		req := map[string]any{"action": "save", "outbound_node": OutboundNodeRequest{Config: map[string]any{"type": "direct"}}}
		if r.URL.Path == "/integration-web-edit" {
			req["outbound_node"] = OutboundNodeRequest{Tag: "relay", Config: map[string]any{"type": "socks", "server": "1.1.1.1", "server_port": 1080, "username": "web"}}
		}
		preview, code := call("/outbound-preview", req)
		if code != 200 {
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(preview)
			return
		}
		out, code := call("/outbound-apply", map[string]string{"plan": text(preview["plan"])})
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(out)
	})}
	defer server.Close()
	go server.Serve(ln)
	cmd := exec.Command(binary, "-test.run", "^TestBotSharedControllerIntegration$", "-test.v", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), "SBBOT_TEST_CONTROLLER_SOCKET="+socket, "SBBOT_TEST_CONFIG="+path)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("Bot/controller integration: %v %s", e, out)
	}
	t.Log(string(out))
}
