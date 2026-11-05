package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/control"
	"tzsingbox/internal/store"
)

func TestConfigTransactionsLostControllerResponseNamesAndReplay(t *testing.T) {
	f, _ := uuidTransactionFixture(t, true)
	var out map[string]any
	call := func(method, path string, v any, cookie *http.Cookie, csrf string) int {
		r := f.req(t, method, path, v, cookie, csrf)
		defer r.Body.Close()
		out = nil
		json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode
	}
	if code := call("POST", "/api/admin/outbounds", map[string]any{"action": "save", "name": "display alias", "node": control.OutboundNodeRequest{CreateTag: "actual-tag", Config: map[string]any{"type": "direct"}}}, f.admin, f.acs); code != 200 {
		t.Fatal(code, out)
	}
	token := out["nonce"].(string)
	for i := 0; i < 3; i++ {
		if code := call("POST", "/api/admin/outbounds", map[string]any{"action": "apply", "nonce": token}, f.admin, f.acs); code != 200 || out["state"] != "succeeded" {
			t.Fatal(code, out)
		}
	}
	if code := call("GET", "/api/control/transaction?id="+token, nil, f.user, ""); code != 403 {
		t.Fatal("owner boundary", code)
	}
	if code := call("GET", "/api/control/transaction?id="+token, nil, f.admin, ""); code != 200 || out["state"] != "succeeded" {
		t.Fatal(code, out)
	}
	if name := f.db.OutboundDisplayName("one", "actual-tag"); name != "display alias" {
		t.Fatal(name)
	}
	if code := call("POST", "/api/admin/outbounds", map[string]any{"action": "save", "name": "other", "node": control.OutboundNodeRequest{CreateTag: "actual-tag", Config: map[string]any{"type": "direct"}}}, f.admin, f.acs); code != 422 {
		t.Fatal("duplicate TAG", code, out)
	}
	// Restart the Web object: durable result and aliases remain authoritative.
	replacement := New(f.db, f.app.Prefix, f.app.Origin, http.NotFoundHandler())
	replacement.ControlServer = f.app.ControlServer
	replacement.ControlSocket = f.app.ControlSocket
	w := httptest.NewRecorder()
	replacement.configOperationStatus(w, httptest.NewRequest("GET", "/", nil), store.User{ID: 1}, token)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	// Status cannot wait behind the Web mutation/permission lock.
	f.app.routeMu.Lock()
	done := make(chan int, 1)
	go func() {
		r := f.req(t, "GET", "/api/control/transaction?id="+token, nil, f.admin, "")
		r.Body.Close()
		done <- r.StatusCode
	}()
	select {
	case code := <-done:
		if code != 200 {
			t.Error(code)
		}
	case <-time.After(time.Second):
		t.Error("status blocked by routeMu")
	}
	f.app.routeMu.Unlock()
	// A crash between persisted intent and dispatch resumes the exact plan only.
	if code := call("POST", "/api/admin/outbounds", map[string]any{"action": "save", "name": "resumed alias", "node": control.OutboundNodeRequest{CreateTag: "resume-tag", Config: map[string]any{"type": "direct"}}}, f.admin, f.acs); code != 200 {
		t.Fatal(code, out)
	}
	token = out["nonce"].(string)
	n := f.app.controlNonces[auth.Digest(token)]
	if e := f.app.saveConfigOperation(token, store.User{ID: 1}, "outbound-apply", "", n.Node, map[string]string{"plan": n.Plan}, false); e != nil {
		t.Fatal(e)
	}
	replacement.controlNonces = nil
	deadline := time.Now().Add(3 * time.Second)
	for {
		w = httptest.NewRecorder()
		replacement.configOperationStatus(w, httptest.NewRequest("GET", "/", nil), store.User{ID: 1}, token)
		json.Unmarshal(w.Body.Bytes(), &out)
		if out["state"] == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if f.db.OutboundDisplayName("one", "resume-tag") != "resumed alias" {
		t.Fatal("alias lost after resume")
	}
}
