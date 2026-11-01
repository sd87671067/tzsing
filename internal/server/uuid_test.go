package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"tzsingbox/internal/model"
)

func TestUUIDAdminGatesAndCSRF(t *testing.T) {
	f := setup(t)
	for _, path := range []string{"node-catalog", "node-preview", "node-create", "node-delete", "node-state"} {
		method := "POST"
		if path == "node-catalog" {
			method = "GET"
		}
		r := f.req(t, method, "/api/admin/"+path, map[string]any{}, f.user, f.ucs)
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatal("viewer access", path, r.StatusCode)
		}
		r = f.req(t, method, "/api/admin/"+path, map[string]any{}, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatal("missing independent permission", path, r.StatusCode)
		}
	}
	f.db.Exec("INSERT INTO control_permissions VALUES(1,'change')")
	for _, path := range []string{"node-create", "node-delete", "node-state"} {
		r := f.req(t, "POST", "/api/admin/"+path, map[string]any{}, f.admin, f.acs)
		r.Body.Close()
		if r.StatusCode != 503 {
			t.Fatal("production write accepted", path, r.StatusCode)
		}
	}
	r := f.req(t, "POST", "/api/admin/node-preview", map[string]any{}, f.admin, "")
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatal("CSRF bypass", r.StatusCode)
	}
	r = f.req(t, "GET", "/api/admin/node-catalog", nil, f.admin, "")
	r.Body.Close()
	if r.StatusCode != 503 {
		t.Fatal("missing controller", r.StatusCode)
	}
}
func TestTwelveUUIDCardsNoIdleLossOrPortMerge(t *testing.T) {
	f := setup(t)
	tags := []map[string]any{{"name": "inbound:shared", "inbound_tag": "shared", "identity": "inbound", "type": "vless", "accounting": "unattributed"}}
	for i := 0; i < 12; i++ {
		id := strings.Repeat(string(rune('a'+i%6)), 64) // distinct synthetic identity digests
		id = id[:62] + []string{"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b"}[i]
		// Use model-derived scoped keys; no UUID is exposed to the browser.
		key := model.IdentityName("shared", id)
		tags = append(tags, map[string]any{"name": key, "inbound_tag": "shared", "auth_id": id, "identity": "inbound", "type": "vless", "accounting": "unavailable", "state": "online"})
	}
	b, _ := json.Marshal(map[string]any{"tags": tags, "interval": 2})
	f.db.Exec("UPDATE servers SET report=? WHERE id='one'", b)
	r := f.req(t, "GET", "/api/snapshot", nil, f.admin, "")
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatal(r.StatusCode)
	}
	var views []struct {
		Report struct {
			Tags []struct {
				ID        string
				MonthUsed *int64 `json:"month_used"`
			}
		}
	}
	json.NewDecoder(r.Body).Decode(&views)
	if len(views) == 0 || len(views[0].Report.Tags) != 12 {
		t.Fatalf("expected twelve cards: %+v", views)
	}
	seen := map[string]bool{}
	for _, tag := range views[0].Report.Tags {
		if tag.ID == "" || seen[tag.ID] || tag.MonthUsed != nil {
			t.Fatal("identity merge or fabricated accounting")
		}
		seen[tag.ID] = true
	}
}
