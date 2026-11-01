package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/model"
)

// Only opt in using the artifact from TestNativeTwelveUUIDRealityRoutingAndClosedTraffic.
// This replays genuine captured payload counters through the authenticated ingestion
// boundary, persistent SQLite, API and WebSocket without inventing traffic.
func TestNativeCapturedTrafficSQLiteAPIAndWebSocket(t *testing.T) {
	path := os.Getenv("TZSING_NATIVE_REPORT_FILE")
	if path == "" {
		t.Skip("real isolated REALITY capture required")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var tags []model.Tag
	if json.Unmarshal(b, &tags) != nil || len(tags) != 12 {
		t.Fatal("invalid capture")
	}
	f := setup(t)
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	h := http.Header{"Cookie": []string{f.admin.String()}, "Origin": []string{f.srv.URL}}
	ws, _, e := d.Dial("wss"+strings.TrimPrefix(f.srv.URL, "https")+"/testprefix/ws", h)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var initial []model.View
	if e = ws.ReadJSON(&initial); e != nil {
		t.Fatal(e)
	}
	report := model.Report{ServerID: "one", Epoch: strings.Repeat("N", 43), Seq: 1, At: time.Now().Unix(), Interval: 2, Tags: tags}
	post := func(want int) {
		t.Helper()
		b, _ := json.Marshal(report)
		r, _ := http.NewRequest("POST", f.srv.URL+"/testprefix/api/agent/report", bytes.NewReader(b))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 43))
		res, e := f.srv.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatal("ingestion", res.StatusCode)
		}
	}
	post(200)
	post(409) // exact report replay must not duplicate usage
	check := func(views []model.View) bool {
		t.Helper()
		for _, v := range views {
			if v.ID == "one" && v.Report != nil && len(v.Report.Tags) == 12 {
				found := map[string]model.Tag{}
				for _, tag := range v.Report.Tags {
					found[tag.ID] = tag
				}
				if len(found) != 12 {
					t.Fatal("merged IDs")
				}
				for _, captured := range tags {
					var up, down int64
					if e := f.db.QueryRow("SELECT totalup,totaldown FROM counters WHERE server='one' AND tag=?", captured.Name).Scan(&up, &down); e != nil {
						t.Fatal(e)
					}
					if captured.Upload == nil || up != *captured.Upload || down != *captured.Download {
						t.Fatal("SQLite traffic mismatch")
					}
					matched := false
					for _, visible := range found {
						if visible.AuthID == captured.AuthID {
							matched = true
							if visible.Accounting != "native_user_observed" || visible.Upload == nil || *visible.Upload != up || *visible.Download != down || visible.MonthUsed == nil || *visible.MonthUsed != up+down || visible.Active != nil || visible.IP != nil {
								t.Fatal("presentation mismatch or fabricated active/exit")
							}
						}
					}
					if !matched {
						t.Fatal("UUID lost at presentation boundary")
					}
				}
				return true
			}
		}
		return false
	}
	var frames []model.View
	for !check(frames) {
		if e = ws.ReadJSON(&frames); e != nil {
			t.Fatal(e)
		}
	}
	res := f.req(t, "GET", "/api/snapshot", nil, f.admin, "")
	defer res.Body.Close()
	var api []model.View
	if json.NewDecoder(res.Body).Decode(&api) != nil || !check(api) {
		t.Fatal("API pipeline")
	}
	t.Log("12 real captured UUID counters survived idempotent ingestion, SQLite, API and WebSocket")
}
