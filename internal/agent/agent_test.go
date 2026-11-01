package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"tzsingbox/internal/adapter"
	"tzsingbox/internal/model"
)

func TestNativeReportsWhenClashUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reports := make(chan model.Report, 1)
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report model.Report
		if e := json.NewDecoder(r.Body).Decode(&report); e != nil {
			t.Error(e)
			return
		}
		reports <- report
		w.Write([]byte(`{"sample_seconds":2}`))
		cancel()
	}))
	defer sink.Close()
	stats := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload []byte
		for _, direction := range []string{"uplink", "downlink"} {
			name := "user>>>fixture>>>traffic>>>" + direction
			stat := []byte{0x0a, byte(len(name))}
			stat = append(stat, []byte(name)...)
			stat = append(stat, 0x10, 0x01)
			payload = append(payload, 0x0a, byte(len(stat)))
			payload = append(payload, stat...)
		}
		frame := make([]byte, 5)
		binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(append(frame, payload...))
		w.Header().Set("Grpc-Status", "0")
	}), &http2.Server{}))
	defer stats.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sink.Certificate().Raw}), 0600)
	id := model.UUIDAuthID("00000000-0000-4000-8000-000000000001")
	inv := adapter.Inventory{ConfigHash: "fixture", Inbounds: []adapter.Inbound{{Tag: "shared", Type: "vless", AuthScheme: "uuid-v1", AuthIDs: []string{id}, AuthCount: 1, NativeUsers: map[string]string{id: model.AuthID("fixture")}, Unknown: true}}}
	inventory := filepath.Join(dir, "inventory.json")
	b, _ := json.Marshal(inv)
	os.WriteFile(inventory, b, 0600)
	config := Config{NativeStatsURL: stats.URL, ServerID: "fixture", Token: strings.Repeat("x", 43), URL: sink.URL, CA: ca, ClashURL: "http://127.0.0.1:0", InventoryFile: inventory, Sample: 2}
	b, _ = json.Marshal(config)
	path := filepath.Join(dir, "agent.json")
	os.WriteFile(path, b, 0600)
	if e := Run(ctx, path); e != nil {
		t.Fatal(e)
	}
	select {
	case report := <-reports:
		if report.Error != "Clash API unavailable" {
			t.Fatal("missing Clash diagnostic", report.Error)
		}
		found := false
		for _, tag := range report.Tags {
			if tag.AuthID == id {
				found = true
				if tag.Accounting != "native_user_observed" || tag.Up == nil || tag.Upload == nil || *tag.Upload != 0 || tag.Active != nil || tag.Egress != "" {
					t.Fatal("native recovery invented active/routes or failed to report")
				}
			}
		}
		if !found {
			t.Fatal("identity lost")
		}
	default:
		t.Fatal("no Agent report while Clash unavailable")
	}
}
