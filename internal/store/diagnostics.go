package store

import (
	"encoding/json"
	"tzsingbox/internal/model"
)

func (s *Store) diagnose(u User, server string, r model.Report) *model.Diagnostics {
	d := &model.Diagnostics{Reasons: map[string]int{}}
	if r.Discovery != nil {
		d.Discovery = *r.Discovery
	} else {
		seen := map[string]bool{}
		for _, t := range r.Tags {
			if t.Identity == "inbound" {
				seen[t.InboundTag] = true
				if t.AuthID != "" {
					d.AuthIdentities++
				}
			}
		}
		d.Inbounds = len(seen)
		d.Discovered = len(r.Tags)
		d.Reported = len(r.Tags)
	}
	for _, t := range r.Tags {
		t.Classify()
		if t.Identity != "inbound" || !t.DisplayEligible {
			d.BackendFiltered++
			d.Reasons["非入站身份或不可展示"]++
			continue
		}
		d.BackendVisible++
		if !s.Allowed(u, server, t.Name) {
			d.PermissionFiltered++
			d.Reasons["缺少服务器或身份授权"]++
		} else {
			d.Authorized++
		}
	}
	if d.UnsupportedAuth > 0 {
		d.Reasons["UUID 无效或重复，或旧协议认证名称不可用"] = d.UnsupportedAuth
	}
	return d
}
func (s *Store) MonitorDiagnostics(u User) ([]map[string]any, error) {
	rows, e := s.Query("SELECT id,report FROM servers ORDER BY id")
	if e != nil {
		return nil, e
	}
	type raw struct {
		id string
		b  []byte
	}
	var all []raw
	for rows.Next() {
		var r raw
		if e = rows.Scan(&r.id, &r.b); e != nil {
			rows.Close()
			return nil, e
		}
		all = append(all, r)
	}
	rows.Close()
	out := []map[string]any{}
	for _, r := range all {
		var report model.Report
		if json.Unmarshal(r.b, &report) != nil {
			continue
		}
		out = append(out, map[string]any{"server_id": r.id, "counts": s.diagnose(u, r.id, report)})
	}
	return out, nil
}
