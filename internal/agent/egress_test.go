package agent

import (
	"testing"
	"tzsingbox/internal/model"
)

func TestUUIDExitProofAttachmentKeepsCountersIndependent(t *testing.T) {
	proof := model.Exit{Verified: true, IPv4: "8.8.8.8", Updated: 1}
	upA, upB := int64(10), int64(30)
	activeA, activeB := 2, 0
	tags := []model.Tag{{Name: "identity:a", Identity: "inbound", Kind: "actual", RouteVersion: "one", Egress: "shared", Egresses: []model.EgressPath{{Tag: "shared", Type: "socks"}}, Upload: &upA, Active: &activeA}, {Name: "identity:b", Identity: "inbound", Kind: "actual", RouteVersion: "one", Egress: "shared", Egresses: []model.EgressPath{{Tag: "shared", Type: "socks"}}, Upload: &upB, Active: &activeB}, {Name: "identity:multi", Identity: "inbound", Kind: "actual", RouteVersion: "one", Egresses: []model.EgressPath{{Tag: "shared", Type: "socks"}, {Tag: "missing", Type: "socks"}}}}
	get := func(tag string) *model.Exit {
		if tag != "shared" {
			return nil
		}
		v := proof
		return &v
	}
	attachExits(tags, get, true)
	if tags[0].IP == nil || tags[1].IP == nil || tags[0].IP.Path != "shared@one" || tags[1].IP.Path != "shared@one" || *tags[0].Upload != 10 || *tags[1].Upload != 30 || *tags[0].Active != 2 || *tags[1].Active != 0 {
		t.Fatal("shared IP affected UUID counters")
	}
	if tags[2].IP != nil || tags[2].Egresses[0].IP == nil || tags[2].Egresses[1].IP != nil {
		t.Fatal("multi-exit proof collapsed or guessed")
	}
	fresh := []model.Tag{{Identity: "inbound", Kind: "actual", Egress: "shared"}}
	attachExits(fresh, get, false)
	if fresh[0].IP != nil {
		t.Fatal("unverified route used cache")
	}
}
