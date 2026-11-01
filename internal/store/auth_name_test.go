package store

import (
	"path/filepath"
	"testing"
	"tzsingbox/internal/model"
)

func TestAuthNameFallbackRenameAndHistory(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.Exec("INSERT INTO servers(id,name,token) VALUES('s','server','token')")
	u := User{ID: 1, Role: "admin"}
	raw := model.IdentityName("shared", model.UUIDAuthID("00000000-0000-4000-8000-000000000001"))
	makeTag := func(name string) model.Tag {
		return model.Tag{Name: raw, Identity: "inbound", InboundTag: "shared", Type: "vless", AuthName: name, Accounting: "rule_user_observed"}
	}
	tag := makeTag("alice")
	if e = s.Present(u, "s", &tag); e != nil || tag.Name != "alice" || tag.AuthName != "" || tag.NeedsName {
		t.Fatalf("default %+v %v", tag, e)
	}
	id := tag.ID
	s.Exec("INSERT INTO counters VALUES('s',?,'epoch',100,200,100,200,1)", raw)
	s.Exec("UPDATE nodes SET name='显示别名' WHERE id=?", id)
	tag = makeTag("alice-new")
	if e = s.Present(u, "s", &tag); e != nil || tag.ID != id || tag.Name != "显示别名" || *tag.Upload != 100 || *tag.Download != 200 {
		t.Fatal("alias or history lost", tag, e)
	}
	s.Exec("UPDATE nodes SET name='' WHERE id=?", id)
	tag = makeTag("alice-new")
	s.Present(u, "s", &tag)
	if tag.ID != id || tag.Name != "alice-new" {
		t.Fatal("name changed UUID", tag)
	}
}
