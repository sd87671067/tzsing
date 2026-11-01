package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenericExternalWriter(t *testing.T) {
	d := t.TempDir()
	c := filepath.Join(d, "config.json")
	os.WriteFile(c, []byte("{}"), 0600)
	p := filepath.Join(d, "123")
	os.MkdirAll(filepath.Join(p, "fd"), 0700)
	os.MkdirAll(filepath.Join(p, "fdinfo"), 0700)
	os.Symlink(c, filepath.Join(p, "fd", "9"))
	os.WriteFile(filepath.Join(p, "fdinfo", "9"), []byte("flags:\t0100002\n"), 0600)
	if configWriterConflict(d, c) == nil {
		t.Fatal("external writable config allowed")
	}
	os.WriteFile(filepath.Join(p, "fdinfo", "9"), []byte("flags:\t0100000\n"), 0600)
	if e := configWriterConflict(d, c); e != nil {
		t.Fatal(e)
	}
	if configWriterConflict(filepath.Join(d, "missing"), c) == nil {
		t.Fatal("missing inventory allowed")
	}
}
