package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKnownUncoordinatedWriterCannotBeBypassedByConfirmation(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "123"), 0700)
	os.WriteFile(filepath.Join(dir, "123", "comm"), []byte("sbbot\n"), 0600)
	if knownWriterConflict(dir) == nil {
		t.Fatal("independent writer allowed")
	}
	os.WriteFile(filepath.Join(dir, "123", "comm"), []byte("sing-box\n"), 0600)
	if e := knownWriterConflict(dir); e != nil {
		t.Fatal(e)
	}
	if knownWriterConflict(filepath.Join(dir, "missing")) == nil {
		t.Fatal("unknown writer inventory allowed")
	}
}
