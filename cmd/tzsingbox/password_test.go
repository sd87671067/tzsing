package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/store"
)

func TestInitializationPreservesAllPasswordBytes(t *testing.T) {
	for _, p := range []string{"密", " ", "\r\n 中文\n", strings.Repeat("🌐长", 3000)} {
		d := t.TempDir()
		input, e := os.CreateTemp(d, "stdin")
		if e != nil {
			t.Fatal(e)
		}
		input.WriteString(p)
		input.Seek(0, 0)
		oldInput, oldArgs := os.Stdin, os.Args
		os.Stdin = input
		os.Args = []string{"tzsingbox", "init-admin"}
		t.Setenv("DB_PATH", filepath.Join(d, "db"))
		t.Setenv("URL_PREFIX", "/testprefix")
		t.Setenv("ADMIN_NAME", "admin")
		err := run()
		os.Stdin = oldInput
		os.Args = oldArgs
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		db, e := store.Open(filepath.Join(d, "db"))
		if e != nil {
			t.Fatal(e)
		}
		u, e := db.ByName("admin")
		db.Close()
		if e != nil || !auth.Check(u.Hash, p) || auth.Check(u.Hash, p+" ") {
			t.Fatal("stdin password was changed")
		}
	}
}
