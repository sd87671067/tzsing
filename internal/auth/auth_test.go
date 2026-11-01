package auth

import (
	"strings"
	"testing"
)

func TestArgon(t *testing.T) {
	a, b := Hash("a sufficiently long password"), Hash("a sufficiently long password")
	if a == b || !Check(a, "a sufficiently long password") || Check(a, "wrong") || Check("bad", "x") {
		t.Fatal("password verification failed")
	}
	if len(Random()) != 43 {
		t.Fatal("token entropy encoding")
	}
}

func TestUnicodePasswordsRemainOpaque(t *testing.T) {
	for _, p := range []string{"密", " ", "a", strings.Repeat("超长🌐 ", 4096), "  中文密码允许 空格 ! 🌐 专线  ", "              ", "Unicode密码与各种特殊符号@$%^&*"} {
		if !ValidPassword(p) || !Check(Hash(p), p) || Check(Hash(p), p+" ") {
			t.Fatal("Unicode or spaces altered")
		}
	}
	for _, p := range []string{"", string([]byte{0xff, 0xff})} {
		if ValidPassword(p) {
			t.Fatal("invalid password accepted")
		}
	}
}
