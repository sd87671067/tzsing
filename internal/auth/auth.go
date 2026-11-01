package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/argon2"
	"strings"
	"unicode/utf8"
)

// Passwords are opaque UTF-8: no trimming, normalization or character classes.
func ValidPassword(p string) bool {
	n := utf8.RuneCountInString(p)
	return utf8.ValidString(p) && n >= 14 && n <= 256 && len(p) <= 1024
}

func Random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Digest(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func Hash(p string) string {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		panic(e)
	}
	h := argon2.IDKey([]byte(p), salt, 2, 32*1024, 1, 32)
	return "argon2id$v=19$m=32768,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(h)
}
func Check(encoded, p string) bool {
	v := strings.Split(encoded, "$")
	if len(v) != 5 || v[0] != "argon2id" || v[1] != "v=19" || v[2] != "m=32768,t=2,p=1" {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(v[3])
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(v[4])
	if e != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(p), salt, 2, 32*1024, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
