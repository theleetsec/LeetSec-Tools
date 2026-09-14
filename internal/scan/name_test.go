package scan

import (
	"strings"
	"testing"
)

func TestNormalise(t *testing.T) {
	cases := map[string]string{
		"Example.COM":                            "example.com",
		"  www.example.com  ":                    "www.example.com",
		"www.example.com\r":                      "www.example.com",
		"*.example.com":                          "example.com",
		".example.com":                           "example.com",
		"example.com.":                           "example.com",
		"HTTPS://api.Example.com:8443/v1/health": "api.example.com",
		"http://user:pw@dev.example.com/":        "dev.example.com",
		"api.example.com:443":                    "api.example.com",
		"cdn_1.example.com":                      "cdn_1.example.com",
		"# a comment":                            "",
		"":                                       "",
		"192.0.2.10":                             "",
		"[2001:db8::1]:443":                      "",
		"localhost":                              "", // no dot: not a scan target
		"-bad.example.com":                       "",
		"bad-.example.com":                       "",
		"has space.example.com":                  "",
		strings.Repeat("a", 64) + ".example.com": "",
	}
	for in, want := range cases {
		if got := Normalise(in); got != want {
			t.Errorf("Normalise(%q) = %q, want %q", in, got, want)
		}
	}
}

// The suffix check is the one piece of scope logic that can leak another party's
// infrastructure into a report, so it is tested from both directions.
func TestInScope(t *testing.T) {
	in := []string{"example.com", "www.example.com", "a.b.c.example.com", "WWW.EXAMPLE.COM"}
	out := []string{"notexample.com", "example.com.evil.net", "example.co", "evil-example.com", ""}
	for _, n := range in {
		if !InScope(n, "example.com") {
			t.Errorf("InScope(%q) = false, want true", n)
		}
	}
	for _, n := range out {
		if InScope(n, "example.com") {
			t.Errorf("InScope(%q) = true, want false", n)
		}
	}
}

func TestCleanTarget(t *testing.T) {
	ok := map[string]string{
		"example.com":   "example.com",
		"Example.COM.":  "example.com",
		"*.example.com": "example.com",
		" example.com ": "example.com",
	}
	for in, want := range ok {
		got, valid := CleanTarget(in)
		if !valid || got != want {
			t.Errorf("CleanTarget(%q) = (%q, %v), want (%q, true)", in, got, valid, want)
		}
	}
	for _, in := range []string{"", "localhost", "192.0.2.1", "http://", "-.com", "a..b"} {
		if got, valid := CleanTarget(in); valid {
			t.Errorf("CleanTarget(%q) = (%q, true), want invalid", in, got)
		}
	}
}
