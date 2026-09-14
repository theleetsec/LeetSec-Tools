package scan

import (
	"strings"
	"testing"
)

func TestParseHackerTarget(t *testing.T) {
	in := "api.example.com,1.2.3.4\nwww.example.com,1.2.3.5\nerror check your api\n"
	s := parseHackerTarget(strings.NewReader(in), "example.com")
	if !s.Has("api.example.com") || !s.Has("www.example.com") {
		t.Fatalf("got %v", s.Sorted())
	}
}

func TestParseRapidDNSInScope(t *testing.T) {
	html := `<td>dev.example.com</td><td>cdn.notexample.com</td><td>api.internal.example.com</td>`
	s := parseRapidDNS(html, "example.com")
	if !s.Has("dev.example.com") || !s.Has("api.internal.example.com") {
		t.Fatalf("missing in-scope names: %v", s.Sorted())
	}
	if s.Has("cdn.notexample.com") {
		t.Fatal("escaped scope")
	}
}

func TestSPFNames(t *testing.T) {
	got := spfNames("v=spf1 include:_spf.google.com include:mail.example.com -all")
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "_spf.google.com") || !strings.Contains(joined, "mail.example.com") {
		t.Fatalf("spf parse: %v", got)
	}
	if spfNames("hello world") != nil {
		t.Fatal("non-spf should be empty")
	}
}

func TestSubsOnlySkipsHeavyPhases(t *testing.T) {
	p := &Pipeline{opt: Options{SubsOnly: true}}
	if p.wanted("p6") || p.wanted("p8") || p.wanted("p9") {
		t.Fatal("subs mode should skip ports, nuclei, screenshots")
	}
	if !p.wanted("p1") || !p.wanted("p3") || !p.wanted("p7") {
		t.Fatal("subs mode should still run discovery phases")
	}
}
