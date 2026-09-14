package scan

import (
	"net"
	"strings"
)

// Normalise turns whatever a recon tool emitted into a canonical hostname, or ""
// if the line does not contain one.
//
// Every transformation here exists because some tool in the pipeline produces that
// shape:
//
//	trailing \r          subfinder output collected on a Windows-mounted volume
//	*.example.com        certificate transparency wildcards
//	.example.com         cookie-domain style leading dot
//	example.com.         fully qualified names from DNS tooling
//	HTTPS://Host:8443/x  katana and waybackurls emit URLs, not names
//	1.2.3.4              naabu and puredns emit addresses; they are not names
//
// Case folding matters more than it looks: DNS is case-insensitive, so WWW.host
// and www.host are one name, but the tools disagree about which case to emit and
// an unnormalised merge keeps both — inflating every count and probing everything
// twice.
func Normalise(raw string) string {
	s := strings.TrimSpace(strings.TrimRight(raw, "\r"))
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	s = strings.ToLower(s)

	// A URL, or something with a path attached. Take the host and drop the rest.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 { // user:pass@host
		s = s[i+1:]
	}
	// Strip a port, but not the colons of an IPv6 literal — which is rejected
	// below anyway, so only the unbracketed single-colon case needs care.
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	s = strings.Trim(s, "[]")

	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}

	// An address is a scan target but not a name; keeping them in the name set
	// meant every phase that expected a hostname got addresses too.
	if net.ParseIP(s) != nil {
		return ""
	}
	if !validName(s) {
		return ""
	}
	return s
}

// validName is deliberately stricter than the DNS specification about what may
// appear, and looser about what a label may contain: underscores are illegal in
// hostnames but common in real CDN and service records, so rejecting them loses
// live assets.
func validName(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// InScope reports whether name is target itself or a subdomain of it.
//
// The comparison is anchored on a label boundary. Matching on a bare suffix is the
// classic scope escape: "example.com" as a suffix also matches
// "notexample.com", and a report that includes somebody else's host is worse than
// one that misses ours.
func InScope(name, target string) bool {
	n, t := Normalise(name), strings.ToLower(strings.TrimSuffix(target, "."))
	if n == "" || t == "" {
		return false
	}
	return n == t || strings.HasSuffix(n, "."+t)
}

// CleanTarget normalises a target given on the command line and reports whether it
// is usable. It returns the cleaned form so the caller can echo back exactly what
// is about to be scanned: a target typed with a trailing dot, a wildcard prefix or
// in mixed case should be accepted, but the operator should see the version the
// pipeline will actually use rather than the one they typed.
//
// An IP address is rejected rather than accommodated. The whole pipeline is
// built on DNS enumeration, and pointing it at an address produces an empty run
// that looks like a broken tool.
func CleanTarget(raw string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(raw))
	t = strings.TrimPrefix(t, "*.")
	t = strings.TrimSuffix(t, ".")
	if t == "" || net.ParseIP(t) != nil || !validName(t) {
		return "", false
	}
	return t, true
}
