package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Extra passive sources that need no API key. Each one is a public HTTP
// endpoint hunters still use in 2026. They overlap with subfinder when that
// tool is configured with keys; they exist here so a laptop with no provider
// accounts still gets more than crt.sh and the Wayback index.
//
// Every function returns an in-scope set. A source being down, rate-limited or
// HTML-shaped is a skip, not a failed phase.

func extraAPIs() []struct {
	label string
	fn    func(context.Context, string) (*Set, error)
} {
	return []struct {
		label string
		fn    func(context.Context, string) (*Set, error)
	}{
		{"crt.sh certificate transparency", CrtSh},
		{"Wayback Machine index", WaybackHosts},
		{"HackerTarget host search", HackerTarget},
		{"RapidDNS", RapidDNS},
		{"AlienVault OTX", OTX},
		{"Anubis (jldc.me)", Anubis},
		{"SSLMate Cert Spotter", CertSpotter},
		{"ThreatMiner", ThreatMiner},
		{"urlscan.io", URLScan},
	}
}

func HackerTarget(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	url := "https://api.hackertarget.com/hostsearch/?q=" + target
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		s := parseHackerTarget(r, target)
		out = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func parseHackerTarget(r io.Reader, target string) *Set {
	s := NewSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(strings.ToLower(line), "error") {
			continue
		}
		host, _, _ := strings.Cut(line, ",")
		s.Add(host)
	}
	return s.InScope(target)
}

func RapidDNS(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	url := "https://rapiddns.io/subdomain/" + target + "?full=1"
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		body, err := io.ReadAll(io.LimitReader(r, 8<<20))
		if err != nil {
			return err
		}
		out = parseRapidDNS(string(body), target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var rapidHost = regexp.MustCompile(`(?i)>([a-z0-9._-]+\.[a-z0-9.-]+)<`)

func parseRapidDNS(html, target string) *Set {
	s := NewSet()
	for _, m := range rapidHost.FindAllStringSubmatch(html, -1) {
		s.Add(m[1])
	}
	return s.InScope(target)
}

func OTX(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + target + "/passive_dns"
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		var payload struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err := json.NewDecoder(io.LimitReader(r, maxSourceBody)).Decode(&payload); err != nil {
			return err
		}
		s := NewSet()
		for _, rec := range payload.PassiveDNS {
			s.Add(rec.Hostname)
		}
		out = s.InScope(target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func Anubis(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	url := "https://jldc.me/anubis/subdomains/" + target
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		var names []string
		if err := json.NewDecoder(io.LimitReader(r, maxSourceBody)).Decode(&names); err != nil {
			return err
		}
		s := NewSet()
		s.AddAll(names)
		out = s.InScope(target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func CertSpotter(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	url := "https://api.certspotter.com/v1/issuances?domain=" + target +
		"&include_subdomains=true&expand=dns_names"
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		var records []struct {
			DNSNames []string `json:"dns_names"`
		}
		if err := json.NewDecoder(io.LimitReader(r, maxSourceBody)).Decode(&records); err != nil {
			return err
		}
		s := NewSet()
		for _, rec := range records {
			for _, n := range rec.DNSNames {
				s.Add(n)
			}
		}
		out = s.InScope(target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func ThreatMiner(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	url := "https://api.threatminer.org/v2/domain.php?q=" + target + "&rt=5"
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		var payload struct {
			Results []string `json:"results"`
		}
		if err := json.NewDecoder(io.LimitReader(r, maxSourceBody)).Decode(&payload); err != nil {
			return err
		}
		s := NewSet()
		s.AddAll(payload.Results)
		out = s.InScope(target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func URLScan(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	url := "https://urlscan.io/api/v1/search/?q=domain:" + target + "&size=10000"
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		var payload struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
			} `json:"results"`
		}
		if err := json.NewDecoder(io.LimitReader(r, maxSourceBody)).Decode(&payload); err != nil {
			return err
		}
		s := NewSet()
		for _, rec := range payload.Results {
			s.Add(rec.Page.Domain)
		}
		out = s.InScope(target)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DNSIntel pulls names out of the apex's own records. SPF includes, MX/NS
// hostnames and CNAMEs are how "hidden" mail and CDN names leak without ever
// appearing in a certificate.
func DNSIntel(ctx context.Context, target string) (*Set, error) {
	s := NewSet()
	s.Add(target)
	if ns, err := net.DefaultResolver.LookupNS(ctx, target); err == nil {
		for _, n := range ns {
			s.Add(strings.TrimSuffix(n.Host, "."))
		}
	}
	if mx, err := net.DefaultResolver.LookupMX(ctx, target); err == nil {
		for _, m := range mx {
			s.Add(strings.TrimSuffix(m.Host, "."))
		}
	}
	if txts, err := net.DefaultResolver.LookupTXT(ctx, target); err == nil {
		for _, t := range txts {
			for _, name := range spfNames(t) {
				s.Add(name)
			}
		}
	}
	for _, host := range []string{target, "www." + target} {
		if cname, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
			s.Add(strings.TrimSuffix(cname, "."))
		}
	}
	return s.InScope(target), nil
}

var spfInclude = regexp.MustCompile(`(?i)(?:include|a|mx|ptr|exists|redirect=)[:]?([a-z0-9._-]+\.[a-z]{2,})`)

func spfNames(txt string) []string {
	if !strings.Contains(strings.ToLower(txt), "v=spf1") {
		return nil
	}
	var out []string
	for _, m := range spfInclude.FindAllStringSubmatch(txt, -1) {
		out = append(out, m[1])
	}
	return out
}

// AXFR tries a zone transfer against each nameserver. It almost never works
// against a well-run zone, and when it does it is the highest-yield single
// query in recon — the entire zone, including names that never got a
// certificate and never appeared in a crawl.
func AXFR(ctx context.Context, target string) (*Set, error) {
	if _, err := exec.LookPath("dig"); err != nil {
		return NewSet(), nil
	}
	ns, err := net.DefaultResolver.LookupNS(ctx, target)
	if err != nil || len(ns) == 0 {
		return NewSet(), nil
	}
	s := NewSet()
	for i, n := range ns {
		if i >= 4 {
			break
		}
		host := strings.TrimSuffix(n.Host, ".")
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		cmd := exec.CommandContext(cctx, "dig", "@"+host, target, "AXFR", "+time=5", "+tries=1")
		out, _ := cmd.Output()
		cancel()
		sc := bufio.NewScanner(strings.NewReader(string(out)))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 0 || strings.HasPrefix(f[0], ";") {
				continue
			}
			s.Add(strings.TrimSuffix(f[0], "."))
		}
	}
	return s.InScope(target), nil
}

func parseJSONStringArray(r io.Reader, target string) (*Set, error) {
	var names []string
	if err := json.NewDecoder(r).Decode(&names); err != nil {
		return nil, fmt.Errorf("not a JSON string array: %w", err)
	}
	s := NewSet()
	s.AddAll(names)
	return s.InScope(target), nil
}
