package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Passive sources that are plain HTTP APIs are queried in-process rather than through
// curl piped into jq.
//
// Three things improve by doing it here. jq stops being a dependency for a phase that
// is otherwise pure Go, which matters on macOS where it is not installed by default.
// The response is parsed as JSON instead of pattern-matched, so a certificate whose
// subject contains a quote or a brace cannot corrupt the output. And there is no shell
// in the path at all — the original built these as command strings with the target
// interpolated into them.

const (
	crtShTimeout    = 2 * time.Minute
	waybackTimeout  = 3 * time.Minute
	maxSourceBody   = 256 << 20 // a runaway response must not fill the disk
	sourceUserAgent = "LeetEnum"
	sourceAttempts  = 3
	sourceBackoff   = 3 * time.Second
)

// CrtSh queries the certificate transparency logs for names under target.
//
// Certificate transparency is the highest-yield passive source there is and the only
// one that reliably returns internal-looking names, because every publicly trusted
// certificate ever issued is in it — including ones for hosts that were never meant
// to be public and no longer resolve.
func CrtSh(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, crtShTimeout)
	defer cancel()

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		var records []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.NewDecoder(io.LimitReader(r, maxSourceBody)).Decode(&records); err != nil {
			return fmt.Errorf("crt.sh returned unparseable JSON: %w", err)
		}
		// Accumulated into a fresh Set inside the closure: a retried attempt must
		// not merge a truncated read of the response with a complete one.
		s := NewSet()
		for _, rec := range records {
			// One record can carry several names, newline separated, because a
			// certificate covers every host in its SAN list.
			for _, n := range strings.Split(rec.NameValue, "\n") {
				s.Add(n)
			}
		}
		out = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out.InScope(target), nil
}

// WaybackHosts pulls hostnames out of the Internet Archive's CDX index.
//
// The archive remembers hosts that DNS has forgotten: a staging box that was linked
// from a page in 2019 is in here and is in no zone file today. Names are extracted
// with net/url rather than by splitting on slashes, because archived URLs routinely
// carry ports and embedded credentials that a field split turns into nonsense
// hostnames.
func WaybackHosts(ctx context.Context, target string) (*Set, error) {
	ctx, cancel := context.WithTimeout(ctx, waybackTimeout)
	defer cancel()

	url := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey",
		target)
	var out *Set
	err := fetchWithRetry(ctx, url, func(r io.Reader) error {
		s := NewSet()
		sc := newLineScanner(io.LimitReader(r, maxSourceBody))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			// CDX emits bare URLs without a scheme for some captures, and HostOf
			// needs one to parse a host rather than a path.
			if !strings.Contains(line, "://") {
				line = "http://" + line
			}
			if h := HostOf(line); h != "" {
				s.Add(h)
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		out = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out.InScope(target), nil
}

// fetchWithRetry runs consume over the response body, retrying the whole
// request-and-parse cycle rather than just the request.
//
// The distinction matters: crt.sh's characteristic failure is dropping a connection
// mid-transfer under load, which arrives as a read or decode error on a truncated
// document, not as a failed request. Retrying only the request would leave the most
// common failure unhandled. consume therefore has to be safe to run more than once,
// which is why both callers build their Set inside the closure and publish it only
// on success.
//
// The response is never buffered so that it could be replayed: a certificate
// transparency answer for a large domain runs to tens of megabytes, and holding it
// in memory to save one re-request is the wrong trade on the 1 GB hosts this is
// meant to run on.
func fetchWithRetry(ctx context.Context, url string, consume func(io.Reader) error) error {
	var lastErr error
	for attempt := 1; attempt <= sourceAttempts; attempt++ {
		if attempt > 1 {
			// The per-source deadline is already on ctx, so a source that is merely
			// slow spends its budget on transfers rather than on sleeping.
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(sourceBackoff):
			}
		}
		body, retryable, err := fetchOnce(ctx, url)
		if err != nil {
			lastErr = err
			if !retryable {
				return err
			}
			continue
		}
		err = consume(body)
		body.Close()
		if err == nil {
			return nil
		}
		lastErr = err
		// A source that has genuinely changed its schema will simply fail all three
		// attempts; an expired context will not improve on a retry.
		if ctx.Err() != nil {
			return lastErr
		}
	}
	return lastErr
}

// fetchOnce reports whether the failure is worth another attempt. A 4xx other than
// 429 is the server saying no, and it will say no again; a transport error, a 429 or
// a 5xx is the server being busy.
func fetchOnce(ctx context.Context, url string) (io.ReadCloser, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", sourceUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retryable, fmt.Errorf("%s returned %s", hostOnly(url), resp.Status)
	}
	return resp.Body, false, nil
}

// hostOnly keeps the target out of error messages that end up in a shared log, and
// keeps those messages short enough to read.
func hostOnly(url string) string {
	if h := HostOf(url); h != "" {
		return h
	}
	return url
}
