// Package scanner assesses PHP2Shell exposure without attempting code execution.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const bodyLimit = 1 << 20
const controlBody = "--x\nContent-Disposition:name=a;filename=\n\n"

var versionRE = regexp.MustCompile(`(?i)PHP/(\d+)\.(\d+)\.(\d+)([^\s,;]*)`)
var fixed = map[int]int{2: 35, 3: 36, 4: 27, 5: 12}
var probeSpecs = [][2]int{{1, 4000}, {8, 1020}, {20, 1020}}
var probeCache [3][]byte
var probeOnce [3]sync.Once

type Options struct {
	Timeout         time.Duration
	Insecure        bool
	Passive         bool
	FollowRedirects bool
	SAPI            string
	Paths           []string
	Headers         http.Header
}
type Evidence struct {
	URL             string `json:"url"`
	Kind            string `json:"kind"`
	Probe           int    `json:"probe,omitempty"`
	SizeMiB         int    `json:"size_mib,omitempty"`
	Parts           int    `json:"parts,omitempty"`
	Status          int    `json:"status"`
	BodyBytes       int    `json:"body_bytes"`
	Truncated       bool   `json:"truncated,omitempty"`
	RequestBytes    int    `json:"request_bytes"`
	UploadBytesRead int64  `json:"upload_bytes_read"`
	Error           string `json:"error,omitempty"`
	Request         string `json:"request,omitempty"`
	Response        string `json:"response,omitempty"`
}
type Result struct {
	URL         string     `json:"url"`
	TestedURL   string     `json:"tested_url,omitempty"`
	FinalURL    string     `json:"final_url,omitempty"`
	Verdict     string     `json:"verdict"`
	Reason      string     `json:"reason"`
	SAPI        string     `json:"sapi,omitempty"`
	PoweredBy   string     `json:"powered_by,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	PathResults []Result   `json:"path_results,omitempty"`
	Timestamp   time.Time  `json:"timestamp"`
}
type Scanner struct {
	client  *http.Client
	options Options
}

func (s *Scanner) Close() { s.client.CloseIdleConnections() }

func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid target URL")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("expected HTTP(S) URL without credentials")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("empty target port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid target port")
		}
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/index.php"
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u.String(), nil
}

// ReplacePath keeps a target's origin and accepts only an application path.
func ReplacePath(target, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || strings.Contains(path, "://") {
		return "", fmt.Errorf("empty custom path")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	p, err := url.Parse(path)
	if err != nil || p.Host != "" || p.Scheme != "" || p.Fragment != "" {
		return "", fmt.Errorf("expected a path, optionally including a query")
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target URL")
	}
	u.Path = p.Path
	u.RawPath = p.RawPath
	u.RawQuery = p.RawQuery
	u.ForceQuery = p.ForceQuery
	u.Fragment = ""
	return u.String(), nil
}

// VersionVerdict is advisory: banners may be stale and vendor fixes backported.
func VersionVerdict(banner string) (string, string) {
	matches := versionRE.FindAllStringSubmatch(banner, -1)
	if len(matches) == 0 {
		return "UNKNOWN", "X-Powered-By does not advertise an exact PHP version"
	}
	if len(matches) != 1 {
		return "UNKNOWN", "multiple PHP versions advertised; verify the running runtime"
	}
	m := matches[0]
	major, e1 := strconv.Atoi(m[1])
	minor, e2 := strconv.Atoi(m[2])
	patch, e3 := strconv.Atoi(m[3])
	if e1 != nil || e2 != nil || e3 != nil || m[4] != "" {
		return "UNKNOWN", "invalid, vendor, or prerelease version requires package verification"
	}
	if major < 5 || (major == 5 && minor < 4) {
		return "UNKNOWN", "release outside the verified affected range"
	}
	if major < 8 || (major == 8 && minor < 2) {
		return "POTENTIALLY_VULNERABLE", "end-of-life upstream release; verify vendor backports"
	}
	if threshold, ok := fixed[minor]; major == 8 && ok {
		if patch < threshold {
			return "POTENTIALLY_VULNERABLE", "advertised release predates upstream fixes; verify vendor backports"
		}
		return "PATCHED_VERSION", "advertised release includes initial fixes; verify installed packages and PHP's session upload-progress follow-up guidance"
	}
	return "UNKNOWN", "release outside the verified version table"
}

func probeBody(sizeMiB, parts int) []byte {
	part := []byte("--\nContent-Disposition:name=a[]" + strings.Repeat("[a]", 62) + ";filename=\n\n")
	base := bytes.Repeat(part, parts)
	filler := ((sizeMiB << 20) - len(base)) / 3
	body := make([]byte, 0, sizeMiB<<20)
	body = append(body, "--\n"...)
	body = append(body, bytes.Repeat([]byte("x:\n"), filler)...)
	body = append(body, base[3:]...)
	return body[:len(body)-1]
}
func cachedProbe(i int) []byte {
	probeOnce[i].Do(func() { probeCache[i] = probeBody(probeSpecs[i][0], probeSpecs[i][1]) })
	return probeCache[i]
}

func rejected(status int) bool {
	switch status {
	case 400, 403, 411, 413, 414, 417, 422, 429, 431:
		return true
	}
	return false
}
func crashSignal(control, probe exchange, sapi string) string {
	data := probe.body
	if bytes.Contains(data, []byte("Allowed memory size of ")) && bytes.Contains(data, []byte(" bytes exhausted")) && bytes.Contains(data, []byte("Unknown")) {
		return "PHP memory exhaustion while parsing multipart data"
	}
	if probe.status == 500 && len(control.body) > 0 && len(data) == 0 {
		return "empty HTTP 500 response differs from control output"
	}
	if sapi == "mod_php" {
		return ""
	}
	if probe.status == 502 || probe.status == 503 || probe.status == 504 {
		return fmt.Sprintf("HTTP %d gateway or worker-failure signal", probe.status)
	}
	if probe.status == 200 && len(control.body) > 0 && len(data) == 0 {
		return "empty HTTP 200 response differs from control output (possible PHP-FPM failure)"
	}
	return ""
}

func (s *Scanner) Scan(ctx context.Context, target string) Result {
	normalized, err := Normalize(target)
	if err != nil {
		return Result{Verdict: "ERROR", Reason: err.Error(), Timestamp: time.Now().UTC()}
	}
	targets := []string{normalized}
	if len(s.options.Paths) > 0 {
		targets = nil
		seen := map[string]bool{}
		for _, path := range s.options.Paths {
			u, err := ReplacePath(normalized, path)
			if err != nil {
				return Result{URL: normalized, Verdict: "ERROR", Reason: err.Error(), Timestamp: time.Now().UTC()}
			}
			if !seen[u] {
				seen[u] = true
				targets = append(targets, u)
			}
		}
	}
	var selected Result
	var all []Result
	rank := map[string]int{"NO_SIGNAL": 0, "UNKNOWN": 0, "PATCHED_VERSION": 1, "INCONCLUSIVE": 2, "ERROR": 2, "POTENTIALLY_VULNERABLE": 3, "SUSPECTED": 4}
	for _, u := range targets {
		r := s.scanURL(ctx, normalized, u)
		all = append(all, r)
		if len(all) == 1 || rank[r.Verdict] > rank[selected.Verdict] {
			selected = r
		}
		if r.Verdict == "SUSPECTED" || r.Verdict == "POTENTIALLY_VULNERABLE" || ctx.Err() != nil {
			break
		}
	}
	if len(targets) > 1 {
		selected.PathResults = all
	}
	return selected
}

func (s *Scanner) scanURL(ctx context.Context, host, target string) Result {
	r := Result{URL: host, TestedURL: target, FinalURL: target, Verdict: "UNKNOWN", Timestamp: time.Now().UTC()}
	var body []byte
	boundary := ""
	if !s.options.Passive {
		body = []byte(controlBody)
		boundary = "x"
	}
	control := s.request(ctx, target, body, boundary, "control", 0)
	r.Evidence = append(r.Evidence, control.evidence...)
	r.FinalURL = control.finalURL
	r.PoweredBy = control.banner
	if control.err != "" {
		r.Verdict = "ERROR"
		r.Reason = "control request failed: " + control.err
		return r
	}
	if s.options.Passive {
		r.Verdict, r.Reason = VersionVerdict(control.banner)
		if r.Verdict == "UNKNOWN" {
			r.Reason += fmt.Sprintf(" (HTTP %d); verify installed PHP packages or run without -passive to test behavioral signals", control.status)
		}
		return r
	}
	// Do not send large probes to redirects, missing pages, blocked requests, or failing baselines.
	if control.status < 200 || control.status >= 300 {
		r.Verdict = "INCONCLUSIVE"
		r.Reason = fmt.Sprintf("control returned HTTP %d; supply a working PHP endpoint", control.status)
		return r
	}
	if bytes.Contains(control.body, []byte("phpMyAdmin")) {
		retarget, _ := ReplacePath(control.finalURL, "/show_config_errors.php")
		if retarget != control.finalURL {
			control = s.scoped(target, retarget).request(ctx, retarget, body, boundary, "phpmyadmin_control", 0)
			r.Evidence = append(r.Evidence, control.evidence...)
			r.FinalURL = control.finalURL
			r.PoweredBy = control.banner
			if control.err != "" || control.status < 200 || control.status >= 300 {
				r.Verdict = "INCONCLUSIVE"
				r.Reason = fmt.Sprintf("phpMyAdmin control failed (HTTP %d): %s", control.status, control.err)
				return r
			}
		}
	}
	banner := control.banner
	for i, spec := range probeSpecs {
		if ctx.Err() != nil {
			r.Verdict = "INCONCLUSIVE"
			r.Reason = "scan canceled"
			return r
		}
		probe := s.scoped(target, control.finalURL).request(ctx, control.finalURL, cachedProbe(i), "", "probe", i+1)
		r.Evidence = append(r.Evidence, probe.evidence...)
		r.FinalURL = probe.finalURL
		if probe.banner != "" {
			banner = probe.banner
		}
		r.PoweredBy = banner
		if probe.err != "" {
			r.Verdict = "INCONCLUSIVE"
			r.Reason = fmt.Sprintf("probe %d failed: %s", i+1, probe.err)
			return r
		}
		if rejected(probe.status) || (probe.status >= 300 && probe.status < 500) {
			r.Verdict, r.Reason = VersionVerdict(banner)
			if r.Verdict == "UNKNOWN" {
				r.Verdict = "INCONCLUSIVE"
				r.Reason = fmt.Sprintf("probe %d returned HTTP %d; parsing was not established", i+1, probe.status)
			} else {
				r.Reason = fmt.Sprintf("probe %d returned HTTP %d; version-only assessment: %s", i+1, probe.status, r.Reason)
			}
			return r
		}
		if signal := crashSignal(control, probe, s.options.SAPI); signal != "" {
			r.Verdict = "SUSPECTED"
			r.SAPI = "mod_php/PHP-FPM"
			if s.options.SAPI == "mod_php" {
				r.SAPI = "mod_php"
			}
			if s.options.SAPI == "fpm" || probe.status == 502 || probe.status == 503 || probe.status == 504 || probe.status == 200 {
				r.SAPI = "PHP-FPM"
			}
			r.Reason = fmt.Sprintf("probe %d (%d MiB, %d parts): %s; patched PHP and unrelated server failures can produce the same signal; verify installed packages", i+1, spec[0], spec[1], signal)
			return r
		}
		verdict, reason := VersionVerdict(banner)
		if verdict == "PATCHED_VERSION" {
			r.Verdict = verdict
			r.Reason = "no failure signal observed; " + reason
			return r
		}
	}
	r.Verdict, r.Reason = VersionVerdict(banner)
	if r.Verdict == "UNKNOWN" {
		r.Verdict = "NO_SIGNAL"
		r.Reason = "all three probes completed without a failure signal; PHP version is unknown, so patch status remains unverified"
	}
	return r
}
