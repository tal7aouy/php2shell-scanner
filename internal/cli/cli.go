// Package cli implements the PHP2Shell command-line interface.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tal7aouy/php2shell-scanner/internal/scanner"
)

type stringList []string

func (v *stringList) String() string         { return strings.Join(*v, ", ") }
func (v *stringList) Set(value string) error { *v = append(*v, value); return nil }

type timeoutValue time.Duration

func (v *timeoutValue) String() string { return time.Duration(*v).String() }
func (v *timeoutValue) Set(value string) error {
	seconds, err := strconv.ParseFloat(value, 64)
	if err == nil {
		if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 86400 {
			return fmt.Errorf("timeout must be greater than zero and at most 86400 seconds")
		}
		duration := time.Duration(seconds * float64(time.Second))
		if duration <= 0 {
			return fmt.Errorf("timeout is below one nanosecond")
		}
		*v = timeoutValue(duration)
		return nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 24*time.Hour {
		return fmt.Errorf("timeout must be a positive number of seconds or duration, up to 24h")
	}
	*v = timeoutValue(duration)
	return nil
}

type scanFunc func(context.Context, string) scanner.Result

func Run(args []string, out, errOut io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx, args, out, errOut, nil)
}

// run accepts a scanner factory so CLI integration tests use in-memory fixtures.
func run(ctx context.Context, args []string, out, errOut io.Writer, factory func(scanner.Options) (scanFunc, func())) int {
	fs := flag.NewFlagSet("php2shell", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var target, list, output, pathFile, sapi string
	var workers int
	var passive, insecure, follow, all, quiet, verbose, noColor, showVersion bool
	active := true
	timeout := timeoutValue(60 * time.Second)
	var paths, headers stringList
	fs.StringVar(&target, "u", "", "single target URL")
	fs.StringVar(&target, "url", "", "single target URL")
	fs.StringVar(&list, "l", "", "target file (one per line; - for stdin)")
	fs.StringVar(&list, "list", "", "target file (one per line; - for stdin)")
	fs.IntVar(&workers, "t", 10, "concurrent targets (1..256)")
	fs.IntVar(&workers, "threads", 10, "concurrent targets (1..256)")
	fs.Var(&timeout, "timeout", "request timeout: seconds or duration (e.g. 60 or 60s)")
	fs.StringVar(&output, "o", "", "JSON report (new file)")
	fs.StringVar(&output, "output", "", "JSON report (new file)")
	fs.BoolVar(&all, "all-results", false, "include all results in JSON, not only findings")
	fs.BoolVar(&passive, "passive", false, "GET/version check only; skip multipart probes")
	fs.BoolVar(&active, "active", true, "multipart probes (default); -active=false selects passive mode")
	fs.BoolVar(&insecure, "k", false, "disable TLS certificate verification")
	fs.BoolVar(&insecure, "insecure", false, "disable TLS certificate verification")
	fs.BoolVar(&follow, "follow-redirects", false, "follow up to 10 redirects, preserving POST bodies")
	fs.Var(&headers, "H", "custom header, repeatable")
	fs.Var(&headers, "header", "custom header, repeatable")
	fs.Var(&paths, "path", "application path, repeatable")
	fs.StringVar(&pathFile, "path-file", "", "path list, one per line")
	fs.StringVar(&sapi, "sapi", "auto", "signal rules: auto, mod_php, or fpm")
	fs.BoolVar(&quiet, "q", false, "print finding URLs only")
	fs.BoolVar(&quiet, "quiet", false, "print finding URLs only")
	fs.BoolVar(&verbose, "v", false, "print redacted HTTP evidence")
	fs.BoolVar(&verbose, "verbose", false, "print redacted HTTP evidence")
	fs.BoolVar(&noColor, "no-color", false, "disable terminal colors")
	fs.BoolVar(&showVersion, "version", false, "show installed version, revision, and default scan mode")
	fs.Usage = func() {
		fmt.Fprint(errOut, "Usage: php2shell -u URL | -l FILE [options]\n\nActive by default: up to 29 MiB per path; may exhaust PHP memory or interrupt workers.\nUse -passive for a version-only check.\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(errOut, message); return 2 }
	if showVersion {
		fmt.Fprintln(out, buildVersion())
		return 0
	}
	if strings.HasPrefix(target, "-") {
		return fail("-u/--url requires a URL immediately after it; example: php2shell -u https://example.com --follow-redirects")
	}
	if fs.NArg() != 0 || (target == "" && list == "") || (target != "" && list != "") {
		return fail("provide exactly one of -u or -l")
	}
	if workers < 1 || workers > 256 {
		return fail("-t must be between 1 and 256")
	}
	if sapi != "auto" && sapi != "mod_php" && sapi != "fpm" {
		return fail("-sapi must be auto, mod_php, or fpm")
	}
	if pathFile != "" && len(paths) > 0 {
		return fail("use either -path or -path-file")
	}
	passive = passive || !active
	parsed, err := parseHeaders(headers)
	if err != nil {
		return fail(err.Error())
	}
	if pathFile != "" {
		lines, err := loadFile(pathFile)
		if err != nil {
			return fail(err.Error())
		}
		paths = lines
		if len(paths) == 0 {
			return fail("no paths to scan")
		}
	}
	for _, path := range paths {
		if _, err := scanner.ReplacePath("https://example.invalid/index.php", path); err != nil {
			return fail(err.Error())
		}
	}
	inputs := []string{target}
	if target == "" {
		inputs, err = loadFile(list)
		if err != nil {
			return fail(err.Error())
		}
	}
	seen := map[string]bool{}
	targets := make([]string, 0, len(inputs))
	for _, raw := range inputs {
		u, err := scanner.Normalize(raw)
		if err != nil {
			return fail("invalid input target: " + err.Error())
		}
		if !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}
	if len(targets) == 0 {
		return fail("no targets to scan")
	}
	// Open before any network traffic so an invalid output path cannot waste a scan.
	var report *os.File
	if output != "" {
		report, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fail(err.Error())
		}
		defer report.Close()
	}
	options := scanner.Options{Timeout: time.Duration(timeout), Insecure: insecure, Passive: passive, FollowRedirects: follow, SAPI: sapi, Paths: paths, Headers: parsed}
	if factory == nil {
		factory = func(o scanner.Options) (scanFunc, func()) { s := scanner.New(o); return s.Scan, s.Close }
	}
	scan, closeScanner := factory(options)
	defer closeScanner()
	if !quiet {
		mode := "active multipart probes (up to 29 MiB per path; may interrupt PHP workers)"
		if passive {
			mode = "passive version check"
		}
		fmt.Fprintf(errOut, "Scanning %d target(s), %d worker(s), timeout %s, SAPI %s\nMode: %s\n", len(targets), workers, time.Duration(timeout), sapi, mode)
	}
	type item struct {
		index  int
		result scanner.Result
	}
	jobs := make(chan int)
	completed := make(chan item)
	var wg sync.WaitGroup
	for n := 0; n < workers && n < len(targets); n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				completed <- item{i, scan(ctx, targets[i])}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range targets {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(completed) }()
	results := make([]scanner.Result, len(targets))
	done := make([]bool, len(targets))
	count := 0
	for item := range completed {
		results[item.index] = item.result
		done[item.index] = true
		count++
		if !quiet {
			fmt.Fprintf(errOut, "Progress: %d/%d target(s) complete\n", count, len(targets))
		}
	}
	ordered := make([]scanner.Result, 0, count)
	for i, r := range results {
		if !done[i] {
			continue
		}
		ordered = append(ordered, r)
		printResult(out, r, quiet, verbose, !noColor && terminal(out))
	}
	findings, incomplete := 0, 0
	for _, r := range ordered {
		if finding(r) {
			findings++
		} else if r.Verdict != "PATCHED_VERSION" {
			incomplete++
		}
	}
	if !quiet {
		fmt.Fprintf(errOut, "Summary: %d completed, %d finding(s), %d patched-version, %d inconclusive/no-signal\n", len(ordered), findings, len(ordered)-findings-incomplete, incomplete)
	}
	if report != nil {
		selected := ordered
		if !all {
			selected = make([]scanner.Result, 0)
			for _, r := range ordered {
				if finding(r) {
					selected = append(selected, r)
				}
			}
		}
		data := struct {
			ScanTime     time.Time        `json:"scan_time"`
			TotalScanned int              `json:"total_scanned"`
			TotalResults int              `json:"total_results"`
			Results      []scanner.Result `json:"results"`
		}{time.Now().UTC(), len(ordered), len(selected), selected}
		enc := json.NewEncoder(report)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return fail(err.Error())
		}
		if err := report.Close(); err != nil {
			return fail(err.Error())
		}
	}
	if ctx.Err() != nil {
		return 130
	}
	if findings > 0 {
		return 1
	}
	if incomplete > 0 {
		return 2
	}
	return 0
}
func finding(r scanner.Result) bool {
	return r.Verdict == "SUSPECTED" || r.Verdict == "POTENTIALLY_VULNERABLE"
}
func printResult(out io.Writer, r scanner.Result, quiet, verbose, color bool) {
	if quiet {
		if finding(r) {
			fmt.Fprintln(out, r.FinalURL)
		}
		return
	}
	label := "[" + r.Verdict + "]"
	if color {
		code := "33"
		if finding(r) {
			code = "91;1"
		} else if r.Verdict == "PATCHED_VERSION" {
			code = "32"
		}
		label = "\x1b[" + code + "m" + label + "\x1b[0m"
	}
	status := 0
	if len(r.Evidence) > 0 {
		status = r.Evidence[len(r.Evidence)-1].Status
	}
	fmt.Fprintf(out, "%s %q", label, r.TestedURL)
	if status > 0 {
		fmt.Fprintf(out, " - Status: %d", status)
	}
	if r.SAPI != "" {
		fmt.Fprintf(out, " - SAPI: %s", r.SAPI)
	}
	fmt.Fprintf(out, ": %s\n", r.Reason)
	if r.FinalURL != r.TestedURL {
		fmt.Fprintf(out, "  Final URL: %q\n", r.FinalURL)
	}
	if verbose {
		if len(r.PathResults) > 0 {
			for _, path := range r.PathResults {
				printResult(out, path, false, true, color)
			}
			return
		}
		for _, e := range r.Evidence {
			fmt.Fprintf(out, "  %s: HTTP %d, %d response bytes, %d/%d upload bytes read\n", e.Kind, e.Status, e.BodyBytes, e.UploadBytesRead, e.RequestBytes)
			fmt.Fprintf(out, "  Request: %q\n  Response: %q\n", e.Request, e.Response)
		}
	}
}
func parseHeaders(values []string) (http.Header, error) {
	result := make(http.Header)
	for _, h := range values {
		if strings.ContainsAny(h, "\r\n") {
			return nil, fmt.Errorf("invalid custom header: line breaks are unsupported")
		}
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, fmt.Errorf("expected header in 'Name: Value' format")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return nil, fmt.Errorf("invalid custom header name")
			}
		}
		for _, c := range value {
			if (c < 32 && c != '\t') || c == 127 {
				return nil, fmt.Errorf("invalid custom header value")
			}
		}
		result.Set(name, value)
	}
	return result, nil
}
func loadFile(path string) ([]string, error) {
	var reader io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		reader = f
	}
	lines := bufio.NewScanner(reader)
	lines.Buffer(make([]byte, 4096), 1<<20)
	var result []string
	for lines.Scan() {
		v := strings.TrimSpace(lines.Text())
		if v != "" && !strings.HasPrefix(v, "#") {
			result = append(result, v)
		}
	}
	return result, lines.Err()
}

func terminal(out io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
