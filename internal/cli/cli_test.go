package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tal7aouy/php2shell-scanner/internal/scanner"
)

func factoryFor(t *testing.T, check func(scanner.Options), verdict string) func(scanner.Options) (scanFunc, func()) {
	t.Helper()
	return func(o scanner.Options) (scanFunc, func()) {
		if check != nil {
			check(o)
		}
		return func(_ context.Context, target string) scanner.Result {
			return scanner.Result{URL: target, TestedURL: target, FinalURL: target, Verdict: verdict, Reason: "fixture"}
		}, func() {}
	}
}
func TestActiveScanOptions(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"--url", "https://example.test", "--threads", "2", "--timeout", "90", "--sapi", "fpm", "--follow-redirects", "--path", "/custom.php", "--header", "Cookie: session=secret"}, &out, &errOut,
		factoryFor(t, func(o scanner.Options) {
			if o.Passive || o.Timeout.Seconds() != 90 || o.SAPI != "fpm" || !o.FollowRedirects || o.Headers.Get("Cookie") != "session=secret" || !reflect.DeepEqual(o.Paths, []string{"/custom.php"}) {
				t.Fatal(o)
			}
		}, "NO_SIGNAL"))
	if code != 2 || !strings.Contains(out.String(), "NO_SIGNAL") || !strings.Contains(errOut.String(), "active multipart") {
		t.Fatal(code, out.String(), errOut.String())
	}
}
func TestPassiveFlags(t *testing.T) {
	for _, option := range []string{"-passive", "-active=false"} {
		var out bytes.Buffer
		code := run(context.Background(), []string{"-u", "https://example.test", option}, &out, &out, factoryFor(t, func(o scanner.Options) {
			if !o.Passive {
				t.Error("not passive")
			}
		}, "PATCHED_VERSION"))
		if code != 0 {
			t.Fatal(code)
		}
	}
}
func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{
		{}, {"-u", "https://example.test", "-l", "file"},
		{"-u", "https://example.test", "-timeout", "NaN"},
		{"-u", "https://example.test", "-timeout", "0"},
		{"-u", "https://example.test", "-t", "0"},
		{"-u", "https://example.test", "-sapi", "invalid"},
		{"-u", "https://example.test", "-path", "//other.test"},
		{"-u", "https://example.test", "-H", "Cookie: secret\r\n"},
		{"-u", "https://example.test", "-path", "/a", "-path-file", "b"},
	} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			var out bytes.Buffer
			code := run(context.Background(), args, &out, &out, func(scanner.Options) (scanFunc, func()) { t.Fatal("validation sent network request"); return nil, nil })
			if code != 2 {
				t.Fatal(code, out.String())
			}
		})
	}
}
func TestReportsAndDedup(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.txt")
	paths := filepath.Join(dir, "paths.txt")
	os.WriteFile(hosts, []byte("# comment\nexample.test\nhttps://example.test\nhttps://other.test\n"), 0600)
	os.WriteFile(paths, []byte("/one.php\n/two.php\n"), 0600)
	for _, all := range []bool{false, true} {
		t.Run(fmt.Sprint(all), func(t *testing.T) {
			report := filepath.Join(dir, fmt.Sprintf("report-%v.json", all))
			var out, errOut bytes.Buffer
			args := []string{"-l", hosts, "-path-file", paths, "-o", report, "-q"}
			if all {
				args = append(args, "-all-results")
			}
			var mu sync.Mutex
			var visited []string
			factory := func(o scanner.Options) (scanFunc, func()) {
				if len(o.Paths) != 2 {
					t.Fatal(o)
				}
				return func(_ context.Context, target string) scanner.Result {
					mu.Lock()
					visited = append(visited, target)
					mu.Unlock()
					verdict := "PATCHED_VERSION"
					if strings.Contains(target, "example.test") {
						verdict = "SUSPECTED"
					}
					return scanner.Result{URL: target, FinalURL: target, Verdict: verdict}
				}, func() {}
			}
			code := run(context.Background(), args, &out, &errOut, factory)
			if code != 1 || len(visited) != 2 || out.String() != "https://example.test/index.php\n" || errOut.Len() != 0 {
				t.Fatal(code, visited, out.String(), errOut.String())
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				TotalScanned int              `json:"total_scanned"`
				Results      []scanner.Result `json:"results"`
			}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			want := 1
			if all {
				want = 2
			}
			if decoded.TotalScanned != 2 || len(decoded.Results) != want || decoded.Results[0].URL != "https://example.test/index.php" {
				t.Fatal(decoded)
			}
			// Refuse an existing report before creating a scanner or sending traffic.
			code = run(context.Background(), args, &out, &errOut, func(scanner.Options) (scanFunc, func()) { t.Fatal("overwriting report"); return nil, nil })
			if code != 2 {
				t.Fatal(code)
			}
		})
	}
}
func TestCanceledScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	code := run(ctx, []string{"-u", "https://example.test"}, &out, &out, factoryFor(t, nil, "INCONCLUSIVE"))
	if code != 130 {
		t.Fatal(code)
	}
}
func TestHelp(t *testing.T) {
	var out bytes.Buffer
	if code := Run([]string{"-h"}, &out, &out); code != 0 || !strings.Contains(out.String(), "Active by default") {
		t.Fatal(code, out.String())
	}
}

func TestVersionDoesNotScan(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"--version"}, &out, &errOut,
		func(scanner.Options) (scanFunc, func()) {
			t.Fatal("version command created a scanner")
			return nil, nil
		})
	if code != 0 || !strings.Contains(out.String(), "php2shell ") || !strings.Contains(out.String(), "active by default") || errOut.Len() != 0 {
		t.Fatal(code, out.String(), errOut.String())
	}
}

func TestMisplacedURLFlag(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), []string{"-u", "-active", "https://example.test"}, &out, &out,
		func(scanner.Options) (scanFunc, func()) {
			t.Fatal("invalid argument order created a scanner")
			return nil, nil
		})
	if code != 2 || !strings.Contains(out.String(), "URL immediately after") {
		t.Fatal(code, out.String())
	}
}
