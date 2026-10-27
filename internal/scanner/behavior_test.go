package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fixture(s *Scanner, handler http.HandlerFunc) { s.client.Transport = handlerTransport{handler} }

func TestDefaultActiveWithoutVersion(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	calls := 0
	fixture(s, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" {
			t.Error("not active")
		}
		if calls == 1 && r.Header.Get("Content-Type") != "multipart/form-data; boundary=x" {
			t.Error("incorrect control")
		}
		if calls > 1 && r.Header.Get("Content-Type") != "multipart/form-data; boundary=" {
			t.Error("incorrect probe")
		}
		fmt.Fprint(w, "same output")
	})
	r := s.Scan(context.Background(), "https://example.test")
	if calls != 4 || r.Verdict != "NO_SIGNAL" || len(r.Evidence) != 4 {
		t.Fatal(r, calls)
	}
	if r.Evidence[3].SizeMiB != 20 || r.Evidence[3].Parts != 1020 {
		t.Fatal(r.Evidence)
	}
}

func TestSAPIRules(t *testing.T) {
	cases := []struct {
		name, sapi string
		status     int
		body, want string
	}{
		{"oom auto", "auto", 500, "Allowed memory size of 123 bytes exhausted in Unknown", "SUSPECTED"},
		{"oom modphp", "mod_php", 500, "Allowed memory size of 123 bytes exhausted in Unknown", "SUSPECTED"},
		{"empty500", "mod_php", 500, "", "SUSPECTED"},
		{"gateway fpm", "fpm", 502, "bad gateway", "SUSPECTED"},
		{"gateway modphp", "mod_php", 502, "bad gateway", "NO_SIGNAL"},
		{"empty200 fpm", "fpm", 200, "", "SUSPECTED"},
		{"empty200 modphp", "mod_php", 200, "", "NO_SIGNAL"},
		{"nonempty500", "auto", 500, "application error", "NO_SIGNAL"},
		{"rejected", "auto", 413, "too large", "INCONCLUSIVE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Options{SAPI: tc.sapi})
			defer s.Close()
			calls := 0
			fixture(s, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					fmt.Fprint(w, "baseline")
					return
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			result := s.Scan(context.Background(), "https://example.test")
			if result.Verdict != tc.want {
				t.Fatal(result)
			}
		})
	}
}

func TestPatchedCrashStillSuspected(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	calls := 0
	fixture(s, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-Powered-By", "PHP/8.4.27")
		if calls > 1 {
			w.WriteHeader(500)
			return
		}
		fmt.Fprint(w, "baseline")
	})
	if r := s.Scan(context.Background(), "https://example.test"); r.Verdict != "SUSPECTED" {
		t.Fatal(r)
	}
}

func TestCustomPathsAndPhpMyAdmin(t *testing.T) {
	s := New(Options{Paths: []string{"/missing", "/admin.php", "/admin.php"}})
	defer s.Close()
	var visited []string
	fixture(s, func(w http.ResponseWriter, r *http.Request) {
		visited = append(visited, r.URL.Path)
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(404)
		case "/admin.php":
			fmt.Fprint(w, "phpMyAdmin")
		case "/show_config_errors.php":
			if r.Header.Get("Content-Type") == "multipart/form-data; boundary=x" {
				fmt.Fprint(w, "control")
			} else {
				w.WriteHeader(502)
			}
		}
	})
	r := s.Scan(context.Background(), "https://example.test")
	if r.Verdict != "SUSPECTED" || r.FinalURL != "https://example.test/show_config_errors.php" || len(r.PathResults) != 2 || len(visited) != 4 {
		t.Fatal(r, visited)
	}
}

func TestRedirectCredentialsAndPOST(t *testing.T) {
	for _, cross := range []bool{false, true} {
		t.Run(fmt.Sprint(cross), func(t *testing.T) {
			headers := http.Header{"Authorization": {"Bearer supersecret"}, "Cookie": {"session=secret"}, "X-Api-Key": {"keysecret"}, "Host": {"example.test"}}
			s := New(Options{FollowRedirects: true, Headers: headers})
			defer s.Close()
			calls := 0
			fixture(s, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" {
					t.Error("redirect changed POST")
				}
				if r.URL.Path == "/index.php" {
					dest := "https://example.test/final.php"
					if cross {
						dest = "https://other.test/final.php"
					}
					w.Header().Set("Location", dest)
					w.WriteHeader(303)
					return
				}
				wantAuth := "Bearer supersecret"
				if cross {
					wantAuth = ""
				}
				if r.Header.Get("Authorization") != wantAuth {
					t.Errorf("authorization restored or lost: %q", r.Header.Get("Authorization"))
				}
				if cross && (r.Header.Get("Cookie") != "" || r.Header.Get("X-Api-Key") != "" || r.Host != "other.test") {
					t.Error("cross-origin secret or Host leak")
				}
				w.Header().Set("X-Powered-By", "PHP/8.4.27")
				w.Header().Set("Set-Cookie", "private-response-cookie")
				fmt.Fprint(w, "output")
			})
			r := s.Scan(context.Background(), "https://example.test")
			if r.Verdict != "PATCHED_VERSION" || calls != 3 {
				t.Fatal(r, calls)
			}
			for _, e := range r.Evidence {
				for _, secret := range []string{"supersecret", "keysecret", "session=secret", "private-response-cookie"} {
					if strings.Contains(e.Request+e.Response, secret) {
						t.Errorf("evidence leaked %s", secret)
					}
				}
			}
		})
	}
}

func TestRedirectLimit(t *testing.T) {
	s := New(Options{FollowRedirects: true})
	defer s.Close()
	calls := 0
	fixture(s, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "/again")
		w.WriteHeader(307)
	})
	r := s.Scan(context.Background(), "https://example.test")
	if r.Verdict != "ERROR" || calls != 11 || !strings.Contains(r.Reason, "too many redirects") {
		t.Fatal(r, calls)
	}
}
func TestPathValidation(t *testing.T) {
	for _, path := range []string{"", "//other.test/path", "/test#fragment"} {
		if _, err := ReplacePath("https://example.test/index.php", path); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
	got, err := ReplacePath("https://example.test/index.php?old=1", "/custom.php?a=2")
	if err != nil || got != "https://example.test/custom.php?a=2" {
		t.Fatal(got, err)
	}
}
func TestGzipLimit(t *testing.T) {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	_, _ = io.WriteString(z, strings.Repeat("x", bodyLimit+10))
	z.Close()
	s := New(Options{Passive: true})
	defer s.Close()
	fixture(s, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	})
	r := s.Scan(context.Background(), "https://example.test")
	if r.Verdict != "UNKNOWN" || !r.Evidence[0].Truncated || r.Evidence[0].BodyBytes != bodyLimit {
		t.Fatal(r)
	}
}

// This verifies the actual net/http wire path, including an early server response.
// The restricted development environment blocks listeners; CI runs this test.
func TestWireEarlyResponse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("sandbox blocks local listeners")
		}
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") == "multipart/form-data; boundary=x" {
			io.Copy(io.Discard, r.Body)
			fmt.Fprint(w, "control")
			return
		}
		// Reject without consuming a large request body.
		if r.Header.Get("Expect") != "100-continue" {
			t.Error("probe must allow rejection before uploading its body")
		}
		w.WriteHeader(413)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	s := New(Options{})
	defer s.Close()
	result := s.Scan(context.Background(), server.URL)
	if result.Verdict != "INCONCLUSIVE" || len(result.Evidence) != 2 || result.Evidence[1].Status != 413 {
		t.Fatal(result)
	}
	if result.Evidence[1].UploadBytesRead != 0 {
		t.Fatal("uploaded a probe body before the server approved it")
	}
}

// Golden hashes verify that the multipart probe payloads remain unchanged.
func TestProbePayloadParity(t *testing.T) {
	for i, tc := range []struct {
		size int
		hash string
	}{
		{1048575, "c9dce21a94b269a93528c324bb3c8de8b1829c8bbbe4ee9ddb5ce0c4d1651ba8"},
		{8388605, "768fd844043b44f44dc8e3be94338c7b778220d7142bb263904cb38d63b8aa64"},
		{20971517, "5835b525e53241c3276b5371bfab717524adf099e73d8adbb4699079cd7d999a"},
	} {
		body := cachedProbe(i)
		sum := fmt.Sprintf("%x", sha256.Sum256(body))
		if len(body) != tc.size || sum != tc.hash {
			t.Fatalf("probe %d differs from the expected payload: length %d, hash %s", i+1, len(body), sum)
		}
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}
func TestTimeoutAndCanceledControl(t *testing.T) {
	s := New(Options{})
	defer s.Close()
	s.client.Transport = failingTransport{}
	r := s.Scan(context.Background(), "https://example.test")
	if r.Verdict != "ERROR" || !strings.Contains(r.Reason, "timed out") {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = s.Scan(ctx, "https://example.test")
	if r.Verdict != "ERROR" {
		t.Fatal(r)
	}
}

func TestRejectedProbeVersionFallback(t *testing.T) {
	for _, tc := range []struct{ banner, want string }{
		{"PHP/8.4.26", "POTENTIALLY_VULNERABLE"},
		{"PHP/8.4.27", "PATCHED_VERSION"},
		{"", "INCONCLUSIVE"},
	} {
		t.Run(tc.banner, func(t *testing.T) {
			s := New(Options{})
			defer s.Close()
			calls := 0
			fixture(s, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("X-Powered-By", tc.banner)
				if calls > 1 {
					w.WriteHeader(413)
					return
				}
				fmt.Fprint(w, "baseline")
			})
			result := s.Scan(context.Background(), "https://example.test")
			if result.Verdict != tc.want || calls != 2 {
				t.Fatal(result, calls)
			}
		})
	}
}
