package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVersions(t *testing.T) {
	for _, tc := range []struct{ banner, want string }{
		{"PHP/8.2.34", "POTENTIALLY_VULNERABLE"}, {"PHP/8.2.35", "PATCHED_VERSION"},
		{"PHP/8.3.35", "POTENTIALLY_VULNERABLE"}, {"PHP/8.3.36", "PATCHED_VERSION"},
		{"PHP/8.4.26", "POTENTIALLY_VULNERABLE"}, {"PHP/8.4.27", "PATCHED_VERSION"},
		{"PHP/8.5.11", "POTENTIALLY_VULNERABLE"}, {"PHP/8.5.12", "PATCHED_VERSION"},
		{"PHP/8.1.34", "POTENTIALLY_VULNERABLE"}, {"PHP/8.4.27RC1", "UNKNOWN"},
		{"PHP/8.4.26-vendor", "UNKNOWN"}, {"PHP/9.0.0", "UNKNOWN"}, {"", "UNKNOWN"},
	} {
		t.Run(tc.banner, func(t *testing.T) {
			got, _ := VersionVerdict(tc.banner)
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
func TestScanHTTP(t *testing.T) {
	for _, tc := range []struct {
		name         string
		active       bool
		status       int
		banner, want string
		requests     int
	}{
		{"passive", false, 200, "PHP/8.4.26", "POTENTIALLY_VULNERABLE", 1},
		{"patched after first probe", true, 200, "PHP/8.4.27", "PATCHED_VERSION", 2},
		{"blocked", true, 403, "", "INCONCLUSIVE", 1},
		{"baseline failure", true, 502, "", "INCONCLUSIVE", 1},
		{"worker failure", true, 200, "", "SUSPECTED", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if !tc.active && r.Method != "GET" {
					t.Error("passive scan sent non-GET")
				}
				w.Header().Set("X-Powered-By", tc.banner)
				if calls > 1 && tc.banner != "PHP/8.4.27" {
					w.WriteHeader(502)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("baseline"))
			})
			s := New(Options{Passive: !tc.active})
			defer s.Close()
			s.client.Transport = handlerTransport{handler}
			result := s.Scan(context.Background(), "https://example.test")
			if result.Verdict != tc.want || calls != tc.requests {
				t.Fatalf("%+v calls=%d", result, calls)
			}
		})
	}
}

type handlerTransport struct{ handler http.Handler }

func (h handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Consume the upload, matching a server that reads the complete probe.
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
func TestRedirectNotFollowed(t *testing.T) {
	calls := 0
	s := New(Options{})
	defer s.Close()
	s.client.Transport = handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://other.test")
		w.WriteHeader(302)
	})}
	r := s.Scan(context.Background(), "https://example.test")
	if r.Verdict != "INCONCLUSIVE" || calls != 1 {
		t.Fatal(r, calls)
	}
}
func TestResponseLimit(t *testing.T) {
	s := New(Options{Passive: true})
	defer s.Close()
	s.client.Transport = handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", bodyLimit+100))
	})}
	r := s.Scan(context.Background(), "https://example.test")
	if !r.Evidence[0].Truncated || r.Evidence[0].BodyBytes != bodyLimit {
		t.Fatal(r)
	}
}
func TestNormalize(t *testing.T) {
	for _, raw := range []string{"", "ftp://example.com", "https://user:secret@example.com"} {
		if _, err := Normalize(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
