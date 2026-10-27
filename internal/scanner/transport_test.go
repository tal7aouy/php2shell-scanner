package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// net.Pipe exercises the real HTTP transport without depending on permission to
// open a listening socket. Keep rejection, acceptance, fallback, and disconnect
// scenarios deterministic instead of relying on OS-specific TCP close timing.
func TestProbeContinueHandshake(t *testing.T) {
	for _, mode := range []string{"reject", "continue", "ignore", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			s := New(Options{Timeout: 5 * time.Second})
			defer s.Close()
			transport := s.client.Transport.(*http.Transport)
			if transport.ExpectContinueTimeout <= 0 {
				t.Fatal("transport must wait for approval before uploading probes")
			}
			if mode == "ignore" {
				transport.ExpectContinueTimeout = 20 * time.Millisecond
			}
			transport.Proxy = nil
			type observation struct {
				control bool
				expect  string
				bytes   int64
				err     error
			}
			observed := make(chan observation, 4)
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				t.Cleanup(func() { client.Close(); server.Close() })
				go func() {
					var o observation
					defer func() { server.Close(); observed <- o }()
					server.SetDeadline(time.Now().Add(5 * time.Second))
					req, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						o.err = err
						return
					}
					o.control = req.Header.Get("Content-Type") == "multipart/form-data; boundary=x"
					o.expect = req.Header.Get("Expect")
					if o.control {
						o.bytes, o.err = io.Copy(io.Discard, req.Body)
						if o.err == nil {
							_, o.err = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncontrol")
						}
						return
					}
					switch mode {
					case "reject":
						_, o.err = io.WriteString(server, "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					case "disconnect":
						// No HTTP response exists; this must remain inconclusive.
						return
					default:
						if mode == "continue" {
							if _, o.err = io.WriteString(server, "HTTP/1.1 100 Continue\r\n\r\n"); o.err != nil {
								return
							}
						}
						// In the ignore case, the client must resume after its bounded wait.
						o.bytes, o.err = io.Copy(io.Discard, req.Body)
						if o.err == nil {
							_, o.err = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Powered-By: PHP/8.4.27\r\nConnection: close\r\n\r\nok")
						}
					}
				}()
				return client, nil
			}
			result := s.Scan(context.Background(), "http://example.test")
			want := "PATCHED_VERSION"
			if mode == "reject" || mode == "disconnect" {
				want = "INCONCLUSIVE"
			}
			if result.Verdict != want || len(result.Evidence) != 2 {
				t.Fatalf("%s: %+v", mode, result)
			}
			for i := 0; i < 2; i++ {
				select {
				case o := <-observed:
					if o.err != nil {
						t.Fatal(o.err)
					}
					if o.control {
						if o.expect != "" || o.bytes != int64(len(controlBody)) {
							t.Fatalf("unexpected control: %+v", o)
						}
					} else {
						if o.expect != "100-continue" {
							t.Fatalf("probe missing handshake: %+v", o)
						}
						wantBytes := int64(len(cachedProbe(0)))
						if mode == "reject" || mode == "disconnect" {
							wantBytes = 0
						}
						if o.bytes != wantBytes {
							t.Fatalf("probe body bytes: got %d, want %d", o.bytes, wantBytes)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("HTTP peer did not finish")
				}
			}
			probe := result.Evidence[1]
			switch mode {
			case "reject":
				if probe.Status != 413 || probe.UploadBytesRead != 0 || probe.Error != "" {
					t.Fatal(fmt.Sprintf("early rejection was lost: %+v", probe))
				}
			case "disconnect":
				if probe.Status != 0 || probe.Error == "" {
					t.Fatal("disconnect must not be fabricated into an HTTP failure signal")
				}
			default:
				if probe.Status != 200 || probe.UploadBytesRead != int64(probe.RequestBytes) {
					t.Fatal(probe)
				}
			}
		})
	}
}
