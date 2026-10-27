package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type exchange struct {
	status   int
	body     []byte
	banner   string
	finalURL string
	err      string
	evidence []Evidence
}

func New(o Options) *Scanner {
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	if o.SAPI == "" {
		o.SAPI = "auto"
	}
	o.Paths = append([]string(nil), o.Paths...)
	o.Headers = o.Headers.Clone()
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.Insecure}, // Explicit CLI setting.
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
		MaxIdleConns:           100, IdleConnTimeout: 30 * time.Second,
	}
	return &Scanner{options: o, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type countedReader struct {
	reader *bytes.Reader
	count  atomic.Int64
}

func (c *countedReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.count.Add(int64(n))
	return n, err
}

func (s *Scanner) request(ctx context.Context, target string, body []byte, boundary, kind string, probe int) exchange {
	ctx, cancel := context.WithTimeout(ctx, s.options.Timeout)
	defer cancel()
	result := exchange{finalURL: target}
	headers := s.options.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Del("Content-Length")
	headers.Del("Transfer-Encoding")
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", "php2shell-scanner-go/2.0")
	}
	if body != nil {
		headers.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	}
	current := target
	for hop := 0; hop <= 10; hop++ {
		result.finalURL = current
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		counter := &countedReader{reader: bytes.NewReader(body)}
		var input io.Reader
		if body != nil {
			input = counter
		}
		req, err := http.NewRequestWithContext(ctx, method, current, input)
		e := Evidence{URL: current, Kind: kind, Probe: probe, RequestBytes: len(body)}
		if probe > 0 {
			e.SizeMiB = probeSpecs[probe-1][0]
			e.Parts = probeSpecs[probe-1][1]
		}
		if err != nil {
			e.Error = "cannot construct request"
			result.evidence = append(result.evidence, e)
			result.err = e.Error
			return result
		}
		req.Header = headers.Clone()
		// Let servers reject large probes before the upload starts. Without
		// this handshake, closing a connection with unread request data can
		// reset the socket before the client receives the rejection response.
		if probe > 0 && req.Header.Get("Expect") == "" {
			req.Header.Set("Expect", "100-continue")
		}
		req.Close = true
		req.ContentLength = int64(len(body))
		if host := req.Header.Get("Host"); host != "" {
			req.Host = host
			req.Header.Del("Host")
		}
		e.Request = dumpRequest(req, len(body), kind)
		resp, err := s.client.Do(req)
		if err != nil {
			e.Error = exchangeError(ctx, err)
			e.UploadBytesRead = counter.count.Load()
			result.evidence = append(result.evidence, e)
			result.err = e.Error
			return result
		}
		result.status = resp.StatusCode
		result.banner = resp.Header.Get("X-Powered-By")
		data, truncated, readErr := readBody(resp)
		resp.Body.Close()
		e.Status = resp.StatusCode
		e.BodyBytes = len(data)
		e.Truncated = truncated
		e.UploadBytesRead = counter.count.Load()
		e.Response = dumpResponse(resp, data)
		if readErr != nil {
			e.Error = exchangeError(ctx, readErr)
		}
		result.evidence = append(result.evidence, e)
		result.body = data
		if e.Error != "" {
			result.err = e.Error
			return result
		}
		location := resp.Header.Get("Location")
		redirect := resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308
		if !s.options.FollowRedirects || !redirect || location == "" {
			return result
		}
		if hop == 10 {
			result.err = "too many redirects (limit 10)"
			return result
		}
		next, err := req.URL.Parse(location)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") || next.Hostname() == "" || next.User != nil {
			result.err = "redirect to an unsupported URL"
			return result
		}
		if !sameOrigin(req.URL, next) {
			for name := range headers {
				if sensitiveHeader(name) || strings.EqualFold(name, "Host") {
					headers.Del(name)
				}
			}
			// Do not reintroduce secrets on subsequent probes to the redirected origin.
		}
		current = next.String()
	}
	return result
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}
func exchangeError(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "request timed out"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "scan canceled"
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return "TLS certificate verification failed"
	}
	return "HTTP exchange failed; check connectivity, protocol, and response encoding"
}
func readBody(resp *http.Response) ([]byte, bool, error) {
	var reader io.Reader = resp.Body
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") {
		decoder, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, false, err
		}
		defer decoder.Close()
		reader = decoder
	} else if enc := strings.TrimSpace(resp.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil, false, fmt.Errorf("unsupported content encoding")
	}
	data, err := io.ReadAll(io.LimitReader(reader, bodyLimit+1))
	truncated := len(data) > bodyLimit
	if truncated {
		data = data[:bodyLimit]
	}
	return data, truncated, err
}
func sensitiveHeader(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key":
		return true
	}
	return strings.Contains(name, "token") || strings.Contains(name, "secret") || strings.Contains(name, "password") || strings.Contains(name, "api-key")
}
func redactedHeaders(headers http.Header) string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		for _, value := range headers[name] {
			if sensitiveHeader(name) {
				value = "<redacted>"
			}
			fmt.Fprintf(&b, "%s: %s\r\n", name, value)
		}
	}
	return b.String()
}
func dumpRequest(req *http.Request, size int, kind string) string {
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n<%s; %d bytes>", req.Method, req.URL.RequestURI(), req.Host, redactedHeaders(req.Header), size, kind, size)
}
func dumpResponse(resp *http.Response, body []byte) string {
	if len(body) > 2048 {
		body = body[:2048]
	}
	// Go may transparently decompress gzip; record headers as observed by the client.
	return fmt.Sprintf("%s %s\r\n%s\r\n%s", resp.Proto, resp.Status, redactedHeaders(resp.Header), strings.ToValidUTF8(string(body), "�"))
}

// scoped prevents original-origin credentials from being restored when a later
// probe starts at a URL reached through a cross-origin control redirect.
func (s *Scanner) scoped(origin, target string) *Scanner {
	a, _ := url.Parse(origin)
	b, _ := url.Parse(target)
	if sameOrigin(a, b) {
		return s
	}
	options := s.options
	options.Headers = s.options.Headers.Clone()
	for name := range options.Headers {
		if sensitiveHeader(name) || strings.EqualFold(name, "Host") {
			options.Headers.Del(name)
		}
	}
	return &Scanner{client: s.client, options: options}
}
