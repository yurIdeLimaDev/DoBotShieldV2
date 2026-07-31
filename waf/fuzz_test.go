package waf

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzBuildVariants(f *testing.F) {
	for _, seed := range []string{
		"hello", "%253Cscript%253E", `\u003cscript\u003e`, "a\x00b", "&#x3c;script&#x3e;",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 256*1024 {
			t.Skip()
		}
		first := BuildVariants(input)
		second := BuildVariants(input)
		if (input != "" && len(first) == 0) || len(first) > 7 {
			t.Fatalf("unexpected variant count: %d", len(first))
		}
		if len(first) != len(second) {
			t.Fatal("variant generation is not deterministic")
		}
		for index := range first {
			if first[index] != second[index] {
				t.Fatal("variant generation is not deterministic")
			}
		}
	})
}

func FuzzCheckRequest(f *testing.F) {
	f.Add("/search", "q=hello", "text/plain", "Mozilla/5.0", []byte("hello"))
	f.Add("/", "id=1%20UNION%20SELECT%20password", "application/json", "fuzzer", []byte(`{"name":"safe"}`))
	f.Add("/api", "", "application/json", "Mozilla/5.0", []byte(`{"url":"http://169.254.169.254/latest/meta-data"}`))
	f.Fuzz(func(t *testing.T, pathValue, rawQuery, contentType, userAgent string, body []byte) {
		if len(pathValue)+len(rawQuery)+len(contentType)+len(userAgent)+len(body) > 512*1024 {
			t.Skip()
		}
		request := &http.Request{
			Method: http.MethodPost,
			Host:   "example.test",
			URL:    &url.URL{Path: "/" + pathValue, RawQuery: rawQuery},
			Header: http.Header{"Content-Type": []string{contentType}, "User-Agent": []string{userAgent}},
		}
		malicious, details, rule := CheckRequest(request, body)
		maliciousAgain, detailsAgain, ruleAgain := CheckRequest(request, body)
		if malicious != maliciousAgain || details != detailsAgain || rule != ruleAgain {
			t.Fatal("request inspection is not deterministic")
		}
	})
}

func FuzzDecodeBodyForInspection(f *testing.F) {
	f.Add("identity", []byte("hello"), int64(1024))
	f.Add("gzip", []byte{0x1f, 0x8b, 0x08, 0x00}, int64(4096))
	f.Add("deflate", []byte{0x78, 0x9c, 0x00}, int64(128))
	f.Fuzz(func(t *testing.T, encoding string, body []byte, rawLimit int64) {
		if len(encoding) > 256 || len(body) > 512*1024 {
			t.Skip()
		}
		limit := rawLimit%65536 + 1
		if limit < 0 {
			limit = -limit
		}
		decoded, _ := DecodeBodyForInspection(encoding, body, limit)
		normalizedEncoding := strings.ToLower(strings.TrimSpace(encoding))
		if normalizedEncoding != "" && normalizedEncoding != "identity" && int64(len(decoded)) > limit {
			t.Fatalf("decoded body exceeded limit: got %d, limit %d", len(decoded), limit)
		}
	})
}

func FuzzStructuredRequestBodies(f *testing.F) {
	f.Add("application/json", []byte(`{"message":"hello"}`))
	f.Add("application/xml", []byte(`<root><message>hello</message></root>`))
	f.Add("application/json", []byte(`{"message":"<script>alert(1)</script>"}`))
	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		if len(contentType) > 256 || len(body) > 512*1024 {
			t.Skip()
		}
		request := &http.Request{
			Method: http.MethodPost,
			Host:   "example.test",
			URL:    &url.URL{Path: "/api"},
			Header: http.Header{"Content-Type": []string{contentType}},
			Body:   http.NoBody,
		}
		firstMalicious, firstDetails, firstRule := CheckRequest(request, bytes.Clone(body))
		secondMalicious, secondDetails, secondRule := CheckRequest(request, bytes.Clone(body))
		if firstMalicious != secondMalicious || firstDetails != secondDetails || firstRule != secondRule {
			t.Fatal("structured-body inspection is not deterministic")
		}
	})
}
