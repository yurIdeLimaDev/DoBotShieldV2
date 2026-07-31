package waf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	maxStructuredDepth = 64
	maxStructuredNodes = 10000
)

func inspectStructuredBody(r *http.Request, body []byte) (bool, string, string) {
	if r == nil || len(body) == 0 {
		return false, "", ""
	}

	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" {
		return false, "", ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return true, "MALFORMED_CONTENT_TYPE in Header Content-Type", "BODY-010"
	}
	mediaType = strings.ToLower(mediaType)

	switch {
	case mediaType == "application/x-www-form-urlencoded":
		return inspectFormBody(body)
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return inspectJSONBody(body)
	case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml"):
		return inspectXMLBody(body)
	default:
		return false, "", ""
	}
}

func inspectFormBody(body []byte) (bool, string, string) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return true, "MALFORMED_FORM in Body", "BODY-011"
	}
	for name, entries := range values {
		if malicious, category, rule := analyzePayload(name); malicious {
			return true, category + " in Form Field Name", rule
		}
		for _, value := range entries {
			if malicious, category, rule := analyzePayload(value); malicious {
				return true, category + " in Form Field " + name, rule
			}
		}
	}
	return false, "", ""
}

func inspectJSONBody(body []byte) (bool, string, string) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	nodes := 0
	var inspectValue func(int) (bool, string, string)
	inspectValue = func(depth int) (bool, string, string) {
		token, err := decoder.Token()
		if err != nil {
			return true, "MALFORMED_JSON in Body", "BODY-012"
		}
		nodes++
		if depth > maxStructuredDepth || nodes > maxStructuredNodes {
			return true, "JSON_COMPLEXITY_LIMIT in Body", "BODY-014"
		}

		switch typed := token.(type) {
		case json.Delim:
			switch typed {
			case '{':
				seen := make(map[string]struct{})
				for decoder.More() {
					keyToken, keyErr := decoder.Token()
					key, ok := keyToken.(string)
					if keyErr != nil || !ok {
						return true, "MALFORMED_JSON in Body", "BODY-012"
					}
					nodes++
					if nodes > maxStructuredNodes {
						return true, "JSON_COMPLEXITY_LIMIT in Body", "BODY-014"
					}
					if _, duplicate := seen[key]; duplicate {
						return true, "DUPLICATE_JSON_KEY in Body", "BODY-018"
					}
					seen[key] = struct{}{}
					if malicious, category, rule := analyzePayload(key); malicious {
						return true, category + " in JSON Key", rule
					}
					if malicious, details, rule := inspectValue(depth + 1); malicious {
						return true, details, rule
					}
				}
				end, endErr := decoder.Token()
				if endErr != nil || end != json.Delim('}') {
					return true, "MALFORMED_JSON in Body", "BODY-012"
				}
			case '[':
				for decoder.More() {
					if malicious, details, rule := inspectValue(depth + 1); malicious {
						return true, details, rule
					}
				}
				end, endErr := decoder.Token()
				if endErr != nil || end != json.Delim(']') {
					return true, "MALFORMED_JSON in Body", "BODY-012"
				}
			default:
				return true, "MALFORMED_JSON in Body", "BODY-012"
			}
		case string:
			if malicious, category, rule := analyzePayload(typed); malicious {
				return true, category + " in JSON Value", rule
			}
		}
		return false, "", ""
	}

	if malicious, details, rule := inspectValue(0); malicious {
		return true, details, rule
	}
	if _, err := decoder.Token(); err != io.EOF {
		return true, "MALFORMED_JSON in Body", "BODY-013"
	}
	return false, "", ""
}

func inspectXMLBody(body []byte) (bool, string, string) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	depth, nodes := 0, 0

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return false, "", ""
		}
		if err != nil {
			return true, "MALFORMED_XML in Body", "BODY-015"
		}
		nodes++
		if nodes > maxStructuredNodes {
			return true, "XML_COMPLEXITY_LIMIT in Body", "BODY-016"
		}

		switch typed := token.(type) {
		case xml.StartElement:
			depth++
			if depth > maxStructuredDepth {
				return true, "XML_COMPLEXITY_LIMIT in Body", "BODY-017"
			}
			for _, attr := range typed.Attr {
				if malicious, category, rule := analyzePayload(attr.Value); malicious {
					return true, category + " in XML Attribute", rule
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if malicious, category, rule := analyzePayload(string(typed)); malicious {
				return true, category + " in XML Value", rule
			}
		}
	}
}
