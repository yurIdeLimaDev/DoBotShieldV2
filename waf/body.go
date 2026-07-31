package waf

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
)

// DecodeBodyForInspection expands a supported content encoding into a bounded
// inspection buffer. The caller still forwards the original body bytes.
func DecodeBodyForInspection(contentEncoding string, raw []byte, limit int64) ([]byte, *Violation) {
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))
	if encoding == "" || encoding == "identity" || len(raw) == 0 {
		return raw, nil
	}
	if limit <= 0 {
		limit = 4 * 1024 * 1024
	}

	var (
		reader io.ReadCloser
		err    error
	)
	switch encoding {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(raw))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(raw))
	default:
		return nil, &Violation{"UNSUPPORTED_CONTENT_ENCODING in Body", "BODY-001", http.StatusUnsupportedMediaType}
	}
	if err != nil {
		return nil, &Violation{"MALFORMED_CONTENT_ENCODING in Body", "BODY-002", http.StatusBadRequest}
	}
	defer reader.Close()

	decoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, &Violation{"MALFORMED_CONTENT_ENCODING in Body", "BODY-003", http.StatusBadRequest}
	}
	if int64(len(decoded)) > limit {
		return nil, &Violation{"DECODED_BODY_TOO_LARGE in Body", "BODY-004", http.StatusRequestEntityTooLarge}
	}
	if err := reader.Close(); err != nil {
		return nil, &Violation{"MALFORMED_CONTENT_ENCODING in Body", "BODY-005", http.StatusBadRequest}
	}
	return decoded, nil
}
