package report

import "strings"

// CategoryInfo provides a plain-language explanation for a threat category.
type CategoryInfo struct {
	Title    string
	Summary  string
	Attack   string
	Defense  string
	Subtypes []Subtype
}

// Subtype describes one concrete attack form and a short example.
type Subtype struct {
	Name        string
	Explanation string
	Example     string
	Reading     string
}

var categoryGlossary = map[string]CategoryInfo{
	"XSS": threat(
		"Cross-Site Scripting (XSS)",
		"Untrusted markup or script could execute in another user's browser.",
		"An attacker places active HTML or JavaScript in a request and relies on the application to return it without context-aware output encoding.",
		"DoBot Shield decodes common obfuscation layers and rejects recognizable script elements, event handlers, and dangerous URL schemes.",
		Subtype{"Script element", "A script element directly invokes browser code.", "<script>alert(1)</script>", "The browser would treat the value as executable script rather than text."},
		Subtype{"Event handler", "An HTML event handler runs code when an element loads or fails.", "<img src=x onerror=alert(1)>", "The broken image triggers the injected handler."},
	),
	"SQLi": threat(
		"SQL Injection",
		"Input attempts to change the structure of a database query.",
		"An attacker supplies SQL operators, clauses, comments, or delay functions where the application expects ordinary data.",
		"DoBot Shield detects common SQL control structures after layered decoding. The backend must still use parameterized queries as the primary defense.",
		Subtype{"Boolean condition", "A condition that is always true can bypass a vulnerable predicate.", "' OR '1'='1", "The injected OR changes the meaning of the application's query."},
		Subtype{"Union query", "A second result set is attached to the intended query.", "1 UNION SELECT username,password FROM users", "The attacker asks the database to include data from another table."},
	),
	"CMD_INJ": threat(
		"OS Command Injection",
		"Input attempts to append or invoke operating-system commands.",
		"A vulnerable application may concatenate a user value into a shell command, allowing separators or command substitutions to run additional programs.",
		"DoBot Shield detects shell separators, command interpreters, command substitution, and common execution utilities.",
		Subtype{"Shell separator", "A separator starts a second command.", "127.0.0.1; cat /etc/passwd", "The intended lookup is followed by an unrelated file-read command."},
	),
	"PATH_TRAVERSAL": threat(
		"Path Traversal / Local File Inclusion",
		"A path attempts to escape the directory selected by the application.",
		"Sequences such as ../ or encoded variants can make a vulnerable file operation reach configuration, key, or operating-system files.",
		"DoBot Shield normalizes encoded separators and blocks traversal sequences and sensitive absolute paths.",
		Subtype{"Parent traversal", "Parent-directory segments walk above the intended folder.", "../../etc/passwd", "The path leaves the application's content directory."},
	),
	"SSRF": threat(
		"Server-Side Request Forgery (SSRF)",
		"A URL targets an internal, local, link-local, or metadata service.",
		"A vulnerable fetch feature can be made to contact services that are not reachable by the external attacker.",
		"DoBot Shield recognizes private and metadata destinations, including decimal, hexadecimal, octal, shortened, and IPv4-mapped address forms, and blocks dangerous schemes.",
		Subtype{"Cloud metadata", "The URL points to a link-local credential service.", "http://169.254.169.254/latest/meta-data/", "The application would request cloud instance metadata."},
		Subtype{"Numeric loopback", "An unusual numeric spelling still resolves to localhost.", "http://2130706433/admin", "The integer represents 127.0.0.1."},
	),
	"XXE":                          threat("XML External Entity (XXE)", "XML declares an external resource or entity.", "A vulnerable XML parser may read local files, contact internal services, or expand entities excessively.", "DoBot Shield rejects DTD and external-entity markers before the request reaches the backend."),
	"JNDI":                         threat("JNDI Injection", "A lookup expression attempts to make a Java service contact an attacker-controlled resource.", "Affected Java logging or lookup components may resolve a crafted JNDI expression.", "DoBot Shield detects direct and commonly obfuscated JNDI lookup syntax in request data and selected headers."),
	"NoSQLi":                       threat("NoSQL Injection", "Input contains database operators such as $where or $ne.", "A document database query can change meaning when attacker-controlled keys are treated as operators.", "DoBot Shield inspects raw and decoded JSON keys and values for common NoSQL operators."),
	"SSTI":                         threat("Server-Side Template Injection", "Input attempts to execute an expression in a template engine.", "A template expression can expose objects, secrets, or code execution when evaluated by the backend.", "DoBot Shield detects common Jinja, Freemarker, Spring EL, and related expression forms."),
	"PROTOTYPE_POLLUTION":          threat("Prototype Pollution", "Input attempts to write JavaScript prototype properties.", "Keys such as __proto__ or constructor.prototype can change inherited behavior in vulnerable JavaScript applications.", "DoBot Shield detects prototype mutation keys in query, form, and JSON input."),
	"OPEN_REDIRECT":                threat("Open Redirect Attempt", "A redirect parameter points to an external or scheme-relative destination.", "A vulnerable redirect endpoint can send users to a phishing or malware site under a trusted-looking link.", "DoBot Shield detects external targets in common redirect parameters. Application-level destination allowlists remain the primary defense."),
	"RFI":                          threat("Remote File Inclusion", "A file or template parameter references a remote resource.", "Vulnerable include functions may retrieve and execute attacker-controlled content.", "DoBot Shield detects remote and dangerous wrapper schemes in common include parameters."),
	"LDAPi":                        threat("LDAP Injection", "Input attempts to change an LDAP filter.", "Crafted parentheses, wildcards, and Boolean operators can bypass or broaden a vulnerable directory query.", "DoBot Shield detects common LDAP filter manipulation forms."),
	"XPATHi":                       threat("XPath Injection", "Input attempts to change an XPath expression.", "A crafted predicate or axis can bypass a vulnerable XML data query.", "DoBot Shield detects XPath axes, functions, and Boolean manipulation in likely XPath parameters."),
	"PHP_INJECTION":                threat("PHP Injection", "Input contains PHP code, wrappers, or dangerous execution functions.", "Vulnerable include, evaluation, or deserialization paths may interpret the value as PHP code or a special stream.", "DoBot Shield blocks PHP tags, dangerous stream wrappers, and common execution primitives."),
	"UNSAFE_DESERIALIZATION":       threat("Unsafe Deserialization", "Input resembles a serialized executable object graph.", "A vulnerable deserializer can invoke gadget chains or application callbacks while reconstructing attacker-controlled objects.", "DoBot Shield detects selected high-signal Java, PHP, .NET, and Python serialization markers. Safe type-constrained deserialization is still required in the backend."),
	"HTTP_HEADER_INJECTION":        threat("HTTP Header Injection", "Input contains line breaks followed by another header or status line.", "A vulnerable component can interpret attacker-controlled CRLF bytes as a second header or response.", "DoBot Shield rejects raw and encoded header-splitting patterns and malformed header values."),
	"RESPONSE_SQL_ERROR":           threat("Database Error Disclosure", "An error response exposes database implementation details.", "Database errors can reveal engines, queries, schema details, and useful attack feedback.", "By default, DoBot Shield inspects diagnostic patterns only in 4xx/5xx responses and can replace a detected leak with a generic 502 response."),
	"RESPONSE_STACK_TRACE":         threat("Stack Trace Disclosure", "An error response exposes internal files, functions, or line numbers.", "Detailed traces give an attacker a map of application internals.", "DoBot Shield recognizes common language and framework traces in error responses and blocks the leak."),
	"RESPONSE_XSS_PATTERN":         threat("Active Script in Response", "The response contains a potentially executable script pattern.", "This signal does not prove reflection and can match legitimate application scripts or documentation.", "This high-false-positive inspection is disabled by default and should be enabled only after monitor-mode calibration."),
	"RESPONSE_FILE_LEAK":           threat("Sensitive File Disclosure", "The response resembles a private key, credential file, or operating-system account file.", "A traversal or file-read flaw may return secrets even with a successful HTTP status.", "DoBot Shield inspects textual responses for high-signal secret and file-content markers."),
	"MALFORMED_MULTIPART":          threat("Malformed Multipart Request", "A multipart body cannot be parsed consistently.", "Parser differences can let an ambiguous upload bypass one layer and be accepted by another.", "DoBot Shield fails closed when multipart framing is malformed."),
	"MULTIPART_LIMIT":              threat("Multipart Part Limit", "The upload contains too many parts.", "Excessive parts can consume parser resources or conceal malicious content.", "DoBot Shield bounds the number and inspected size of multipart parts."),
	"MULTIPART_PART_TOO_LARGE":     threat("Oversized Multipart Part", "One multipart part exceeds the inspection bound.", "An oversized part can exhaust resources or evade complete inspection.", "DoBot Shield rejects parts that exceed its bounded inspection policy."),
	"MULTIPART_READ_ERROR":         threat("Multipart Read Failure", "A multipart part could not be read safely.", "Truncated or manipulated framing can produce different interpretations across components.", "DoBot Shield fails closed instead of forwarding an ambiguous body."),
	"MALFORMED_QUERY":              threat("Malformed Query String", "The query string contains invalid or ambiguous encoding.", "Different parsers may disagree about malformed separators or percent escapes.", "DoBot Shield rejects a query that Go's canonical parser cannot interpret consistently."),
	"MALFORMED_JSON":               threat("Malformed JSON", "A JSON request is incomplete, invalid, or contains trailing data.", "Lenient parsers and downstream components may disagree about malformed JSON.", "DoBot Shield requires one well-formed JSON value for JSON media types."),
	"MALFORMED_XML":                threat("Malformed XML", "An XML body cannot be parsed consistently.", "Malformed nesting or tokens can exploit parser differences.", "DoBot Shield rejects malformed XML before forwarding it."),
	"JSON_COMPLEXITY_LIMIT":        threat("JSON Complexity Limit", "The JSON structure is too deep or contains too many nodes.", "Deep or highly fragmented input can exhaust parser CPU or stack resources.", "DoBot Shield enforces bounded depth and node counts."),
	"XML_COMPLEXITY_LIMIT":         threat("XML Complexity Limit", "The XML structure is too deep or contains too many tokens.", "Highly complex XML can consume disproportionate parser resources.", "DoBot Shield bounds XML depth and token count."),
	"UNSUPPORTED_CONTENT_ENCODING": threat("Unsupported Content Encoding", "The WAF cannot safely decode the encoded request body.", "Forwarding an opaque body would let the backend inspect data the WAF did not see.", "Blocking mode fails closed for unsupported content encodings."),
	"MALFORMED_CONTENT_ENCODING":   threat("Malformed Compressed Body", "The declared compressed body is corrupt or incomplete.", "Parser discrepancies or malformed compression streams can evade inspection.", "DoBot Shield rejects a body that cannot be decoded consistently."),
	"DECODED_BODY_TOO_LARGE":       threat("Decoded Body Limit", "The expanded body exceeds the configured inspection bound.", "A small compressed request can expand into a resource-exhaustion payload.", "DoBot Shield applies a separate post-decompression size limit."),
	"PROTOCOL_VIOLATION":           threat("HTTP Protocol Violation", "The request uses ambiguous framing or malformed HTTP metadata.", "Frontend and backend parser differences can enable request smuggling, header injection, or routing confusion.", "DoBot Shield rejects ambiguous singleton headers, framing conflicts, unsafe Connection tokens, and bounded-size violations before proxying."),
}

func threat(title, summary, attack, defense string, subtypes ...Subtype) CategoryInfo {
	if len(subtypes) == 0 {
		subtypes = []Subtype{{
			Name:        title + " indicator",
			Explanation: summary,
		}}
	}
	return CategoryInfo{Title: title, Summary: summary, Attack: attack, Defense: defense, Subtypes: subtypes}
}

var defaultCategoryInfo = CategoryInfo{
	Title:   "Suspicious activity detected",
	Summary: "The request or response matched a web-security rule.",
	Attack:  "The traffic contained a pattern associated with malicious or ambiguous web input.",
	Defense: "DoBot Shield applied the configured policy before the traffic could reach its destination.",
}

func lookupCategory(category string) CategoryInfo {
	if info, ok := categoryGlossary[category]; ok {
		return info
	}
	if strings.HasPrefix(category, "CUSTOM_RULE_") {
		return threat(
			"Operator-defined policy match",
			"Traffic matched an application-specific RE2 expression configured by the operator.",
			"The meaning is defined by the local policy and should be reviewed with the rule owner.",
			"DoBot Shield applied the configured monitor, block, or allowlist behavior using the stable custom rule identifier.",
		)
	}
	info := defaultCategoryInfo
	if category != "" && category != "-" {
		info.Title = category
	}
	return info
}
