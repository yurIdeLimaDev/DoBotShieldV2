package waf

import "regexp"

var (
	xssPatterns                = initXSSPatterns()
	sqliPatterns               = initSQLiPatterns()
	cmdPatterns                = initCMDPatterns()
	traversalPatterns          = initTraversalPatterns()
	ssrfPatterns               = initSSRFPatterns()
	xxePatterns                = initXXEPatterns()
	jndiPatterns               = initJNDIPatterns()
	nosqlPatterns              = initNoSQLPatterns()
	sstiPatterns               = initSSTIPatterns()
	prototypePollutionPatterns = initPrototypePollutionPatterns()
	openRedirectPatterns       = initOpenRedirectPatterns()
	rfiPatterns                = initRFIPatterns()
	ldapPatterns               = initLDAPPatterns()
	xpathPatterns              = initXPathPatterns()
	phpPatterns                = initPHPPatterns()
	deserializationPatterns    = initDeserializationPatterns()
	headerInjectionPatterns    = initHeaderInjectionPatterns()
	responseSQLLeakPatterns    = initResponseSQLLeakPatterns()
	responseStackTracePatterns = initResponseStackTracePatterns()
	responseXSSPatterns        = initResponseXSSPatterns()
	responseFileLeakPatterns   = initResponseFileLeakPatterns()
)

func initXSSPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\s*script`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)<\s*/?\s*(iframe|object|embed|svg|math)\b`),
		regexp.MustCompile(`(?i)on\w+\s*=\s*`),
		regexp.MustCompile(`(?i)alert\s*\(`),
		regexp.MustCompile(`(?i)vbscript\s*:`),
		regexp.MustCompile(`(?i)expression\s*\(`),
		regexp.MustCompile(`(?i)data\s*:\s*text\s*/\s*html`),
		regexp.MustCompile(`(?i)\beval\s*\(`),
		regexp.MustCompile(`(?i)\b(srcdoc|formaction|xlink:href)\s*=`),
		regexp.MustCompile(`(?i)<\s*(base|meta)\b[^>]{0,200}(href|http-equiv)\s*=`),
		regexp.MustCompile(`(?i)\bset(?:timeout|interval)\s*\(`),
		regexp.MustCompile(`(?i)document\s*\.\s*(cookie|write|location)`),
		regexp.MustCompile(`(?i)window\s*\.\s*(location|open)\b`),
		regexp.MustCompile(`(?i)\blocation\s*\.\s*(href|replace|assign)\b`),
	}
}

func initSQLiPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bunion\b[\s\S]{0,120}\bselect\b`),
		regexp.MustCompile(`(?i)\binsert\s+into\b[\s\S]{0,120}\bvalues?\b`),
		regexp.MustCompile(`(?i)\bupdate\s+[a-z0-9_."\[\]-]{1,80}\s+set\b`),
		regexp.MustCompile(`(?i)\bdelete\s+from\b[\s\S]{0,120}\bwhere\b`),
		regexp.MustCompile(`(?i)(?:'|")?\s*(?:or|and)\s+(?:'[^'\r\n]{0,40}'?|"[^"\r\n]{0,40}"?|\d+(?:\.\d+)?)\s*(?:=|~|\blike\b)\s*(?:'[^'\r\n]{0,40}'?|"[^"\r\n]{0,40}"?|\d+(?:\.\d+)?)`),
		regexp.MustCompile(`(?i)\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d`),
		regexp.MustCompile(`(?i)\bwaitfor\s+delay\s+`),
		regexp.MustCompile(`(?i)\b(?:information_schema|pg_catalog|sqlite_master|sysobjects|syscolumns)\b`),
		regexp.MustCompile(`(?i)\b(?:xp_cmdshell|sp_executesql)\b`),
		regexp.MustCompile(`(?i);\s*(?:drop|truncate|alter|create)\s+(?:table|database|schema|index)`),
		regexp.MustCompile(`(?i)(?:'|")\s*(?:--|#|/\*)`),
		regexp.MustCompile(`(?i)\border\s+by\s+\d+\s*(?:--|#|/\*)`),
		regexp.MustCompile(`(?i)\b(?:load_file|into\s+outfile|into\s+dumpfile)\b`),
		regexp.MustCompile(`(?i)\b(?:extractvalue|updatexml)\s*\(`),
	}
}

func initCMDPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)cmd\.exe`),
		regexp.MustCompile(`(?i)/bin/(sh|bash|cat|ls|id|whoami|uname|wget|curl|nc|python|perl|ruby|php)\b`),
		regexp.MustCompile(`(?i)\b(?:powershell|pwsh)\s+(?:-|/)?(?:enc|encodedcommand|nop|w|c|command|file)\b`),
		regexp.MustCompile(`(?i)\b(?:certutil|bitsadmin|mshta|wscript|cscript|rundll32|regsvr32)\s+[-/]`),
		regexp.MustCompile(`(?i)\b(?:bash|sh|cmd)\s+(?:-c|/c)\b`),
		regexp.MustCompile("(?i)`[^`]{1,200}`"),
		regexp.MustCompile(`(?i)\$\([^)]{1,200}\)`),
		regexp.MustCompile(`(?i)(?:;|\||&&|\|\||&)\s*(id|whoami|ls|cat|uname|wget|curl|nc|ncat|netcat|python|perl|ruby|php|bash|sh|cmd|powershell|pwsh)\b`),
		regexp.MustCompile(`\$\{IFS\}`),
	}
}

func initTraversalPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[/?&=])\.\.[\\/]`),
		regexp.MustCompile(`(?i)(\.\.[\\/]){2,}`),
		regexp.MustCompile(`(?i)%2e%2e[%2f%5c/\\]`),
		regexp.MustCompile(`(?i)%252e%252e`),
		regexp.MustCompile(`(?i)\.\.[\\/].*(passwd|shadow|htpasswd|\.conf|\.ini|\.env|\.bak|\.log|\.key|win\.ini|boot\.ini|system32)`),
		regexp.MustCompile(`(?i)(?:^|[\\/])etc[\\/]passwd\b`),
		regexp.MustCompile(`(?i)(?:^|[\\/])proc[\\/]self[\\/]environ\b`),
		regexp.MustCompile(`(?i)[a-z]:[\\/](?:windows|winnt|boot\.ini|system32)`),
	}
}

func initSSRFPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:https?|ftp|gopher|file)://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|\[?::1\]?|\[?(?:fc|fd)[0-9a-f]{2}:|\[?fe80:|169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|metadata)(?:[/?#:\s\]]|$)`),
		regexp.MustCompile(`(?i)\b(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal)\b`),
		regexp.MustCompile(`(?i)\b(?:fc|fd)[0-9a-f]{2}:[0-9a-f:]{2,}\b`),
		regexp.MustCompile(`(?i)\bfe80:[0-9a-f:]{2,}\b`),
		regexp.MustCompile(`(?i)\bfile:///`),
	}
}

func initXXEPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)<!doctype\b[^>]{0,500}\[`),
		regexp.MustCompile(`(?i)<!entity\b`),
		regexp.MustCompile(`(?i)\bsystem\s+["'](?:file|https?)://`),
	}
}

func initJNDIPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)\$\{\s*jndi\s*:`),
		regexp.MustCompile(`(?i)\$\{[\s\S]{0,200}j[\s\S]{0,80}n[\s\S]{0,80}d[\s\S]{0,80}i[\s\S]{0,80}:`),
		regexp.MustCompile(`(?i)\bjndi\s*:\s*(?:ldap|rmi|dns|iiop|http)\s*:`),
	}
}

func initNoSQLPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[?&={,\s"'])\$(?:where|ne|gt|gte|lt|lte|regex|expr|nin|in|or|and)\b`),
		regexp.MustCompile(`(?i)["']\s*\$(?:where|ne|gt|gte|lt|lte|regex|expr|nin|in|or|and)\s*["']\s*:`),
		regexp.MustCompile(`(?i)\bthis\.[a-z0-9_.$-]{1,80}\s*(?:==|!=|>=|<=|>|<)`),
	}
}

func initSSTIPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)\{\{\s*[^}]{0,120}(?:__|config|request|self|cycler|joiner|namespace|7\s*\*\s*7)[^}]{0,120}\s*\}\}`),
		regexp.MustCompile(`(?i)\$\{\s*(?:\d+\s*[*+/\-]\s*\d+|T\s*\(|new\s+java\.|#request|#context)`),
		regexp.MustCompile(`(?i)<#(?:assign|include|import|if|list|setting)\b`),
		regexp.MustCompile(`(?i)\[\#(?:assign|include|import|if|list|setting)\b`),
	}
}

func initPrototypePollutionPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[?&={,\s"'])(?:__proto__|constructor\.prototype)(?:[.\[=:]|%5b)`),
		regexp.MustCompile(`(?i)(?:^|[?&={,\s"'])prototype(?:[.\[]|%5b)[a-z0-9_$-]{1,80}`),
		regexp.MustCompile(`(?i)["'](?:__proto__|constructor|prototype)["']\s*:`),
	}
}

func initOpenRedirectPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[?&])(?:next|url|target|r|redirect|redirect_uri|return|return_to|continue|callback)=\s*(?:https?://|https?:%2f%2f|//|%2f%2f)`),
		regexp.MustCompile(`(?i)(?:^|[?&])(?:next|url|target|r|redirect|redirect_uri|return|return_to|continue|callback)=\s*(?:%5c%5c|\\\\)`),
	}
}

func initHeaderInjectionPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:\r|\n|%0d|%0a)\s*[a-z0-9-]{1,64}\s*:`),
		regexp.MustCompile(`(?i)(?:\r|\n|%0d|%0a)\s*http/[0-9.]`),
	}
}

func initRFIPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[?&{,\s"'])(?:file|page|path|include|template|document|folder|root|download)\s*(?:=|:)\s*["']?(?:https?|ftp)://`),
		regexp.MustCompile(`(?i)(?:^|[?&{,\s"'])(?:file|page|path|include|template)\s*(?:=|:)\s*["']?(?:php|data|zip|phar)://`),
	}
}

func initLDAPPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:\*|%2a)\s*(?:\)|%29)\s*(?:\(|%28)\s*(?:\||&|!)`),
		regexp.MustCompile(`(?i)(?:^|[?&={,\s"'])(?:filter|ldap|search|query)\s*(?:=|:)\s*["']?\(\s*(?:\||&|!)`),
		regexp.MustCompile(`(?i)\(\s*[a-z][a-z0-9._-]{0,63}\s*=\s*\*\s*\)\s*\(\s*\|`),
	}
}

func initXPathPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:ancestor|descendant|following-sibling|preceding-sibling|parent|self)::`),
		regexp.MustCompile(`(?i)(?:^|[?&])(?:xpath|xmlpath|node)=[^&]{0,160}(?:\bor\b|\band\b)[^&]{0,80}=`),
		regexp.MustCompile(`(?i)(?:^|[?&])(?:xpath|xmlpath|node)=[^&]{0,160}(?:count|string|substring|contains|name)\s*\(`),
	}
}

func initPHPPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\?(?:php|=)`),
		regexp.MustCompile(`(?i)\bphp://(?:filter|input|fd|memory|temp)`),
		regexp.MustCompile(`(?i)\b(?:data|zip|phar)://[^\s"']{1,300}`),
		regexp.MustCompile(`(?i)\b(?:assert|passthru|shell_exec|proc_open|popen)\s*\(`),
	}
}

func initDeserializationPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[=:{,"'])rO0AB[a-z0-9+/=]{8,}`),
		regexp.MustCompile(`(?i)(?:^|[=:{,"'])O:\d+:"[^"]{1,100}":\d+:\{`),
		regexp.MustCompile(`(?i)\b(?:__reduce__|ObjectInputStream|BinaryFormatter|LosFormatter)\b`),
	}
}

func initResponseSQLLeakPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bSQLSTATE\[[0-9a-z]{2,5}\]`),
		regexp.MustCompile(`(?i)\b(?:mysql|mariadb|postgres|postgresql|sqlite|oracle|sql server|odbc|jdbc)\b.{0,160}\b(?:error|exception|syntax|driver)\b`),
		regexp.MustCompile(`(?i)\b(?:ORA-\d{5}|PLS-\d{5}|PG::|psql:)`),
		regexp.MustCompile(`(?i)\bsyntax error\b.{0,120}\b(?:near|at or near|in query|line \d+)`),
		regexp.MustCompile(`(?i)\b(?:unclosed quotation mark|unterminated quoted string|quoted string not properly terminated)\b`),
		regexp.MustCompile(`(?i)\b(?:mysql_fetch|mysqli_fetch|pg_query|sqlite_query|sqlsrv_query)\s*\(`),
	}
}

func initResponseStackTracePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)traceback \(most recent call last\):`),
		regexp.MustCompile(`(?i)\bexception in thread\b`),
		regexp.MustCompile(`(?i)\bfatal error:\s+uncaught\b`),
		regexp.MustCompile(`(?i)\b(?:stack trace|stacktrace):`),
		regexp.MustCompile(`(?m)\s+at\s+[a-z0-9_.$<>]+\([^)]{1,160}\.(?:java|kt|scala):\d+\)`),
		regexp.MustCompile(`(?i)\b(?:NullReferenceException|InvalidOperationException|IndexOutOfRangeException|TypeError|ReferenceError)\b`),
		regexp.MustCompile(`(?i)\bpanic:\s+[^\n]{1,200}`),
	}
}

func initResponseXSSPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\s*script[^>]{0,200}>\s*(?:alert|confirm|prompt|eval|fetch)\s*\(`),
		regexp.MustCompile(`(?i)<[^>]{1,200}\bon(?:error|load|click|mouseover|focus)\s*=\s*["']?\s*(?:alert|confirm|prompt|eval|fetch)\s*\(`),
		regexp.MustCompile(`(?i)(?:href|src|formaction)\s*=\s*["']?\s*javascript\s*:\s*(?:alert|confirm|prompt|eval)\s*\(`),
	}
}

func initResponseFileLeakPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)root:[x*]:0:0:`),
		regexp.MustCompile(`(?i)\[(?:boot loader|operating systems)\]`),
		regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\b(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY|PRIVATE_KEY)\s*=`),
	}
}
