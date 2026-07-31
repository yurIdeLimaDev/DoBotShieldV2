package report

import (
	"html/template"
	"os"
	"path/filepath"
	"runtime"
)

// reportCSSRelPath points to the report stylesheet's single source of truth.
// The generator embeds it so the generated report remains self-contained.
var reportCSSRelPath = filepath.Join("admin-config", "styles", "report.css")

// loadReportCSS locates and returns the report stylesheet as trusted template
// CSS. A minimal fallback keeps the report readable when the asset is absent.
func loadReportCSS() template.CSS {
	for _, path := range reportCSSCandidates() {
		if data, err := os.ReadFile(path); err == nil {
			return template.CSS(data)
		}
	}
	return template.CSS(fallbackReportCSS)
}

// reportCSSCandidates lists possible report.css paths in priority order.
func reportCSSCandidates() []string {
	paths := make([]string, 0, 2)
	if _, file, _, ok := runtime.Caller(0); ok {
		// file = <project>/report/cssloader.go; move one level to the root.
		paths = append(paths, filepath.Join(filepath.Dir(file), "..", reportCSSRelPath))
	}
	paths = append(paths, reportCSSRelPath)
	return paths
}

// fallbackReportCSS is used only when the full stylesheet cannot be read.
const fallbackReportCSS = `
  body{margin:0;padding:24px;font-family:system-ui,-apple-system,sans-serif;line-height:1.5;color:#1f2925;background:#f7f9f8}
  .wrap{max-width:1180px;margin:0 auto}
  .card,.panel,.event,.gloss-item{border:1px solid #d8e0dc;border-radius:10px;padding:16px;margin-bottom:12px;background:#fff}
  .badge,.pill{padding:2px 8px;border-radius:999px;font-size:.74rem}
  pre.payload{background:#10221f;color:#e7f4f0;padding:12px;border-radius:8px;overflow:auto}
`
