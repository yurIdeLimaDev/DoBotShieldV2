package report

import "html/template"

// reportTemplate is a self-contained Training Mode report. html/template
// contextually escapes every event field so captured attack payloads are shown
// as inert text and never executed by the browser.
var reportTemplate = template.Must(template.New("report").Parse(reportHTML))

const reportHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DoBot Shield | Training Mode</title>
<style>{{.CSS}}</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div>
      <p class="eyebrow">DoBot Shield</p>
      <h1>Training Mode: security-event timeline</h1>
      <p class="subtitle">Each item below represents HTTP or WebSocket traffic detected by the WAF. Review the original value, bounded decoding variants, and the rule that made the decision.</p>
    </div>
    <div class="meta">
      <div>Generated <strong>{{.GeneratedAt}}</strong></div>
      {{if .Source}}<div>Source: <strong>{{.Source}}</strong></div>{{end}}
      {{if .FirstSeen}}<div>Period: {{.FirstSeen}} &rarr; {{.LastSeen}}</div>{{end}}
    </div>
  </header>

  {{if eq .Total 0}}
    <div class="empty"><h2>No events recorded</h2><p>Enable Training Mode, generate representative traffic, and run the report generator again.</p></div>
  {{else}}
    <section class="cards">
      <div class="card accent"><div class="label">Total events</div><div class="value">{{.Total}}</div></div>
      <div class="card danger"><div class="label">Blocked</div><div class="value">{{.BlockedCount}}</div></div>
      <div class="card warning"><div class="label">Detected only</div><div class="value">{{.DetectedCount}}</div></div>
      <div class="card"><div class="label">Requests</div><div class="value">{{.RequestCount}}</div></div>
      <div class="card"><div class="label">Responses</div><div class="value">{{.ResponseCount}}</div></div>
	  <div class="card"><div class="label">WebSocket messages</div><div class="value">{{.WebSocketCount}}</div></div>
      <div class="card"><div class="label">Distinct IPs</div><div class="value">{{.UniqueIPs}}</div></div>
      <div class="card"><div class="label">Triggered rules</div><div class="value">{{.UniqueRules}}</div></div>
    </section>

    <section class="grid2">
      <div class="panel"><h2>Events by category</h2>{{range .Categories}}<div class="bar-row"><span class="name" title="{{.Label}}">{{.Label}}</span><span class="bar-track"><span class="bar-fill" data-percent="{{printf "%.1f" .Percent}}"></span></span><span class="num">{{.Count}}</span></div>{{end}}</div>
      <div class="panel"><h2>Top source IPs</h2>{{if .TopIPs}}{{range .TopIPs}}<div class="bar-row"><span class="name" title="{{.Label}}">{{.Label}}</span><span class="bar-track"><span class="bar-fill" data-percent="{{printf "%.1f" .Percent}}"></span></span><span class="num">{{.Count}}</span></div>{{end}}{{else}}<p class="subtitle">No source IPs recorded.</p>{{end}}</div>
    </section>

    {{if .Glossary}}
    <h2 class="section-title">Understand the detected categories</h2>
    <p class="section-lead">Expand a category for a plain-language explanation. A WAF is a compensating control; backend validation, safe APIs, and context-aware output encoding remain required.</p>
    <div class="glossary-list">{{range .Glossary}}
      <details class="gloss-item">
        <summary class="gloss-summary"><span class="badge {{.CategoryClass}}">{{.Category}}</span><span class="gloss-title">{{.Title}}</span><span class="gloss-count">{{.Count}} event(s)</span>{{if .Summary}}<span class="gloss-hint">{{.Summary}}</span>{{end}}</summary>
        <div class="gloss-body">
          <div class="gloss-block attack"><span class="tag">What it means</span><p>{{.Attack}}</p></div>
          {{if .Subtypes}}<h4 class="gloss-sub-title">Common forms</h4><div class="subtypes">{{range .Subtypes}}<div class="subtype"><div class="subtype-name">{{.Name}}</div><p class="subtype-exp">{{.Explanation}}</p>{{if .Example}}<div class="subtype-example"><span class="subtype-ex-label">Example</span><code>{{.Example}}</code></div><p class="subtype-reading"><span class="reading-label">Interpretation:</span> {{.Reading}}</p>{{end}}</div>{{end}}</div>{{end}}
          <div class="gloss-block defense"><span class="tag">DoBot Shield response</span><p>{{.Defense}}</p></div>
        </div>
      </details>
    {{end}}</div>
    {{end}}

    <h2 class="section-title">Event timeline</h2>
    <div class="toolbar">
      <input type="search" id="search" placeholder="Filter by payload, rule, path, or IP...">
      <select id="filterCategory"><option value="">All categories</option>{{range .Categories}}<option value="{{.Label}}">{{.Label}}</option>{{end}}</select>
	  <select id="filterPhase"><option value="">All phases</option><option value="request">HTTP requests</option><option value="response">HTTP responses</option><option value="websocket-client">WebSocket client messages</option><option value="websocket-server">WebSocket server messages</option></select>
      <span class="count" id="visibleCount"></span>
    </div>

    <div id="timeline">{{range .Timeline}}
      <article class="event {{.ActionClass}}" data-category="{{.Category}}" data-phase="{{.Phase}}" data-search="{{.Payload}} {{.Rule}} {{.Path}} {{.IP}} {{.Category}} {{.Location}}">
        <div class="event-head"><span class="idx">#{{.Index}}</span><span class="badge {{.CategoryClass}}">{{.Category}}</span><span class="pill {{.Action}}">{{.Action}}</span><span class="pill phase">{{.Phase}}</span>{{if .Path}}<span class="route">{{if .Method}}<span class="method">{{.Method}}</span> {{end}}{{.Path}}</span>{{end}}<span class="ip">{{.IP}}</span></div>
        <div class="event-head" style="margin-top:6px"><span class="ts">{{.Timestamp}}</span></div>
        <dl class="kv">{{if .Location}}<dt>Location</dt><dd>{{.Location}}</dd>{{end}}{{if .Rule}}<dt>Rule</dt><dd class="rule"><code>{{.Rule}}</code></dd>{{end}}{{if .RequestID}}<dt>Request ID</dt><dd><code>{{.RequestID}}</code></dd>{{end}}</dl>
        {{if .Attack}}<details class="explain"><summary>What was detected and how did DoBot Shield respond?</summary>{{if .FriendlyTitle}}<p style="margin:8px 0 0;font-weight:600">{{.FriendlyTitle}}</p>{{end}}<div class="ex attack"><span class="tag">Threat</span><p>{{.Attack}}</p></div><div class="ex defense"><span class="tag">Defense</span><p>{{.Defense}}</p></div></details>{{end}}
        {{if .Payload}}<div style="margin-top:12px"><dt style="color:var(--muted);font-weight:600;font-size:.86rem">Captured value</dt><pre class="payload">{{.Payload}}</pre></div>{{end}}
        {{if .Variants}}<details class="variants"><summary>Inspection variants ({{len .Variants}})</summary><ol>{{range .Variants}}<li><code>{{.}}</code></li>{{end}}</ol></details>{{end}}
      </article>
    {{end}}<div class="no-results" id="noResults">No events match the filters.</div></div>
  {{end}}

  <footer>Generated by DoBot Shield Training Mode. Captured values are escaped and displayed as inert text. Protect the report as sensitive security data.</footer>
</div>
<script>
(function(){
  "use strict";
  var fills = document.querySelectorAll(".bar-fill");
  for (var i = 0; i < fills.length; i++) { fills[i].style.width = (fills[i].getAttribute("data-percent") || "0") + "%"; }
  var search = document.getElementById("search");
  var filterCategory = document.getElementById("filterCategory");
  var filterPhase = document.getElementById("filterPhase");
  var counter = document.getElementById("visibleCount");
  var noResults = document.getElementById("noResults");
  if (!search) { return; }
  var events = Array.prototype.slice.call(document.querySelectorAll(".event"));
  function apply(){
    var term = search.value.trim().toLowerCase();
    var category = filterCategory.value;
    var phase = filterPhase.value;
    var visible = 0;
    events.forEach(function(element){
      var text = (element.getAttribute("data-search") || "").toLowerCase();
      var show = (term === "" || text.indexOf(term) !== -1) && (category === "" || element.getAttribute("data-category") === category) && (phase === "" || element.getAttribute("data-phase") === phase);
      element.style.display = show ? "" : "none";
      if (show) { visible++; }
    });
    if (counter) { counter.textContent = visible + " of " + events.length + " event(s)"; }
    if (noResults) { noResults.style.display = visible === 0 ? "block" : "none"; }
  }
  search.addEventListener("input", apply);
  filterCategory.addEventListener("change", apply);
  filterPhase.addEventListener("change", apply);
  apply();
})();
</script>
</body>
</html>`
