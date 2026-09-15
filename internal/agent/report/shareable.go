package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// ToShareableHTML renders a polished, fully self-contained security report as a
// single HTML file. Everything is inlined (CSS lives in a <style> tag, there
// are no external assets or CDN references), so the file can be emailed,
// dropped in a bucket, or opened offline anywhere and still look right.
//
// The layout is on-brand (absolute-black background + brand green), print
// friendly (@media print switches to a white background and page-breaks
// findings), and read-only — this is the "shareable report" artifact. There is
// no hosting backend; it's just a file.
func (r *Renderer) ToShareableHTML(report *pipeline.PentestReport) ([]byte, error) {
	data := buildShareableData(report)

	tmpl, err := template.New("shareable").Funcs(template.FuncMap{}).Parse(shareableTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse shareable template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render shareable html: %w", err)
	}
	return buf.Bytes(), nil
}

// shareableData is the flattened view model the shareable template renders.
type shareableData struct {
	Target      string
	Objective   string
	Date        string
	ExecSummary string
	OverallRisk string

	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int

	Findings []shareableFinding
}

type shareableFinding struct {
	Index          int
	Title          string
	SeverityClass  string // css-safe: critical|high|medium|low|info
	SeverityLabel  string // display: CRITICAL, HIGH, ...
	CVSS           string // "" when no score
	Classification []string
	Components     []string
	Description    string
	Evidence       []string
	Remediation    string
}

func buildShareableData(report *pipeline.PentestReport) shareableData {
	d := shareableData{
		Target:      report.Target,
		Objective:   report.Objective,
		ExecSummary: report.ExecutiveSummary,
		OverallRisk: report.RiskSummary.OverallRisk,
		Critical:    report.RiskSummary.CriticalCount,
		High:        report.RiskSummary.HighCount,
		Medium:      report.RiskSummary.MediumCount,
		Low:         report.RiskSummary.LowCount,
		Info:        report.RiskSummary.InfoCount,
	}
	if !report.GeneratedAt.IsZero() {
		d.Date = report.GeneratedAt.Format("January 2, 2006")
	}
	d.Total = d.Critical + d.High + d.Medium + d.Low + d.Info

	for i, f := range report.Findings {
		sf := shareableFinding{
			Index:         i + 1,
			Title:         f.Title,
			SeverityClass: severityClass(f.Severity),
			SeverityLabel: strings.ToUpper(strings.TrimSpace(string(f.Severity))),
			Components:    f.AffectedComponents,
			Description:   f.Description,
			Remediation:   f.Remediation,
		}
		if sf.SeverityLabel == "" {
			sf.SeverityLabel = "UNKNOWN"
		}
		if f.CVSSScore > 0 {
			sf.CVSS = fmt.Sprintf("%.1f", f.CVSSScore)
		}
		if f.OWASP != "" {
			sf.Classification = append(sf.Classification, "OWASP "+f.OWASP)
		}
		if f.CWE != "" {
			sf.Classification = append(sf.Classification, f.CWE)
		}
		if f.ATTACK != "" {
			sf.Classification = append(sf.Classification, "ATT&CK "+f.ATTACK)
		}
		for _, e := range f.Evidence {
			if strings.TrimSpace(e.Content) != "" {
				sf.Evidence = append(sf.Evidence, e.Content)
			}
		}
		d.Findings = append(d.Findings, sf)
	}
	return d
}

// severityClass maps a pipeline severity onto a css-safe class token used by
// both the severity summary and the per-finding pills.
func severityClass(s pipeline.Severity) string {
	switch s {
	case pipeline.SeverityCritical:
		return "critical"
	case pipeline.SeverityHigh:
		return "high"
	case pipeline.SeverityMedium:
		return "medium"
	case pipeline.SeverityLow:
		return "low"
	case pipeline.SeverityInformational:
		return "info"
	default:
		return "info"
	}
}

// shareableTemplate is the single-file HTML template. It is intentionally
// self-contained: no external stylesheets, scripts, fonts, or images — so the
// rendered file works offline and can be shared as-is.
const shareableTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — {{.Target}}</title>
<style>
  :root {
    --bg: #000000;
    --panel: #0b0f0c;
    --panel-2: #11161230;
    --border: #1f2a22;
    --text: #d8e0da;
    --muted: #8a978e;
    --green: #7ce38b;
    --crit: #ff5c5c;
    --high: #ff9f43;
    --med: #ffd43b;
    --low: #7ce38b;
    --info: #7fb0ff;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 0;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 960px; margin: 0 auto; padding: 48px 28px 80px; }
  header.report-head {
    border-bottom: 1px solid var(--border);
    padding-bottom: 28px;
    margin-bottom: 36px;
  }
  .eyebrow {
    text-transform: uppercase;
    letter-spacing: 0.28em;
    font-size: 11px;
    color: var(--green);
    margin: 0 0 12px;
    font-weight: 600;
  }
  h1 { font-size: 32px; margin: 0 0 18px; color: #fff; font-weight: 700; letter-spacing: -0.01em; }
  .meta { display: flex; flex-wrap: wrap; gap: 8px 28px; color: var(--muted); font-size: 14px; }
  .meta strong { color: var(--text); font-weight: 600; }
  h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: 0.18em;
    color: var(--green); margin: 44px 0 16px; font-weight: 600;
  }
  .exec {
    background: var(--panel);
    border: 1px solid var(--border);
    border-left: 3px solid var(--green);
    border-radius: 8px;
    padding: 20px 22px;
    white-space: pre-wrap;
    color: var(--text);
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
  }
  .stat {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }
  .stat .n { font-size: 30px; font-weight: 700; line-height: 1; }
  .stat .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--muted); margin-top: 8px; }
  .stat.critical .n { color: var(--crit); }
  .stat.high .n { color: var(--high); }
  .stat.medium .n { color: var(--med); }
  .stat.low .n { color: var(--low); }
  .stat.info .n { color: var(--info); }

  .finding {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px 24px;
    margin: 16px 0;
  }
  .finding-head { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 10px; }
  .finding-head h3 { font-size: 18px; margin: 0; color: #fff; font-weight: 650; flex: 1 1 240px; }
  .pill {
    display: inline-block;
    font-size: 11px; font-weight: 700; letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 4px 10px; border-radius: 999px;
    border: 1px solid currentColor;
  }
  .pill.critical { color: var(--crit); }
  .pill.high { color: var(--high); }
  .pill.medium { color: var(--med); }
  .pill.low { color: var(--low); }
  .pill.info { color: var(--info); }
  .cvss { font-size: 12px; color: var(--muted); font-weight: 600; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 4px; }
  .tag {
    font-size: 11px; color: var(--green);
    background: rgba(124,227,139,0.08);
    border: 1px solid rgba(124,227,139,0.25);
    border-radius: 5px; padding: 2px 8px;
  }
  .targets { font-size: 13px; color: var(--muted); margin: 6px 0; }
  .targets code {
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 4px; padding: 1px 6px; color: var(--text); font-size: 12px;
  }
  .desc { white-space: pre-wrap; margin: 12px 0; }
  .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--muted); margin: 16px 0 6px; }
  pre.evidence {
    background: #06090720; border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 14px; overflow-x: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12.5px; color: #b7e6c0; white-space: pre-wrap; word-break: break-word;
    margin: 6px 0;
  }
  .remediation {
    background: rgba(124,227,139,0.06);
    border: 1px solid rgba(124,227,139,0.2);
    border-radius: 6px; padding: 12px 14px; white-space: pre-wrap;
  }
  .empty { color: var(--muted); font-style: italic; }
  footer.report-foot { margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }

  @media print {
    body { background: #fff; color: #111; }
    .wrap { max-width: none; padding: 0; }
    .exec, .finding, .stat { background: #fff; border-color: #ccc; }
    .exec { border-left-color: #2c8f3d; }
    h1 { color: #000; }
    h2 { color: #2c8f3d; }
    .finding-head h3 { color: #000; }
    .tag { color: #2c8f3d; background: #f2faf3; border-color: #bfe3c6; }
    pre.evidence { background: #f6f8f6; color: #123; border-color: #ccc; }
    .remediation { background: #f2faf3; border-color: #bfe3c6; }
    .finding { break-inside: avoid; page-break-inside: avoid; }
    .finding + .finding { page-break-before: always; }
    .stat .l, .targets, .cvss, .label { color: #555; }
  }
  @media (max-width: 640px) {
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="report-head">
    <p class="eyebrow">Penetration Test Report</p>
    <h1>{{if .Target}}{{.Target}}{{else}}Security Assessment{{end}}</h1>
    <div class="meta">
      {{if .Target}}<span><strong>Target:</strong> {{.Target}}</span>{{end}}
      {{if .Objective}}<span><strong>Objective:</strong> {{.Objective}}</span>{{end}}
      {{if .Date}}<span><strong>Date:</strong> {{.Date}}</span>{{end}}
      {{if .OverallRisk}}<span><strong>Overall risk:</strong> {{.OverallRisk}}</span>{{end}}
    </div>
  </header>

  <section>
    <h2>Executive Summary</h2>
    {{if .ExecSummary}}<div class="exec">{{.ExecSummary}}</div>{{else}}<p class="empty">No executive summary was generated for this run.</p>{{end}}
  </section>

  <section>
    <h2>Severity Summary</h2>
    <div class="summary-grid">
      <div class="stat critical"><div class="n">{{.Critical}}</div><div class="l">Critical</div></div>
      <div class="stat high"><div class="n">{{.High}}</div><div class="l">High</div></div>
      <div class="stat medium"><div class="n">{{.Medium}}</div><div class="l">Medium</div></div>
      <div class="stat low"><div class="n">{{.Low}}</div><div class="l">Low</div></div>
      <div class="stat info"><div class="n">{{.Info}}</div><div class="l">Info</div></div>
    </div>
  </section>

  <section>
    <h2>Findings{{if .Findings}} ({{len .Findings}}){{end}}</h2>
    {{if not .Findings}}<p class="empty">No findings were reported.</p>{{end}}
    {{range .Findings}}
    <article class="finding">
      <div class="finding-head">
        <span class="pill {{.SeverityClass}}">{{.SeverityLabel}}</span>
        <h3>{{.Index}}. {{.Title}}</h3>
        {{if .CVSS}}<span class="cvss">CVSS {{.CVSS}}</span>{{end}}
      </div>
      {{if .Classification}}
      <div class="tags">{{range .Classification}}<span class="tag">{{.}}</span>{{end}}</div>
      {{end}}
      {{if .Components}}
      <div class="targets">Affected: {{range $i, $c := .Components}}{{if $i}} {{end}}<code>{{$c}}</code>{{end}}</div>
      {{end}}
      {{if .Description}}<div class="desc">{{.Description}}</div>{{end}}
      {{if .Evidence}}
      <div class="label">Evidence</div>
      {{range .Evidence}}<pre class="evidence">{{.}}</pre>{{end}}
      {{end}}
      {{if .Remediation}}
      <div class="label">Remediation</div>
      <div class="remediation">{{.Remediation}}</div>
      {{end}}
    </article>
    {{end}}
  </section>

  <footer class="report-foot">
    Generated by Pentest Swarm AI. This is a read-only report artifact — for print, use your browser's Print dialog (Save as PDF).
  </footer>
</div>
</body>
</html>`
