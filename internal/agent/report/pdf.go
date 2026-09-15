package report

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/toolpath"
)

// PDFResult describes the outcome of ToPDF.
type PDFResult struct {
	// Path is the file that was actually written — the .pdf when a converter
	// was available, otherwise the print-ready .html fallback.
	Path string
	// UsedFallback is true when no headless converter was found (or conversion
	// failed) and a print-ready HTML file was written instead of a PDF.
	UsedFallback bool
	// Converter is the binary used to produce the PDF (e.g. "chromium"), empty
	// on the fallback path.
	Converter string
	// Message is a human-readable note — on the fallback path it tells the user
	// how to turn the HTML into a PDF themselves.
	Message string
}

// resolveConverter finds a headless PDF converter on PATH (or in the managed
// toolbin). Overridable in tests so the fallback path can be exercised without
// requiring — or invoking — a real browser.
var resolveConverter = toolpath.Resolve

// ToPDF renders the print-optimized report and converts it to a real PDF when a
// headless converter is available on PATH — trying, in order: chromium,
// chromium-browser, google-chrome, chrome (via --headless --print-to-pdf), then
// wkhtmltopdf. pdfPath is where the .pdf should be written.
//
// When no converter is found (or conversion fails), ToPDF does NOT error:
// instead it writes the print-ready HTML next to where the PDF would have gone
// and returns a PDFResult explaining how to produce the PDF by hand
// (open it and Print → Save as PDF, or install chromium).
func (r *Renderer) ToPDF(report *pipeline.PentestReport, pdfPath string) (PDFResult, error) {
	// The shareable HTML is already print-optimized (@media print), so it
	// doubles as both the PDF source and the fallback artifact.
	html, err := r.ToShareableHTML(report)
	if err != nil {
		return PDFResult{}, err
	}

	if dir := filepath.Dir(pdfPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return PDFResult{}, fmt.Errorf("create output dir: %w", err)
		}
	}

	// Try each converter in priority order.
	if bin, kind, ok := findConverter(); ok {
		if err := convertToPDF(bin, kind, html, pdfPath); err == nil {
			return PDFResult{Path: pdfPath, Converter: filepath.Base(bin)}, nil
		}
		// Conversion attempted but failed — fall through to the HTML fallback
		// rather than leaving the user with nothing.
	}

	fallbackPath := fallbackHTMLPath(pdfPath)
	if err := os.WriteFile(fallbackPath, html, 0o644); err != nil {
		return PDFResult{}, fmt.Errorf("write print-ready html: %w", err)
	}
	return PDFResult{
		Path:         fallbackPath,
		UsedFallback: true,
		Message: fmt.Sprintf(
			"no headless PDF converter found on PATH — wrote a print-ready HTML report to %s instead. "+
				"Open it in a browser and choose Print → Save as PDF, or install chromium and re-run.",
			fallbackPath),
	}, nil
}

// converterKind distinguishes the two command-line shapes we support.
type converterKind int

const (
	kindChromium converterKind = iota // --headless --print-to-pdf=<out> <html>
	kindWkhtml                        // <html> <out>
)

// findConverter looks up the first available headless converter.
func findConverter() (bin string, kind converterKind, ok bool) {
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if p, found := resolveConverter(name); found {
			return p, kindChromium, true
		}
	}
	if p, found := resolveConverter("wkhtmltopdf"); found {
		return p, kindWkhtml, true
	}
	return "", 0, false
}

// convertToPDF writes the HTML to a temp file and runs the converter.
func convertToPDF(bin string, kind converterKind, html []byte, pdfPath string) error {
	tmp, err := os.CreateTemp(filepath.Dir(pdfPath), "report-*.html")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(html); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	var args []string
	switch kind {
	case kindChromium:
		args = []string{"--headless", "--disable-gpu", "--no-sandbox",
			"--print-to-pdf=" + pdfPath, tmpName}
	case kindWkhtml:
		args = []string{tmpName, pdfPath}
	}

	if err := exec.Command(bin, args...).Run(); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(bin), err)
	}
	// Some converters exit 0 without producing a file on odd inputs — verify.
	if fi, err := os.Stat(pdfPath); err != nil || fi.Size() == 0 {
		return fmt.Errorf("%s produced no output", filepath.Base(bin))
	}
	return nil
}

// fallbackHTMLPath turns "…/report.pdf" into "…/report-print.html" — a
// distinct name so it never clobbers a separately-rendered report.html.
func fallbackHTMLPath(pdfPath string) string {
	ext := filepath.Ext(pdfPath)
	return strings.TrimSuffix(pdfPath, ext) + "-print.html"
}
