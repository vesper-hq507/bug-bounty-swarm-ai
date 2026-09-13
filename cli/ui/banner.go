package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Hero palette — the exact tokens from banner/hero.svg and the demo GIF
// (docs/demo-flashy.gif), so the interactive UI matches the README identity:
// amber pheromone accent, agent purple, an "executes" green, cyan recon.
var (
	hVoid   = lipgloss.Color("#0B0E14") // terminal void ground
	hInk    = lipgloss.Color("#E6E9EF") // primary text
	hMuted  = lipgloss.Color("#8A93A6") // secondary text
	hFaint  = lipgloss.Color("#5C6577") // tertiary / rules
	hAmber  = lipgloss.Color("#F5A623") // pheromone accent (primary)
	hCrest  = lipgloss.Color("#FFD580") // amber crest (banner top)
	hEmber  = lipgloss.Color("#99601D") // deep ember (banner base)
	hPurple = lipgloss.Color("#7F77DD") // agents
	hPurpLt = lipgloss.Color("#AFA9EC") // agents (light)
	hGreen  = lipgloss.Color("#3DDC97") // executes / ok
	hCyan   = lipgloss.Color("#57C7FF") // recon / info
	hRed    = lipgloss.Color("#FF6B6B") // danger

	// Semantic styles used across the interactive UI.
	stAmber  = lipgloss.NewStyle().Foreground(hAmber).Bold(true)
	stAmberF = lipgloss.NewStyle().Foreground(hAmber)
	stInk    = lipgloss.NewStyle().Foreground(hInk)
	stMuted  = lipgloss.NewStyle().Foreground(hMuted)
	stFaint  = lipgloss.NewStyle().Foreground(hFaint)
	stPurple = lipgloss.NewStyle().Foreground(hPurpLt)
	stGreen  = lipgloss.NewStyle().Foreground(hGreen)
	stCyan   = lipgloss.NewStyle().Foreground(hCyan)
	stRed    = lipgloss.NewStyle().Foreground(hRed)
)

// swarmWordmark is the "SWARM" block wordmark, painted top-to-bottom in the
// amber crest→ember gradient (same art + shading as the demo GIF banner).
var swarmArt = []string{
	"██████  ██     ██  █████  ██████  ███    ███",
	"██      ██     ██ ██   ██ ██   ██ ████  ████",
	"███████ ██  █  ██ ███████ ██████  ██ ████ ██",
	"     ██ ██ ███ ██ ██   ██ ██   ██ ██  ██  ██",
	"███████  ███ ███  ██   ██ ██   ██ ██      ██",
}

var swarmShades = []lipgloss.Color{hCrest, hAmber, hAmber, lipgloss.Color("#D68C24"), hEmber}

// SwarmWordmark returns the gradient block wordmark as a multi-line string,
// each line indented by pad spaces.
func SwarmWordmark(pad int) string {
	indent := strings.Repeat(" ", pad)
	var b strings.Builder
	for i, ln := range swarmArt {
		b.WriteString(indent + lipgloss.NewStyle().Foreground(swarmShades[i]).Render(ln) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// swarmConstellation is the product thesis as art: four specialist agents
// (recon / classify / exploit / report) converging on a shared blackboard
// core, with pheromone trails. Reads as a swarm, not a mascot.
func swarmConstellation() string {
	dotR := stCyan.Render("◍")   // recon
	dotC := stPurple.Render("◍") // classify
	dotX := stAmberF.Render("◍") // exploit
	dotP := stPurple.Render("◍") // report
	core := stAmber.Render("◈")
	trail := stFaint.Render("·")
	lines := []string{
		"  " + dotR + " recon " + trail + trail + stFaint.Render("╮") + "        " + stFaint.Render("╭") + trail + trail + " exploit " + dotX,
		"             " + core + " " + core + " " + core + "   " + stFaint.Render("blackboard"),
		"  " + dotC + " classify " + stFaint.Render("╯") + "        " + stFaint.Render("╰") + " report " + dotP,
	}
	return strings.Join(lines, "\n")
}

// swarmRule is a honeycomb "pheromone" divider of the given visible width,
// tinted in the amber accent.
func swarmRule(width int) string {
	if width < 8 {
		width = 8
	}
	cells := width / 2
	if cells < 4 {
		cells = 4
	}
	var b strings.Builder
	for i := 0; i < cells; i++ {
		if i%2 == 0 {
			b.WriteString("⬡")
		} else {
			b.WriteString("⬢")
		}
	}
	return stAmberF.Render(b.String())
}

// Banner renders the full hero for the launcher: wordmark + tagline +
// pheromone rule. When width is too narrow for the block art, it falls back
// to a compact one-line mark so nothing wraps into noise.
func Banner(width int) string {
	const artWidth = 46 // widest wordmark line + a little indent
	if width > 0 && width < artWidth+6 {
		return stAmber.Render("◢ PENTEST SWARM") + stMuted.Render("  ·  swarms of agents, one mission")
	}
	var b strings.Builder
	b.WriteString(SwarmWordmark(2) + "\n")
	b.WriteString("  " + stMuted.Render("PENTEST") + "  " + stAmber.Render("SWARM") + "  " +
		stMuted.Render("AI") + stFaint.Render("   ·   swarms of agents, one mission") + "\n")
	b.WriteString(swarmConstellation() + "\n")
	rw := width - 6
	if rw <= 0 || rw > 52 {
		rw = 52
	}
	b.WriteString("  " + swarmRule(rw))
	return b.String()
}
