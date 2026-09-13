package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// LaunchConfig is the scan configuration the interactive launcher collects.
// When IsLab is true, Lab names a bundled target and Target is ignored.
//
// KeyConfigured is an input: when true the caller already has an API key
// available (config/env/keychain), so the launcher won't prompt for one.
// APIKey is an output: a key the user pasted into the launcher for a
// key-based provider (empty otherwise).
type LaunchConfig struct {
	IsLab         bool
	Lab           string
	Target        string
	Mode          string
	Provider      string
	Swarm         bool
	ActiveScan    bool
	Dashboard     bool
	KeyConfigured bool
	APIKey        string
}

// providerMeta describes each selectable provider: whether it authenticates
// with an API key, and a one-line description shown under the picker.
type providerInfo struct {
	needsKey bool
	desc     string
}

var providerMeta = map[string]providerInfo{
	"together":   {true, "Together AI — hosted Llama / Qwen / DeepSeek, needs an API key"},
	"claude":     {true, "Anthropic Claude — frontier quality, needs an API key"},
	"openai":     {true, "OpenAI (or any OpenAI-compatible endpoint), needs an API key"},
	"gemini":     {true, "Google Gemini — needs an API key"},
	"orcarouter": {true, "OrcaRouter — multi-model gateway, needs an API key"},
	"ollama":     {false, "Ollama — fully local models, no key, no cost"},
	"lmstudio":   {false, "LM Studio — local models via its server, no key"},
}

func providerNeedsKeyUI(p string) bool {
	if info, ok := providerMeta[p]; ok {
		return info.needsKey
	}
	return true
}

func providerDesc(p string) string {
	if info, ok := providerMeta[p]; ok {
		return info.desc
	}
	return ""
}

// Brand palette (matches the web dashboard / armur.ai).
var (
	lBrand  = lipgloss.Color("#7ce38b")
	lBrandD = lipgloss.Color("#1f7a3a")
	lInk    = lipgloss.Color("#e9f4ec")
	lDimC   = lipgloss.Color("#5a5a57")
	lLabelC = lipgloss.Color("#8a8a86")

	lsBrand = lipgloss.NewStyle().Foreground(lBrand).Bold(true)
	lsDim   = lipgloss.NewStyle().Foreground(lDimC)
	lsLabel = lipgloss.NewStyle().Foreground(lLabelC)
	lsVal   = lipgloss.NewStyle().Foreground(lInk)
	lsBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lBrandD).Padding(1, 3)
	lsErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5d6e"))
	lsRule  = lipgloss.NewStyle().Foreground(lBrandD)
)

// field focus indices. fAPIKey sits right after fProvider and is skipped
// during navigation when the chosen provider needs no key (or one is
// already configured).
const (
	fTargetType = iota
	fTargetOrLab
	fMode
	fProvider
	fAPIKey
	fSwarm
	fActive
	fDash
	fLaunch
	fCount
)

type launchModel struct {
	ti            textinput.Model
	tiKey         textinput.Model
	tType         int // 0 = custom URL, 1 = bundled lab
	labs          []string
	labIdx        int
	modes         []string
	modeIdx       int
	providers     []string
	provIdx       int
	swarm         bool
	active        bool
	dash          bool
	keyConfigured bool
	focus         int
	launched      bool
	err           string
}

func indexOf(ss []string, v string) int {
	for i, s := range ss {
		if s == v {
			return i
		}
	}
	return -1
}

func newLaunchModel(providers []string, def LaunchConfig) launchModel {
	ti := textinput.New()
	ti.Placeholder = "http://localhost:8888"
	ti.SetValue(def.Target)
	ti.CharLimit = 240
	ti.Width = 46
	ti.Prompt = ""
	ti.Focus()

	tiKey := textinput.New()
	tiKey.Placeholder = "paste key (hidden)"
	tiKey.CharLimit = 400
	tiKey.Width = 46
	tiKey.Prompt = ""
	tiKey.EchoMode = textinput.EchoPassword
	tiKey.EchoCharacter = '•'

	if len(providers) == 0 {
		providers = []string{"together", "claude", "openai", "gemini", "ollama", "lmstudio", "orcarouter"}
	}
	modes := []string{"manual", "bugbounty", "ctf"}
	labs := []string{"crapi", "juiceshop", "vampi", "dvga"}
	mi := indexOf(modes, def.Mode)
	if mi < 0 {
		mi = 0
	}
	pi := indexOf(providers, def.Provider)
	if pi < 0 {
		pi = 0
	}
	return launchModel{
		ti: ti, tiKey: tiKey, tType: 0, labs: labs, labIdx: 0, modes: modes, modeIdx: mi,
		providers: providers, provIdx: pi, swarm: def.Swarm, active: def.ActiveScan, dash: def.Dashboard,
		keyConfigured: def.KeyConfigured, focus: 0,
	}
}

func (m launchModel) Init() tea.Cmd { return textinput.Blink }

// keyFieldActive reports whether the API-key field should be shown and
// focusable: the selected provider needs a key and none is configured yet.
func (m launchModel) keyFieldActive() bool {
	return providerNeedsKeyUI(m.providers[m.provIdx]) && !m.keyConfigured
}

func (m launchModel) editingText() bool {
	return (m.focus == fTargetOrLab && m.tType == 0) || (m.focus == fAPIKey && m.keyFieldActive())
}

func (m *launchModel) refocus() {
	m.ti.Blur()
	m.tiKey.Blur()
	switch {
	case m.focus == fTargetOrLab && m.tType == 0:
		m.ti.Focus()
	case m.focus == fAPIKey && m.keyFieldActive():
		m.tiKey.Focus()
	}
}

func (m *launchModel) move(d int) {
	for i := 0; i < fCount; i++ {
		m.focus = (m.focus + d + fCount) % fCount
		if m.focus == fAPIKey && !m.keyFieldActive() {
			continue // skip the hidden key field
		}
		break
	}
	m.refocus()
}

func (m *launchModel) adjust(d int) {
	switch m.focus {
	case fTargetType:
		m.tType = (m.tType + 1) % 2
		m.refocus()
	case fTargetOrLab:
		if m.tType == 1 {
			m.labIdx = (m.labIdx + d + len(m.labs)) % len(m.labs)
		}
	case fMode:
		m.modeIdx = (m.modeIdx + d + len(m.modes)) % len(m.modes)
	case fProvider:
		m.provIdx = (m.provIdx + d + len(m.providers)) % len(m.providers)
		m.refocus() // key field may appear/disappear with the new provider
	case fSwarm:
		m.swarm = !m.swarm
	case fActive:
		m.active = !m.active
	case fDash:
		m.dash = !m.dash
	}
}

func (m launchModel) updateActiveInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if m.focus == fAPIKey {
		m.tiKey, cmd = m.tiKey.Update(msg)
	} else {
		m.ti, cmd = m.ti.Update(msg)
	}
	return m, cmd
}

func (m launchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "tab", "down":
			m.move(1)
			return m, nil
		case "shift+tab", "up":
			m.move(-1)
			return m, nil
		case "enter":
			if m.tType == 0 && strings.TrimSpace(m.ti.Value()) == "" {
				m.err = "enter a target URL first"
				m.focus = fTargetOrLab
				m.refocus()
				return m, nil
			}
			if m.keyFieldActive() && strings.TrimSpace(m.tiKey.Value()) == "" {
				m.err = "paste your " + m.providers[m.provIdx] + " API key (or pick a local provider like ollama)"
				m.focus = fAPIKey
				m.refocus()
				return m, nil
			}
			m.launched = true
			return m, tea.Quit
		}
		// While editing a text field, route printable keys / left-right /
		// space to that field so the user can type freely.
		if m.editingText() {
			return m.updateActiveInput(msg)
		}
		switch key.String() {
		case "left":
			m.adjust(-1)
			return m, nil
		case "right":
			m.adjust(1)
			return m, nil
		case " ":
			if m.focus >= fSwarm && m.focus <= fDash {
				m.adjust(1)
			}
			return m, nil
		}
	}
	return m, nil
}

func toggle(on bool) string {
	if on {
		return lsBrand.Render("● on")
	}
	return lsDim.Render("○ off")
}

func (m launchModel) sel(options []string, idx int) string {
	return lsDim.Render("‹ ") + lsVal.Render(options[idx]) + lsDim.Render(" ›")
}

func (m launchModel) View() string {
	row := func(idx int, label, val string) string {
		cursor := "  "
		lbl := lsLabel.Render(label)
		if m.focus == idx {
			cursor = lsBrand.Render("▸ ")
			lbl = lsBrand.Render(label)
		}
		return cursor + padRight(lbl, 22) + val
	}

	var b strings.Builder
	b.WriteString(lsBrand.Render("◢ PENTEST SWARM") + lsDim.Render("  //  LAUNCH") + "\n")
	b.WriteString(lsDim.Render("autonomous swarm · pick a target and go") + "\n")
	b.WriteString(lsRule.Render(strings.Repeat("─", 52)) + "\n")

	// Target
	b.WriteString(row(fTargetType, "Target type", m.sel([]string{"custom URL", "bundled lab"}, m.tType)) + "\n")
	if m.tType == 0 {
		field := m.ti.View()
		if m.focus != fTargetOrLab {
			field = lsVal.Render(orPlaceholder(m.ti.Value(), "http://localhost:8888"))
		}
		b.WriteString(row(fTargetOrLab, "Target URL", field) + "\n")
	} else {
		b.WriteString(row(fTargetOrLab, "Lab target", m.sel(m.labs, m.labIdx)) + "\n")
	}
	b.WriteString(row(fMode, "Scan mode", m.sel(m.modes, m.modeIdx)) + "\n")

	// Provider + its one-line description, and (when needed) a key field.
	prov := m.providers[m.provIdx]
	b.WriteString(row(fProvider, "AI provider", m.sel(m.providers, m.provIdx)) + "\n")
	if d := providerDesc(prov); d != "" {
		b.WriteString("    " + lsDim.Render(d) + "\n")
	}
	switch {
	case m.keyFieldActive():
		field := m.tiKey.View()
		if m.focus != fAPIKey {
			field = lsVal.Render(orPlaceholder(maskLen(m.tiKey.Value()), "paste key (hidden)"))
		}
		b.WriteString(row(fAPIKey, "API key", field) + "\n")
	case providerNeedsKeyUI(prov) && m.keyConfigured:
		b.WriteString("    " + lsDim.Render("using your configured API key") + "\n")
	}

	// Toggles
	b.WriteString(row(fSwarm, "Swarm engine", toggle(m.swarm)) + "\n")
	b.WriteString(row(fActive, "Active scan", toggle(m.active)) + "\n")
	b.WriteString(row(fDash, "Live dashboard", toggle(m.dash)) + "\n")
	b.WriteString(lsRule.Render(strings.Repeat("─", 52)) + "\n")

	launch := "  " + lsDim.Render("▶ LAUNCH ATTACK")
	if m.focus == fLaunch {
		launch = lsBrand.Render("▸ ▶ LAUNCH ATTACK")
	}
	b.WriteString(launch + "\n")
	if m.err != "" {
		b.WriteString("\n" + lsErr.Render("✕ "+m.err) + "\n")
	}
	b.WriteString("\n" + lsDim.Render("↑/↓ move · ←/→ change · space toggle · enter launch · esc cancel"))
	return lsBox.Render(b.String()) + "\n"
}

func padRight(s string, n int) string {
	// lipgloss-rendered strings carry ANSI; pad by visible width.
	w := lipgloss.Width(s)
	if w >= n {
		return s + "  "
	}
	return s + strings.Repeat(" ", n-w)
}

func orPlaceholder(v, ph string) string {
	if strings.TrimSpace(v) == "" {
		return lsDim.Render(ph)
	}
	return v
}

// maskLen renders a key as bullets so a blurred key field still shows that
// something was entered, without revealing it.
func maskLen(v string) string {
	if v == "" {
		return ""
	}
	n := len(v)
	if n > 24 {
		n = 24
	}
	return strings.Repeat("•", n)
}

// RunLauncher shows the interactive launcher and returns the chosen config.
// The bool is false if the user cancelled (esc / ctrl-c).
func RunLauncher(providers []string, def LaunchConfig) (LaunchConfig, bool, error) {
	m := newLaunchModel(providers, def)
	res, err := tea.NewProgram(m).Run()
	if err != nil {
		return LaunchConfig{}, false, err
	}
	fm, ok := res.(launchModel)
	if !ok || !fm.launched {
		return LaunchConfig{}, false, nil
	}
	prov := fm.providers[fm.provIdx]
	apiKey := ""
	if providerNeedsKeyUI(prov) {
		apiKey = strings.TrimSpace(fm.tiKey.Value())
	}
	return LaunchConfig{
		IsLab:      fm.tType == 1,
		Lab:        fm.labs[fm.labIdx],
		Target:     strings.TrimSpace(fm.ti.Value()),
		Mode:       fm.modes[fm.modeIdx],
		Provider:   prov,
		Swarm:      fm.swarm,
		ActiveScan: fm.active,
		Dashboard:  fm.dash,
		APIKey:     apiKey,
	}, true, nil
}
