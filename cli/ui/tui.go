package ui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles — hero palette (see banner.go) so the live campaign TUI matches the
// README demo GIF: amber pheromone accent, agent purple, execute-green, cyan.
var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(hAmber).Padding(0, 1)

	dimStyle = lipgloss.NewStyle().Foreground(hFaint)

	agentActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(hAmber).
				Padding(0, 1).
				Width(40)

	agentIdleStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(hFaint).
			Padding(0, 1).
			Width(40)

	findingCritical = lipgloss.NewStyle().Foreground(hRed).Bold(true)
	findingHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("#F97316")).Bold(true)
	findingMedium   = lipgloss.NewStyle().Foreground(hAmber)
	findingLow      = lipgloss.NewStyle().Foreground(hGreen)

	phaseActive  = lipgloss.NewStyle().Background(hAmber).Foreground(hVoid).Padding(0, 1)
	phaseDone    = lipgloss.NewStyle().Background(hGreen).Foreground(hVoid).Padding(0, 1)
	phasePending = lipgloss.NewStyle().Foreground(hFaint).Padding(0, 1)

	footerStyle = lipgloss.NewStyle().Foreground(hFaint).Padding(0, 1)
)

// EventMsg delivers a campaign event to the TUI.
type EventMsg pipeline.CampaignEvent

// TickMsg triggers periodic UI updates.
type TickMsg time.Time

// Model is the bubbletea model for the campaign watch TUI.
type Model struct {
	// Campaign info
	campaignID string
	target     string
	objective  string
	startTime  time.Time

	// Agent status
	agents map[string]AgentStatus

	// Events log
	events   []pipeline.CampaignEvent
	viewport viewport.Model

	// Findings
	findings    []FindingDisplay
	severityMap map[pipeline.Severity]int

	// Phase tracking
	currentPhase string
	phases       []PhaseInfo

	// UI
	spinner spinner.Model
	width   int
	height  int
	// DashboardURL, when set, is the live web dashboard running in parallel;
	// shown in the footer so the user knows the browser view is available.
	DashboardURL string
	quitting     bool
	done         bool
	doneErr      error
}

// DoneMsg tells the TUI the campaign finished (the swarm run returned). The
// view switches to a "complete — press q" state; err is non-nil if the run
// failed.
type DoneMsg struct{ Err error }

// AgentStatus tracks an agent's display state.
type AgentStatus struct {
	Name   string
	Status string // idle, active, complete, error
	Detail string
}

// FindingDisplay is a finding formatted for display.
type FindingDisplay struct {
	Severity pipeline.Severity
	Title    string
	Target   string
}

// PhaseInfo tracks phase progress.
type PhaseInfo struct {
	Name   string
	Status string // pending, active, done
}

// NewModel creates the TUI model.
func NewModel(campaignID, target, objective string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(hAmber)

	vp := viewport.New(80, 20)

	return Model{
		campaignID: campaignID,
		target:     target,
		objective:  objective,
		startTime:  time.Now(),
		agents: map[string]AgentStatus{
			"orchestrator": {Name: "Orchestrator", Status: "active", Detail: "Initializing..."},
			"recon":        {Name: "Recon Agent", Status: "idle", Detail: "Waiting"},
			"classifier":   {Name: "Classifier", Status: "idle", Detail: "Waiting"},
			"exploit":      {Name: "Exploit Agent", Status: "idle", Detail: "Waiting"},
			"report":       {Name: "Report Agent", Status: "idle", Detail: "Waiting"},
		},
		severityMap: make(map[pipeline.Severity]int),
		phases: []PhaseInfo{
			{Name: "Recon", Status: "pending"},
			{Name: "Classify", Status: "pending"},
			{Name: "Plan", Status: "pending"},
			{Name: "Execute", Status: "pending"},
			{Name: "Report", Status: "pending"},
		},
		currentPhase: "initializing",
		spinner:      s,
		viewport:     vp,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "s":
			// Emergency stop
			m.quitting = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = msg.Height - 20

	case EventMsg:
		event := pipeline.CampaignEvent(msg)
		m.events = append(m.events, event)
		m.handleEvent(event)
		m.updateViewport()

	case DoneMsg:
		m.done = true
		m.doneErr = msg.Err
		for id, a := range m.agents {
			if a.Status == "active" {
				a.Status = "complete"
				m.agents[id] = a
			}
		}
		for i := range m.phases {
			m.phases[i].Status = "done"
		}

	case TickMsg:
		cmds = append(cmds, tickCmd())

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) handleEvent(event pipeline.CampaignEvent) {
	// Update agent status based on event
	switch event.EventType {
	case pipeline.EventStateChange:
		if strings.Contains(event.Detail, "recon") {
			m.setPhase("Recon")
			m.agents["recon"] = AgentStatus{Name: "Recon Agent", Status: "active", Detail: "Scanning..."}
		} else if strings.Contains(event.Detail, "classif") {
			m.setPhase("Classify")
			m.agents["recon"] = AgentStatus{Name: "Recon Agent", Status: "complete", Detail: "Done"}
			m.agents["classifier"] = AgentStatus{Name: "Classifier", Status: "active", Detail: "Classifying..."}
		} else if strings.Contains(event.Detail, "plan") {
			m.setPhase("Plan")
			m.agents["classifier"] = AgentStatus{Name: "Classifier", Status: "complete", Detail: "Done"}
			m.agents["exploit"] = AgentStatus{Name: "Exploit Agent", Status: "active", Detail: "Building chains..."}
		} else if strings.Contains(event.Detail, "execut") {
			m.setPhase("Execute")
		} else if strings.Contains(event.Detail, "report") {
			m.setPhase("Report")
			m.agents["exploit"] = AgentStatus{Name: "Exploit Agent", Status: "complete", Detail: "Done"}
			m.agents["report"] = AgentStatus{Name: "Report Agent", Status: "active", Detail: "Writing report..."}
		} else if strings.Contains(event.Detail, "complete") {
			m.agents["report"] = AgentStatus{Name: "Report Agent", Status: "complete", Detail: "Done"}
		}

	case pipeline.EventFindingDiscovered:
		// Prefer the structured finding payload the swarm streams
		// ({"severity","title",...}); fall back to text if it's absent.
		title := event.Detail
		var sev pipeline.Severity = pipeline.SeverityMedium
		if len(event.Data) > 0 {
			var d struct {
				Severity string `json:"severity"`
				Title    string `json:"title"`
			}
			if json.Unmarshal(event.Data, &d) == nil {
				if d.Title != "" {
					title = d.Title
				}
				if d.Severity != "" {
					sev = pipeline.Severity(strings.ToLower(d.Severity))
				}
			}
		} else {
			switch {
			case strings.Contains(event.Detail, "CRITICAL"):
				sev = pipeline.SeverityCritical
			case strings.Contains(event.Detail, "HIGH"):
				sev = pipeline.SeverityHigh
			case strings.Contains(event.Detail, "LOW"):
				sev = pipeline.SeverityLow
			}
		}
		m.severityMap[sev]++
		m.findings = append(m.findings, FindingDisplay{Severity: sev, Title: title})

	case pipeline.EventToolResult:
		if a, ok := m.agents[event.AgentName]; ok {
			a.Status = "active"
			a.Detail = truncateStr(event.Detail, 50)
			m.agents[event.AgentName] = a
		}

	case pipeline.EventError:
		if a, ok := m.agents[event.AgentName]; ok {
			a.Status = "error"
			a.Detail = truncateStr(event.Detail, 50)
			m.agents[event.AgentName] = a
		}

	case pipeline.EventThought:
		if event.AgentName != "" {
			if a, ok := m.agents[event.AgentName]; ok {
				a.Detail = truncateStr(event.Detail, 50)
				m.agents[event.AgentName] = a
			}
		}

	case pipeline.EventToolCall:
		if event.AgentName != "" {
			if a, ok := m.agents[event.AgentName]; ok {
				a.Status = "active"
				a.Detail = truncateStr(event.Detail, 50)
				m.agents[event.AgentName] = a
			}
		}
	}
}

func (m *Model) setPhase(name string) {
	for i := range m.phases {
		if m.phases[i].Name == name {
			m.phases[i].Status = "active"
			m.currentPhase = name
		} else if m.phases[i].Status == "active" {
			m.phases[i].Status = "done"
		}
	}
}

func (m *Model) updateViewport() {
	var lines []string
	for _, e := range m.events {
		ts := e.Timestamp.Format("15:04:05")
		prefix := dimStyle.Render(ts)

		switch e.EventType {
		case pipeline.EventThought:
			lines = append(lines, fmt.Sprintf("%s [think] %s", prefix, e.Detail))
		case pipeline.EventToolCall:
			lines = append(lines, fmt.Sprintf("%s   [>>]  %s", prefix, e.Detail))
		case pipeline.EventToolResult:
			lines = append(lines, fmt.Sprintf("%s   [<<]  %s", prefix, e.Detail))
		case pipeline.EventFindingDiscovered:
			lines = append(lines, fmt.Sprintf("%s    [!]  %s", prefix, e.Detail))
		case pipeline.EventError:
			lines = append(lines, fmt.Sprintf("%s  [ERR]  %s", prefix, e.Detail))
		case pipeline.EventMilestone:
			lines = append(lines, fmt.Sprintf("%s [DONE]  %s", prefix, e.Detail))
		default:
			lines = append(lines, fmt.Sprintf("%s   [%s] %s", prefix, e.EventType, e.Detail))
		}
	}
	m.viewport.SetContent(strings.Join(lines, "\n"))
	m.viewport.GotoBottom()
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// Header — SWARM wordmark + campaign meta
	elapsed := time.Since(m.startTime).Round(time.Second)
	b.WriteString(SwarmWordmark(1) + "\n")
	b.WriteString(" " + stAmber.Render("PENTEST SWARM AI") + "   " +
		stInk.Render(m.target) + "   " + stMuted.Render(truncateStr(m.objective, 40)) +
		"   " + stFaint.Render(elapsed.String()) + "\n\n")

	// Phase progress bar + pips
	done := 0
	for _, p := range m.phases {
		if p.Status == "done" {
			done++
		}
	}
	b.WriteString(" " + stMuted.Render("progress ") + ProgressBar(done, len(m.phases), 26) +
		stMuted.Render(fmt.Sprintf("  %d/%d phases", done, len(m.phases))) + "\n")
	var phases []string
	for _, p := range m.phases {
		switch p.Status {
		case "done":
			phases = append(phases, phaseDone.Render(p.Name+" ✓"))
		case "active":
			phases = append(phases, phaseActive.Render(m.spinner.View()+" "+p.Name))
		default:
			phases = append(phases, phasePending.Render(p.Name))
		}
	}
	b.WriteString(" " + strings.Join(phases, stFaint.Render(" → ")) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", m.dividerWidth())) + "\n")

	// Architecture — the swarm topology, lit live by agent status
	states := map[string]string{
		"recon": m.agents["recon"].Status, "classifier": m.agents["classifier"].Status,
		"exploit": m.agents["exploit"].Status, "report": m.agents["report"].Status,
	}
	b.WriteString(" " + stCyan.Render("ARCHITECTURE") + stFaint.Render("  ── live swarm topology") + "\n")
	b.WriteString(LiveConstellation(states) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", m.dividerWidth())) + "\n")

	// Two columns: agents (left) + findings (right), sized to the terminal
	// so the layout stretches when the window grows. lipgloss.JoinHorizontal
	// aligns ANSI-styled blocks by visible width (a plain %-45s can't).
	colW := (m.dividerWidth() - 3) / 2
	if colW < 28 {
		colW = 28
	}
	left := lipgloss.NewStyle().Width(colW).Render(m.renderAgents(colW))
	right := lipgloss.NewStyle().Width(colW).Render(m.renderFindings(colW))
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right) + "\n")

	b.WriteString(dimStyle.Render(strings.Repeat("─", m.dividerWidth())) + "\n")

	// Event log
	b.WriteString(dimStyle.Render(" Event Log") + "\n")
	// Show last 8 events
	start := 0
	if len(m.events) > 8 {
		start = len(m.events) - 8
	}
	for _, e := range m.events[start:] {
		ts := dimStyle.Render(e.Timestamp.Format("15:04:05"))
		b.WriteString(fmt.Sprintf(" %s %s\n", ts, truncateStr(e.Detail, m.dividerWidth()-12)))
	}

	// Footer
	b.WriteString("\n")
	if m.DashboardURL != "" {
		b.WriteString(" " + stCyan.Render("web dashboard") + stFaint.Render(" → ") + stInk.Render(m.DashboardURL) + "\n")
	}
	if m.done {
		if m.doneErr != nil {
			b.WriteString(findingHigh.Render(" ✗ campaign failed: "+truncateStr(m.doneErr.Error(), 60)) + footerStyle.Render("   q:quit"))
		} else {
			b.WriteString(findingLow.Render(" ✓ campaign complete") + footerStyle.Render("   q:quit  ↑↓:scroll"))
		}
	} else {
		b.WriteString(footerStyle.Render(" q:quit  s:stop  ↑↓:scroll"))
	}

	return b.String()
}

// dividerWidth is the width for full-width rules and the two-column split:
// the live terminal width, floored so a tiny window doesn't collapse and
// defaulted before the first WindowSizeMsg arrives.
func (m Model) dividerWidth() int {
	w := m.width
	if w <= 0 {
		w = 72 // sensible default before the terminal reports its size
	}
	if w < 40 {
		w = 40
	}
	return w
}

func (m Model) renderAgents(colW int) string {
	// Box content width = column minus border (2) and the style's h-padding (2).
	boxW := colW - 4
	if boxW < 18 {
		boxW = 18
	}
	active := agentActiveStyle.Width(boxW)
	idle := agentIdleStyle.Width(boxW)

	var b strings.Builder
	b.WriteString(stCyan.Render(" Agents") + "\n")

	order := []string{"orchestrator", "recon", "classifier", "exploit", "report"}
	for _, name := range order {
		a := m.agents[name]
		style := idle
		statusIcon := "○"

		switch a.Status {
		case "active":
			style = active
			statusIcon = "●"
		case "complete":
			statusIcon = "✓"
		case "error":
			statusIcon = "✗"
		}

		content := fmt.Sprintf(" %s %s\n %s", statusIcon, a.Name, dimStyle.Render(truncateStr(a.Detail, boxW-1)))
		b.WriteString(style.Render(content) + "\n")
	}

	return b.String()
}

func (m Model) renderFindings(colW int) string {
	var b strings.Builder
	b.WriteString(stCyan.Render(" Findings") + "\n")

	// Severity distribution — horizontal bar chart
	c := m.severityMap[pipeline.SeverityCritical]
	h := m.severityMap[pipeline.SeverityHigh]
	med := m.severityMap[pipeline.SeverityMedium]
	l := m.severityMap[pipeline.SeverityLow]
	b.WriteString(SeverityBars(c, h, med, l) + "\n\n")

	// Recent findings — as many as the column can show titles for.
	titleW := colW - 4
	if titleW < 16 {
		titleW = 16
	}
	start := 0
	if len(m.findings) > 6 {
		start = len(m.findings) - 6
	}
	for _, f := range m.findings[start:] {
		var style lipgloss.Style
		switch f.Severity {
		case pipeline.SeverityCritical:
			style = findingCritical
		case pipeline.SeverityHigh:
			style = findingHigh
		case pipeline.SeverityMedium:
			style = findingMedium
		default:
			style = findingLow
		}
		b.WriteString(" " + style.Render("●") + " " + truncateStr(f.Title, titleW) + "\n")
	}

	if len(m.findings) == 0 {
		b.WriteString(dimStyle.Render(" No findings yet") + "\n")
	}

	return b.String()
}

// truncateStr shortens s to at most max runes (ellipsised), counting by rune
// so multibyte titles aren't cut mid-character.
func truncateStr(s string, max int) string {
	if max < 1 {
		max = 1
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
