package cli

import (
	"context"
	"sync/atomic"

	"github.com/Armur-Ai/Pentest-Swarm-AI/cli/ui"
	livedash "github.com/Armur-Ai/Pentest-Swarm-AI/internal/dashboard"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	tea "github.com/charmbracelet/bubbletea"
)

// runCampaignTUI runs a campaign with the full-screen Bubble Tea dashboard as
// the live view. The swarm runs in a goroutine and streams events into the
// program via Send; the TUI owns the terminal until the user quits (q / Ctrl-C
// / s). It is the real-event wiring the old `campaign watch` stub never had.
//
// cancel stops the swarm if the user quits mid-run. exitCode is set to 1 when
// the run surfaced findings, matching the scriptable exit-code contract of the
// non-TUI path.
func runCampaignTUI(
	ctx context.Context,
	cancel context.CancelFunc,
	run func(context.Context, engine.CampaignConfig, engine.EventCallback) error,
	cc engine.CampaignConfig,
	target, objective string,
	dash *livedash.Server,
	exitCode *int,
) error {
	var anyFindings int64
	// Loop so the operator can restart the campaign with the same config by
	// pressing 'r' after a run ends — each pass is a fresh swarm run on a fresh
	// cancelable context.
	for attempt := 0; ; attempt++ {
		runCtx, runCancel := context.WithCancel(ctx)

		model := ui.NewModel("live", target, objective)
		// Let the spend meter fill toward the real per-run cap (0 = no cap).
		model.BudgetUSD = cc.MaxCostUSD
		if dash != nil {
			model.DashboardURL = dash.URL()
		}
		prog := tea.NewProgram(model, tea.WithAltScreen())

		var findings int64
		onEvent := func(e pipeline.CampaignEvent) {
			if e.EventType == pipeline.EventFindingDiscovered {
				atomic.AddInt64(&findings, 1)
			}
			prog.Send(ui.EventMsg(e))
			if dash != nil {
				publishToDashboard(dash, e)
			}
		}

		go func() {
			err := run(runCtx, cc, onEvent)
			if dash != nil {
				dash.PublishStatus("complete")
			}
			prog.Send(ui.DoneMsg{Err: err})
		}()

		res, err := prog.Run()
		runCancel() // tear down this pass's swarm goroutine
		atomic.AddInt64(&anyFindings, atomic.LoadInt64(&findings))
		if err != nil {
			if dash != nil {
				dash.Stop()
			}
			cancel()
			return err
		}
		// Restart requested? Re-run with the same config; otherwise we're done.
		if fm, ok := res.(ui.Model); ok && fm.RestartRequested() {
			continue
		}
		break
	}

	cancel()
	if dash != nil {
		dash.Stop()
	}
	if atomic.LoadInt64(&anyFindings) > 0 {
		*exitCode = 1
	}
	return nil
}
