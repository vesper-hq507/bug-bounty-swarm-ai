package cli

import (
	"context"
	"sync/atomic"

	"github.com/Armur-Ai/Pentest-Swarm-AI/cli/ui"
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
	exitCode *int,
) error {
	model := ui.NewModel("live", target, objective)
	prog := tea.NewProgram(model, tea.WithAltScreen())

	var findings int64
	onEvent := func(e pipeline.CampaignEvent) {
		if e.EventType == pipeline.EventFindingDiscovered {
			atomic.AddInt64(&findings, 1)
		}
		prog.Send(ui.EventMsg(e))
	}

	go func() {
		err := run(ctx, cc, onEvent)
		// Tell the TUI the run finished; it switches to the "complete" state
		// and waits for the user to quit so they can read the final board.
		prog.Send(ui.DoneMsg{Err: err})
	}()

	if _, err := prog.Run(); err != nil {
		cancel()
		return err
	}
	// The user quit (or quit after completion); make sure the swarm goroutine
	// is torn down if it's still running.
	cancel()

	if atomic.LoadInt64(&findings) > 0 {
		*exitCode = 1
	}
	return nil
}
