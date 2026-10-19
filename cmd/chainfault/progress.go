package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/its-hixye/chainfault/internal/gitutil"
	"github.com/its-hixye/chainfault/internal/scanner"
)

// spinnerFrames is the braille spinner the wait screen advances while a tool is
// still running (CHAINFAULT_DOC.md §14). One frame is drawn per spinnerInterval.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerInterval is how often the spinner advances: about ten times a second,
// which reads as smooth without wasting CPU.
const spinnerInterval = 100 * time.Millisecond

// progress draws the live wait screen of CHAINFAULT_DOC.md §14: one line per
// tool that updates in place, with five states — waiting (empty circle),
// running (a spinner that animates), done (green check), interrupted (a dim
// dash, when the user cancels the scan) and failed (red mark).
//
// The spinner only animates when stdout is an interactive terminal. When the
// output is a pipe, a file or CI, every line is printed once as plain text with
// no escape codes and nothing ever loops.
//
// Everything else the tools print is hidden — their own chatter only surfaces
// when a tool fails, and then it travels in the failed tool's reason line.
type progress struct {
	live bool // stdout is an interactive terminal: animate and repaint in place
	out  io.Writer

	mu      sync.Mutex
	names   []string // draw order
	state   map[string]*toolState
	note    map[string]string // extra text shown next to a step
	printed map[string]bool   // non-interactive streams: already printed
	drawn   int
	active  bool
	frame   int // spinner frame index, advanced by the ticker

	stopCh   chan struct{} // closed to stop the animation goroutine
	animDone chan struct{} // closed when the animation goroutine has exited
	wg       sync.WaitGroup
}

type toolState struct {
	started  bool
	ok       bool
	finished bool
	// interrupted marks a row that was still running when the user cancelled
	// the scan. It renders as a neutral "interrupted", never as a failure.
	interrupted bool
	duration    time.Duration
	startedAt   time.Time
}

// newProgress builds the wait screen. interactive must be true only when stdout
// is a terminal (see isTerminal): that single flag decides animation versus
// plain lines.
func newProgress(interactive bool) *progress {
	return &progress{
		live:    interactive,
		out:     os.Stdout,
		state:   map[string]*toolState{},
		note:    map[string]string{},
		printed: map[string]bool{},
	}
}

// add registers a tool in the waiting state (empty circle) without starting it.
func (p *progress) add(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.touchLocked(name)
	p.active = true
	p.drawLocked()
}

// step prints a single status line while the scan is being prepared.
func (p *progress) step(name, text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.touchLocked(name)
	p.state[name].started = true
	p.note[name] = text
	p.active = true
	p.ensureAnimationLocked()
	p.drawLocked()
}

// cloneStep registers the Cloning row for a remote URL. A local path is opened
// in place, so showing "Cloning" there would be misleading; the plain output
// never showed this step either.
func (p *progress) cloneStep(target string) {
	if !p.live || !gitutil.IsURL(target) {
		return
	}
	p.step("Cloning", "cloning "+target)
}

// cloneDone marks the Cloning row finished once the clone has completed, so it
// stops spinning and shows how long the download took.
func (p *progress) cloneDone() {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.state["Cloning"]
	if st == nil || st.finished {
		return
	}
	st.started = true
	st.ok = true
	st.finished = true
	st.duration = time.Since(st.startedAt)
	p.drawLocked()
}

// startScanner moves a tool from waiting to running and starts the animation.
func (p *progress) startScanner(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.touchLocked(name)
	p.state[name].started = true
	p.active = true
	p.ensureAnimationLocked()
	p.drawLocked()
}

// scannerStatus is the callback scanner.Run uses to report progress.
func (p *progress) scannerStatus(s scanner.Status) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.touchLocked(s.Name)
	p.state[s.Name] = &toolState{started: true, ok: s.OK, finished: s.Finished, duration: s.Duration}
	p.drawLocked()
}

// interrupt marks every row that was started but had not succeeded as
// interrupted, because the user cancelled the scan. Rows that already finished
// are left alone: a tool that passed before Ctrl+C really did pass, and
// relabelling it would be a lie.
//
// Call it after the scan returns and before done, so the final frame keeps the
// interrupted wording. It is safe to call more than once and safe on a
// non-interactive stream, where it prints each cancelled row exactly once.
func (p *progress) interrupt() {
	p.mu.Lock()
	defer p.mu.Unlock()

	changed := false
	for _, name := range p.names {
		st := p.state[name]
		if st == nil || !st.started || st.ok || st.interrupted {
			continue
		}
		st.interrupted = true
		st.finished = true
		st.duration = time.Since(st.startedAt)
		changed = true
	}
	if !changed {
		return
	}
	p.drawLocked()
}

// done closes the wait screen, leaving the final state on screen and stopping
// the animation. It is safe to call more than once.
func (p *progress) done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = false
	p.stopAnimationLocked()
	p.drawLocked()
}

// clear wipes the wait screen so an error message is not mixed into it.
func (p *progress) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active = false
	p.stopAnimationLocked()
	if !p.live || p.drawn == 0 {
		p.drawn = 0
		return
	}
	fmt.Fprintf(p.out, "\x1b[%dA\x1b[0J", p.drawn)
	p.drawn = 0
}

// stopAnimation stops the spinner goroutine if it is running. It is safe to
// call more than once and safe to call after done or clear.
func (p *progress) stopAnimation() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopAnimationLocked()
}

func (p *progress) touchLocked(name string) {
	if _, ok := p.state[name]; ok {
		return
	}
	p.names = append(p.names, name)
	p.state[name] = &toolState{startedAt: time.Now()}
}

// ensureAnimationLocked starts the spinner goroutine, once, when the output is
// an interactive terminal.
func (p *progress) ensureAnimationLocked() {
	if !p.live || p.stopCh != nil {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	p.stopCh = stop
	p.animDone = done
	p.wg.Add(1)
	go p.animate(stop, done)
}

// animate advances the spinner every spinnerInterval until stop is closed. It
// exits on its own when the scan ends, on Ctrl+C or when the wait screen is
// cleared, so no goroutine is ever left behind.
func (p *progress) animate(stop, done chan struct{}) {
	defer p.wg.Done()
	defer close(done)

	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			p.mu.Lock()
			if p.active && p.live {
				p.frame++
				p.drawLocked()
			}
			p.mu.Unlock()
		}
	}
}

func (p *progress) stopAnimationLocked() {
	if p.stopCh == nil {
		return
	}
	close(p.stopCh)
	p.stopCh = nil
}

// drawLocked repaints every line. An interactive terminal is repainted in
// place; a redirected stream gets one plain line per finished step instead.
//
// Each row is a complete line ending in a newline. After a frame the cursor
// sits on the line below the block, so the next frame moves up the exact number
// of rows the previous frame printed and repaints them one by one, without ever
// moving up between rows.
func (p *progress) drawLocked() {
	if !p.live {
		for _, name := range p.names {
			st := p.state[name]
			if st == nil || !st.finished || p.printed[name] {
				continue
			}
			// A scanner that returns an error because the context was cancelled
			// reaches us as finished/not-OK before interrupt can relabel it.
			// Defer that row until the scan ends, so a redirected stream never
			// prints "failed" and then "interrupted" for the same tool.
			if !st.ok && !st.interrupted && p.active {
				continue
			}
			p.printed[name] = true
			fmt.Fprintln(p.out, p.plainLocked(name, st))
		}
		return
	}

	if p.drawn > 0 {
		fmt.Fprintf(p.out, "\x1b[%dA", p.drawn)
	}
	for _, name := range p.names {
		fmt.Fprintf(p.out, "\r\x1b[2K%s\n", p.renderLocked(name, p.state[name]))
	}
	p.drawn = len(p.names)
}

// renderLocked formats one line of the interactive wait screen: an empty circle
// while a tool is waiting, the spinner while it runs, a green check when it is
// done, a neutral dash when the scan was interrupted and a red mark when it
// failed.
//
// Tool names are printed in bright blue so the eye can find them immediately on
// a dark terminal, where the dim and green glyphs are easy to lose.
func (p *progress) renderLocked(name string, st *toolState) string {
	label := blueToolLabel(name)
	switch {
	case st == nil || !st.started:
		line := fmt.Sprintf("  \x1b[2m○\x1b[0m %s", label)
		if n := strings.TrimSpace(p.note[name]); n != "" {
			line += " " + n
		}
		return line
	case st.interrupted:
		return fmt.Sprintf("  \x1b[2m-\x1b[0m %s interrupted", label)
	case !st.finished:
		return fmt.Sprintf("  \x1b[33m%s\x1b[0m %s %s", p.spinnerFrame(), label, orDefault(p.note[name], "scanning..."))
	case st.ok:
		return fmt.Sprintf("  \x1b[32m✔\x1b[0m %s %s", label, formatDuration(st.duration))
	default:
		return fmt.Sprintf("  \x1b[31m✖\x1b[0m %s failed", label)
	}
}

// blueToolLabel pads a tool name to the label column and wraps it in the bright
// blue SGR code. Only the interactive wait screen calls it; plain output is
// never coloured, so it has to stay free of escape sequences.
func blueToolLabel(name string) string {
	return "\x1b[94m" + padRight(name, 12) + "\x1b[0m"
}

// spinnerFrame returns the current tick of the spinner.
func (p *progress) spinnerFrame() string {
	return spinnerFrames[p.frame%len(spinnerFrames)]
}

// plainLocked is the non-interactive variant, used when stdout is redirected.
// It never contains an escape sequence.
func (p *progress) plainLocked(name string, st *toolState) string {
	switch {
	case st == nil || !st.finished:
		return fmt.Sprintf("  ... %s %s", name, orDefault(p.note[name], "scanning..."))
	case st.interrupted:
		return fmt.Sprintf("  interrupted %s", name)
	case st.ok:
		return fmt.Sprintf("  ok  %s %s", name, formatDuration(st.duration))
	default:
		return fmt.Sprintf("  ERR %s failed", name)
	}
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// padRight pads s with spaces to width n, counting runes.
func padRight(s string, n int) string {
	if r := []rune(s); len(r) < n {
		return s + strings.Repeat(" ", n-len(r))
	}
	return s
}
