package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/its-hixye/chainfault/internal/scanner"
)

// The wait screen has four states per tool line: waiting (empty circle),
// running (spinner), done (green check), interrupted (dim dash) and failed (red
// mark). This test reads the rendered lines directly so it needs no terminal.
func TestProgressStateGlyphs(t *testing.T) {
	p := newProgress(true)

	waiting := &toolState{}
	if got := p.renderLocked("gitleaks", waiting); !strings.Contains(got, "○") {
		t.Errorf("waiting line = %q, want an empty circle", got)
	}

	running := &toolState{started: true}
	got := p.renderLocked("gitleaks", running)
	if !strings.Contains(got, spinnerFrames[0]) {
		t.Errorf("running line = %q, want the first spinner frame %q", got, spinnerFrames[0])
	}

	done := &toolState{started: true, finished: true, ok: true, duration: 1500 * time.Millisecond}
	got = p.renderLocked("gitleaks", done)
	if !strings.Contains(got, "✔") || !strings.Contains(got, "1.5s") {
		t.Errorf("done line = %q, want a check mark and the elapsed time", got)
	}

	failed := &toolState{started: true, finished: true, ok: false}
	got = p.renderLocked("gitleaks", failed)
	if !strings.Contains(got, "✖") || !strings.Contains(got, "failed") {
		t.Errorf("failed line = %q, want a red mark and a failure note", got)
	}
}

// When stdout is not a terminal the wait screen must print plain text with no
// escape codes, and it must not loop.
func TestProgressPlainOutputHasNoEscapeCodes(t *testing.T) {
	out := captureOutput(t, func() {
		p := newProgress(false)
		p.startScanner("gitleaks")
		p.scannerStatus(scanner.Status{Name: "gitleaks", Finished: true, OK: true, Duration: 1500 * time.Millisecond})
		p.done()
	})

	if strings.Contains(out, "\x1b") {
		t.Errorf("non-terminal wait screen contains an escape sequence:\n%q", out)
	}
	if !strings.Contains(out, "gitleaks") {
		t.Errorf("non-terminal wait screen does not name the finished tool:\n%q", out)
	}
	if strings.Contains(out, spinnerFrames[0]) {
		t.Errorf("non-terminal wait screen drew a spinner frame:\n%q", out)
	}
}

// A non-terminal stream must never start the animation goroutine.
func TestProgressPlainModeStartsNoAnimation(t *testing.T) {
	captureOutput(t, func() {
		p := newProgress(false)
		p.startScanner("gitleaks")
		if p.animDone != nil {
			t.Error("plain output started an animation goroutine")
		}
		p.done()
	})
}

// The animation goroutine must stop when the scan ends, so nothing is left to
// leak and no escape sequence is written after the screen is closed.
func TestProgressTickerStops(t *testing.T) {
	var p *progress
	var animDone chan struct{}
	captureOutput(t, func() {
		p = newProgress(true)
		p.startScanner("gitleaks")
		animDone = p.animDone
		p.done()
	})

	if animDone == nil {
		t.Fatal("interactive wait screen started no animation goroutine")
	}
	select {
	case <-animDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the spinner goroutine did not stop after done")
	}

	// Closing the screen twice must be safe and leave nothing to stop.
	p.done()
	p.stopAnimation()
	if p.stopCh != nil {
		t.Error("stopAnimation left the stop channel open")
	}
}

// TestProgressLiveFramesRepaintInPlace drives the live wait screen by hand and
// replays its escape sequences through a tiny terminal model, so the test sees
// what a user would see rather than the raw byte stream.
func TestProgressLiveFramesRepaintInPlace(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("previous output one\nprevious output two\n")

	p := newProgress(true)
	p.out = &buf
	// A non-nil stop channel keeps ensureAnimationLocked from starting the
	// ticker: this test draws each frame itself so the byte stream is stable.
	p.stopCh = make(chan struct{})

	const target = "https://example.com/repo.git"
	p.cloneStep(target)
	p.add("gitleaks")
	p.add("trufflehog")
	p.cloneDone()
	p.startScanner("gitleaks")
	p.startScanner("trufflehog")

	// Several animated frames exercise the repaint path.
	for i := 0; i < 3; i++ {
		p.mu.Lock()
		p.frame++
		p.drawLocked()
		p.mu.Unlock()
	}

	p.scannerStatus(scanner.Status{Name: "gitleaks", Finished: true, OK: true, Duration: 1500 * time.Millisecond})
	p.scannerStatus(scanner.Status{Name: "trufflehog", Finished: true, OK: true, Duration: 900 * time.Millisecond})
	p.done()

	screen := replayScreen(t, buf.String())

	// (a) Output printed before the animation must still be untouched.
	if screen[0] != "previous output one" || screen[1] != "previous output two" {
		t.Fatalf("animation overwrote earlier output; screen = %q", screen)
	}

	var rows []string
	for _, line := range screen[2:] {
		if strings.TrimSpace(line) != "" {
			rows = append(rows, line)
		}
	}

	// (b) Exactly one row per tool, and nothing else, is visible at the end.
	if len(rows) != 3 {
		t.Fatalf("final screen has %d animation rows, want 3: %q", len(rows), rows)
	}
	for _, tool := range []string{"Cloning", "gitleaks", "trufflehog"} {
		count := 0
		for _, row := range rows {
			if strings.Contains(row, tool) {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s appears on %d rows, want exactly 1: %q", tool, count, rows)
		}
	}
	for _, row := range rows {
		if !strings.Contains(row, "✔") {
			t.Errorf("final row is not in a done state: %q", row)
		}
	}

	// (c) No spinner or waiting row may survive the final frame.
	for _, row := range rows {
		for _, glyph := range spinnerFrames {
			if strings.Contains(row, glyph) {
				t.Errorf("leftover spinner row: %q", row)
			}
		}
		if strings.Contains(row, "○") || strings.Contains(row, "scanning...") {
			t.Errorf("leftover waiting row: %q", row)
		}
	}
}

// A local path is opened in place, so the live screen must not invent a
// Cloning row that would spin forever.
func TestProgressLocalPathHasNoCloningRow(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(true)
	p.out = &buf
	p.stopCh = make(chan struct{})

	p.cloneStep("/tmp/some-local-repo")
	p.add("gitleaks")
	p.done()

	if strings.Contains(buf.String(), "Cloning") {
		t.Errorf("local path drew a Cloning row:\n%q", buf.String())
	}
}

// Tool names are the anchor of each row, so on a dark terminal they are printed
// in bright blue while the status glyphs keep their own colours.
func TestProgressLiveColorsToolNamesBlue(t *testing.T) {
	p := newProgress(true)

	states := map[string]*toolState{
		"Cloning":    {started: true, finished: true, ok: true},
		"gitleaks":   {started: true, finished: true, ok: true, duration: 1500 * time.Millisecond},
		"trufflehog": {started: true, finished: true, ok: true, duration: 900 * time.Millisecond},
	}
	for _, name := range []string{"Cloning", "gitleaks", "trufflehog"} {
		got := p.renderLocked(name, states[name])
		if !strings.Contains(got, "\x1b[94m"+padRight(name, 12)+"\x1b[0m") {
			t.Errorf("%s is not wrapped in the bright blue code: %q", name, got)
		}
	}

	// The running row carries the same blue name, next to the yellow spinner.
	running := p.renderLocked("gitleaks", &toolState{started: true})
	if !strings.Contains(running, "\x1b[94m"+padRight("gitleaks", 12)+"\x1b[0m") {
		t.Errorf("running row does not colour the tool name: %q", running)
	}
	if !strings.Contains(running, "\x1b[33m") {
		t.Errorf("running row lost its yellow spinner: %q", running)
	}

	// Status colours stay exactly as they were.
	ok := p.renderLocked("gitleaks", &toolState{started: true, finished: true, ok: true})
	if !strings.Contains(ok, "\x1b[32m✔\x1b[0m") {
		t.Errorf("done row lost its green check: %q", ok)
	}
	failed := p.renderLocked("gitleaks", &toolState{started: true, finished: true})
	if !strings.Contains(failed, "\x1b[31m✖\x1b[0m") {
		t.Errorf("failed row lost its red mark: %q", failed)
	}
}

// Redirected output must never be coloured, so the same names appear there as
// bare text.
func TestProgressPlainToolNamesHaveNoColor(t *testing.T) {
	out := captureOutput(t, func() {
		p := newProgress(false)
		p.add("gitleaks")
		p.add("trufflehog")
		p.scannerStatus(scanner.Status{Name: "gitleaks", Finished: true, OK: true, Duration: time.Second})
		p.scannerStatus(scanner.Status{Name: "trufflehog", Finished: true, OK: true, Duration: time.Second})
		p.done()
	})

	if strings.Contains(out, "\x1b[94m") {
		t.Errorf("non-terminal output contains the blue code:\n%q", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("non-terminal output contains an escape sequence:\n%q", out)
	}
	if !strings.Contains(out, "  ok  gitleaks") {
		t.Errorf("non-terminal output does not list the tool plainly:\n%q", out)
	}
}

// Interrupting the scan must relabel the rows that were still running, without
// touching the ones that already finished and without repainting in red.
func TestProgressInterruptedRowsRenderNeutral(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(true)
	p.out = &buf
	p.stopCh = make(chan struct{})

	p.cloneStep("https://example.com/repo.git")
	p.add("gitleaks")
	p.add("trufflehog")
	p.cloneDone()
	p.startScanner("gitleaks")
	p.startScanner("trufflehog")
	p.scannerStatus(scanner.Status{Name: "gitleaks", Finished: true, OK: true, Duration: 1500 * time.Millisecond})

	p.interrupt()
	p.done()

	rows := finalRows(t, buf.String())

	if len(rows) != 3 {
		t.Fatalf("final screen has %d rows, want 3: %q", len(rows), rows)
	}

	// The scanner that passed before the cancellation stays a green check.
	cloning := rowContaining(t, rows, "Cloning")
	if !strings.Contains(cloning, "✔") || strings.Contains(cloning, "interrupted") {
		t.Errorf("finished Cloning row was relabelled: %q", cloning)
	}
	passed := rowContaining(t, rows, "gitleaks")
	if !strings.Contains(passed, "✔") || !strings.Contains(passed, "1.5s") {
		t.Errorf("finished gitleaks row is no longer done: %q", passed)
	}
	if strings.Contains(passed, "interrupted") {
		t.Errorf("finished gitleaks row was marked interrupted: %q", passed)
	}

	// The one that was still running reads "interrupted", in no alarm colour.
	cancelled := rowContaining(t, rows, "trufflehog")
	if !strings.Contains(cancelled, "interrupted") {
		t.Errorf("cancelled row does not say interrupted: %q", cancelled)
	}
	for _, code := range []string{"\x1b[31m", "\x1b[32m", "\x1b[33m"} {
		if strings.Contains(cancelled, code) {
			t.Errorf("cancelled row is coloured %q: %q", code, cancelled)
		}
	}
	if strings.Contains(cancelled, "failed") || strings.Contains(cancelled, "✖") {
		t.Errorf("cancelled row is still drawn as failed: %q", cancelled)
	}
	for _, glyph := range spinnerFrames {
		if strings.Contains(cancelled, glyph) {
			t.Errorf("cancelled row is still spinning: %q", cancelled)
		}
	}

	// Interrupting twice changes nothing on screen.
	before := buf.String()
	p.interrupt()
	if buf.String() != before {
		t.Errorf("a repeated interrupt repainted the screen:\n%q", buf.String())
	}
}

// A failed row that was never interrupted still reads as failed: the renderer
// keys the wording off the interrupted flag, not off the scan having ended.
func TestProgressFailedRowWithoutInterruptStillFails(t *testing.T) {
	p := newProgress(true)

	got := p.renderLocked("gitleaks", &toolState{started: true, finished: true, ok: false})
	if !strings.Contains(got, "✖") || !strings.Contains(got, "failed") {
		t.Errorf("failed row = %q, want a red mark and a failure note", got)
	}
	if strings.Contains(got, "interrupted") {
		t.Errorf("a genuine failure was relabelled as interrupted: %q", got)
	}
}

// Redirected output reports the cancelled tools in plain text, without escape
// codes and without repeating a row.
func TestProgressPlainInterruptedOutput(t *testing.T) {
	out := captureOutput(t, func() {
		p := newProgress(false)
		p.add("gitleaks")
		p.add("trufflehog")
		p.startScanner("gitleaks")
		p.startScanner("trufflehog")
		p.scannerStatus(scanner.Status{Name: "gitleaks", Finished: true, OK: true, Duration: 1500 * time.Millisecond})
		p.interrupt()
		p.done()
	})

	if strings.Contains(out, "\x1b") {
		t.Errorf("non-terminal output contains an escape sequence:\n%q", out)
	}
	if !strings.Contains(out, "  interrupted trufflehog") {
		t.Errorf("non-terminal output does not report the cancelled tool:\n%q", out)
	}
	if !strings.Contains(out, "  ok  gitleaks 1.5s") {
		t.Errorf("non-terminal output lost the finished tool:\n%q", out)
	}
	if strings.Contains(out, "trufflehog failed") {
		t.Errorf("non-terminal output calls the cancelled tool failed:\n%q", out)
	}
	if n := strings.Count(out, "trufflehog"); n != 1 {
		t.Errorf("cancelled tool appears %d times, want exactly 1:\n%q", n, out)
	}
}

func TestProgressPlainCancelledScannerDoesNotPrintFailureFirst(t *testing.T) {
	var out bytes.Buffer
	p := newProgress(false)
	p.out = &out
	p.add("gitleaks")
	p.startScanner("gitleaks")

	// A context cancellation makes scanner.Run report a finished, not-OK row
	// before main gets a chance to call interrupt.
	p.scannerStatus(scanner.Status{
		Name:     "gitleaks",
		Finished: true,
		OK:       false,
		Duration: 2 * time.Second,
	})
	if strings.Contains(out.String(), "failed") {
		t.Fatalf("failed row printed before interrupt: %q", out.String())
	}

	p.interrupt()
	p.done()

	if strings.Contains(out.String(), "failed") {
		t.Errorf("cancelled scanner still reported as failed:\n%q", out.String())
	}
	if n := strings.Count(out.String(), "interrupted gitleaks"); n != 1 {
		t.Errorf("interrupted row printed %d times, want 1:\n%q", n, out.String())
	}
	if n := strings.Count(out.String(), "gitleaks"); n != 1 {
		t.Errorf("tool appears %d times, want exactly 1:\n%q", n, out.String())
	}
}

// finalRows replays a live byte stream and returns the non-empty lines left on
// screen, with every escape sequence removed, so a test can assert on what a
// user actually sees.
func finalRows(t *testing.T, raw string) []string {
	t.Helper()

	var rows []string
	for _, line := range replayScreen(t, raw) {
		clean := stripANSI(line)
		if strings.TrimSpace(clean) != "" {
			rows = append(rows, clean)
		}
	}
	return rows
}

// rowContaining returns the single row that mentions tool.
func rowContaining(t *testing.T, rows []string, tool string) string {
	t.Helper()

	var found []string
	for _, row := range rows {
		if strings.Contains(row, tool) {
			found = append(found, row)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s appears on %d rows, want exactly 1: %q", tool, len(found), rows)
	}
	return found[0]
}

// stripANSI removes SGR escape sequences so a rendered line can be matched as
// text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != 0x1b || i+1 >= len(s) || s[i+1] != '[' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i + 2
		for j < len(s) && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
			j++
		}
		i = j + 1
	}
	return b.String()
}

// replayScreen applies the escape sequences the wait screen emits to a simple
// line buffer: cursor up, clear line, carriage return and newline. Everything
// else (the SGR colour codes) is invisible and ignored.
func replayScreen(t *testing.T, raw string) []string {
	t.Helper()

	lines := []string{""}
	row := 0
	for i := 0; i < len(raw); {
		switch raw[i] {
		case '\r':
			i++
		case '\n':
			row++
			if row == len(lines) {
				lines = append(lines, "")
			}
			i++
		case 0x1b:
			if i+1 >= len(raw) || raw[i+1] != '[' {
				i++
				continue
			}
			j := i + 2
			for j < len(raw) && (raw[j] < 'A' || raw[j] > 'Z') && (raw[j] < 'a' || raw[j] > 'z') {
				j++
			}
			if j >= len(raw) {
				t.Fatalf("unterminated escape sequence at byte %d", i)
			}
			switch raw[j] {
			case 'A':
				n := 1
				if param := raw[i+2 : j]; param != "" {
					var err error
					n, err = strconv.Atoi(param)
					if err != nil {
						t.Fatalf("bad cursor-up parameter %q", param)
					}
				}
				row -= n
				if row < 0 {
					t.Fatalf("cursor moved above the start of the screen: %q", raw)
				}
			case 'K':
				lines[row] = ""
			}
			i = j + 1
		default:
			j := i
			for j < len(raw) && raw[j] != '\r' && raw[j] != '\n' && raw[j] != 0x1b {
				j++
			}
			lines[row] += raw[i:j]
			i = j
		}
	}
	return lines
}
