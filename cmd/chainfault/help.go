package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// scanOption is the single definition of one scan option: its flag name, the
// value shown after it, its one-line description, and an optional explanatory
// note printed on the following line. Both the root help and `scan --help` are
// rendered from this list, so an option can never exist in one and be missing
// from the other.
type scanOption struct {
	Flag        string
	Value       string
	Description string
	Note        string
}

var scanOptions = []scanOption{
	{
		Flag:        "depth",
		Value:       "=N|full",
		Description: "how many commits to scan (default: full)",
		Note:        "Scans the last N commits; a secret deleted inside those commits may still be reported.",
	},
	{
		Flag:        "html",
		Description: "also write an HTML report",
	},
	{
		Flag:        "output",
		Value:       "=<file>",
		Description: "where to write the HTML report (requires --html, must end in .html)",
	},
	{
		Flag:        "verify",
		Description: "let TruffleHog check the discovered secrets against real services",
	},
	{
		Flag:        "reveal",
		Description: "print full secrets instead of masking them",
	},
}

const (
	helpHeadingColor = "\x1b[33m"
	helpOptionColor  = "\x1b[94m"
	helpColorReset   = "\x1b[0m"

	// helpLineLimit is the maximum number of plain-text columns allowed in the
	// help output. Descriptions and notes are wrapped to fit; the ANSI color
	// codes add no visible width because they are only ever emitted around the
	// option token or a section heading.
	helpLineLimit = 90
)

// usage renders the process-wide help. It is used for `chainfault --help` and
// for the no-argument and unknown-command errors.
func usage(w io.Writer) {
	writeUsage(w, false, colorEnabled(w))
}

// scanUsage renders `chainfault scan --help`.
func scanUsage(w io.Writer) {
	writeUsage(w, true, colorEnabled(w))
}

// writeUsage is the common renderer. scanOnly trims the commands section; color
// is passed explicitly so tests can prove the plain output stays byte-for-byte
// free of escape codes.
func writeUsage(w io.Writer, scanOnly, color bool) {
	heading := func(s string) string {
		if color {
			return helpHeadingColor + s + helpColorReset
		}
		return s
	}

	fmt.Fprintln(w, "chainfault — find leaked secrets across your whole git history")
	fmt.Fprintln(w)
	fmt.Fprintln(w, heading("Usage:"))
	if scanOnly {
		fmt.Fprintln(w, "  chainfault scan <path-or-url> [options]")
	} else {
		fmt.Fprintln(w, "  chainfault scan <path-or-url> [options]")
		fmt.Fprintln(w, "  chainfault doctor")
		fmt.Fprintln(w, "  chainfault version")
	}

	if !scanOnly {
		fmt.Fprintln(w)
		fmt.Fprintln(w, heading("Commands:"))
		fmt.Fprintln(w, "  scan      scan a repository for leaked secrets")
		fmt.Fprintln(w, "  doctor    show where the helper tools are installed")
		fmt.Fprintln(w, "  version   print the Chainfault version")
	}

	// Width of the widest "--flag=value" cell, in runes, so the descriptions
	// line up even though the flag itself may be colored.
	width := 0
	for _, opt := range scanOptions {
		if n := len([]rune("--" + opt.Flag + opt.Value)); n > width {
			width = n
		}
	}

	// Descriptions and notes start in the same column. Wrapping is measured
	// from the plain text, so colored output obeys the same line limit.
	descIndent := 2 + width + 2
	indent := strings.Repeat(" ", descIndent)
	writeDescription := func(text string) {
		for _, line := range wrapText(text, helpLineLimit-descIndent) {
			fmt.Fprintf(w, "%s%s\n", indent, line)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, heading("Scan options:"))
	for _, opt := range scanOptions {
		token := "--" + opt.Flag + opt.Value
		shown := token
		if color {
			// The whole token is blue, including any "=value" suffix.
			shown = helpOptionColor + token + helpColorReset
		}
		padding := strings.Repeat(" ", width-len([]rune(token)))
		descLines := wrapText(opt.Description, helpLineLimit-descIndent)
		fmt.Fprintf(w, "  %s%s  %s\n", shown, padding, descLines[0])
		for _, line := range descLines[1:] {
			fmt.Fprintf(w, "%s%s\n", indent, line)
		}
		if opt.Note != "" {
			writeDescription(opt.Note)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, heading("Exit codes:"))
	fmt.Fprintln(w, "  0  both scanners finished, no secrets")
	fmt.Fprintln(w, "  1  both scanners finished, secrets found")
	fmt.Fprintln(w, "  2  a scanner failed, the scan was interrupted, or the input was invalid")
}

// wrapText breaks text into lines of at most width runes, splitting on spaces.
// The wording is preserved exactly; only the spaces at line breaks change.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, 2)
	current := words[0]
	for _, word := range words[1:] {
		if len([]rune(current))+1+len([]rune(word)) <= width {
			current += " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	return append(lines, current)
}

// colorEnabled reports whether ANSI colors may be written to w. NO_COLOR (at
// any value, including empty) disables them, and so does a non-terminal
// destination such as a pipe, a file, or a test capture file.
func colorEnabled(w io.Writer) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := w.(*os.File)
	return ok && isTerminal(f)
}
