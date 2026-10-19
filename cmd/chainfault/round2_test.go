package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestScanHelpIsSuccessfulAndUsesSharedSections(t *testing.T) {
	code, out := runCLI(t, "scan", "--help")
	if code != exitClean {
		t.Fatalf("scan --help = %d, want %d\n%s", code, exitClean, out)
	}
	for _, section := range []string{"Usage:", "Scan options:", "Exit codes:"} {
		if !strings.Contains(out, section) {
			t.Errorf("scan --help is missing %q:\n%s", section, out)
		}
	}
}

func TestHelpAndScanHelpListTheSameOptions(t *testing.T) {
	_, root := runCLI(t, "--help")
	_, scan := runCLI(t, "scan", "--help")

	// Notes are wrapped across lines, so compare with normalized whitespace.
	flatScan := strings.Join(strings.Fields(scan), " ")

	for _, opt := range scanOptions {
		name := "--" + opt.Flag
		if !strings.Contains(root, name) {
			t.Errorf("root help does not list %s:\n%s", name, root)
		}
		if !strings.Contains(scan, name) {
			t.Errorf("scan help does not list %s:\n%s", name, scan)
		}
		if opt.Note != "" && !strings.Contains(flatScan, opt.Note) {
			t.Errorf("scan help is missing the note for %s: %q", name, opt.Note)
		}
	}
}

func TestHelpColorOnlyWhenEnabled(t *testing.T) {
	var plain, colored, rootColored bytes.Buffer
	writeUsage(&plain, true, false)
	writeUsage(&colored, true, true)
	writeUsage(&rootColored, false, true)

	if strings.Contains(plain.String(), "\x1b[") {
		t.Errorf("plain help contains ANSI escapes:\n%q", plain.String())
	}
	if !strings.Contains(colored.String(), helpHeadingColor+"Usage:"+helpColorReset) {
		t.Errorf("colored help does not color the section heading yellow:\n%q", colored.String())
	}
	if !strings.Contains(rootColored.String(), helpHeadingColor+"Commands:"+helpColorReset) {
		t.Errorf("colored root help does not color the Commands heading:\n%q", rootColored.String())
	}
	for _, token := range []string{"--depth=N|full", "--html", "--output=<file>", "--verify", "--reveal"} {
		if !strings.Contains(colored.String(), helpOptionColor+token+helpColorReset) {
			t.Errorf("colored help does not color the whole option token %q in blue:\n%q", token, colored.String())
		}
	}
	if strings.Contains(colored.String(), helpOptionColor+"--depth"+helpColorReset+"=N|full") {
		t.Errorf("colored help leaves the option value outside the blue span:\n%q", colored.String())
	}
	if strings.Contains(colored.String(), helpOptionColor+"how many commits") {
		t.Errorf("colored help colors a description, which the rules forbid:\n%q", colored.String())
	}
	if strings.Contains(colored.String(), helpHeadingColor+"chainfault scan") {
		t.Errorf("colored help colors a command name, which the rules forbid:\n%q", colored.String())
	}
}

func TestHelpLinesFitWithin90Columns(t *testing.T) {
	for _, scanOnly := range []bool{false, true} {
		var buf bytes.Buffer
		writeUsage(&buf, scanOnly, false)
		out := strings.TrimRight(buf.String(), "\n")
		for i, line := range strings.Split(out, "\n") {
			if n := utf8.RuneCountInString(line); n > helpLineLimit {
				t.Errorf("scanOnly=%v: help line %d is %d columns, want <= %d:\n%q",
					scanOnly, i+1, n, helpLineLimit, line)
			}
		}
	}
}

func TestDepthNoteWrapsWithDescriptionIndentation(t *testing.T) {
	var buf bytes.Buffer
	writeUsage(&buf, true, false)
	out := buf.String()

	note := scanOptions[0].Note
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, note) {
		t.Fatalf("depth note text changed by wrapping:\n%s", out)
	}
	if strings.Contains(out, note) {
		t.Fatalf("depth note was not wrapped:\n%s", out)
	}

	width := 0
	for _, opt := range scanOptions {
		if n := utf8.RuneCountInString("--" + opt.Flag + opt.Value); n > width {
			width = n
		}
	}
	indent := strings.Repeat(" ", 2+width+2)
	var noteLines []string
	collecting := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Scans the last N commits") {
			collecting = true
		}
		if !collecting {
			continue
		}
		if trimmed == "" {
			break
		}
		noteLines = append(noteLines, line)
		if strings.HasSuffix(trimmed, "reported.") {
			break
		}
	}
	if len(noteLines) < 2 {
		t.Errorf("depth note was not wrapped onto separate lines:\n%s", out)
	}
	for _, line := range noteLines {
		if !strings.HasPrefix(line, indent) {
			t.Errorf("depth note line is not indented like a description: %q", line)
		}
	}
}

func TestInterruptedMessageOnlyMentionsCloneForURLs(t *testing.T) {
	url := "https://github.com/its-hixye/chainfault.git"
	urlMessage := interruptedMessage(url)
	if !strings.Contains(urlMessage, "Interrupted") {
		t.Errorf("URL interruption message %q does not say Interrupted", urlMessage)
	}
	if !strings.Contains(urlMessage, "temporary clone was deleted") {
		t.Errorf("URL interruption message %q omits the clone cleanup", urlMessage)
	}

	local := "/tmp/local-repo"
	localMessage := interruptedMessage(local)
	if localMessage != "\nInterrupted" {
		t.Errorf("local interruption message = %q, want only %q", localMessage, "\nInterrupted")
	}
	if strings.Contains(localMessage, "temporary clone") {
		t.Errorf("local interruption message %q mentions a temporary clone:\n%s", localMessage, local)
	}
}

func TestScanRejectsSingleDashLongFlags(t *testing.T) {
	repo := cleanRepo(t)
	cases := []string{"-depth", "-depth=5", "-html", "-output=report.html", "-verify", "-reveal"}
	for _, arg := range cases {
		code, out := runCLI(t, "scan", repo, arg)
		if code != exitIncomplete {
			t.Errorf("scan %s = %d, want %d\n%s", arg, code, exitIncomplete, out)
		}
		name := strings.TrimPrefix(arg, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		want := "chainfault scan: use --" + name + " instead of -" + name
		if !strings.Contains(out, want) {
			t.Errorf("scan %s output %q does not contain %q", arg, out, want)
		}
	}
}

func TestScanKeepsShortHelpAliases(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		code, out := runCLI(t, "scan", arg)
		if code != exitClean {
			t.Errorf("scan %s = %d, want %d\n%s", arg, code, exitClean, out)
		}
		if !strings.Contains(out, "Scan options:") {
			t.Errorf("scan %s did not print the scan help:\n%s", arg, out)
		}
	}
}

func TestDoubleDashDepthFormsStillParse(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"/repo", "--depth=5"}, "5"},
		{[]string{"/repo", "--depth", "5"}, "5"},
		{[]string{"--depth", "5", "/repo"}, "5"},
		{[]string{"/repo", "--depth=full"}, "full"},
		{[]string{"/repo", "--depth", "full"}, "full"},
	}
	for _, c := range cases {
		var f scanFlags
		target, flags := splitTarget(c.args)
		fs := scanFlagSet(&f)
		fs.SetOutput(io.Discard)
		if err := fs.Parse(flags); err != nil {
			t.Errorf("parse %q: %v", c.args, err)
			continue
		}
		if target != "/repo" {
			t.Errorf("parse %q target = %q, want /repo", c.args, target)
		}
		if f.depth != c.want {
			t.Errorf("parse %q depth = %q, want %q", c.args, f.depth, c.want)
		}
	}
}

func TestValidateTargetRejectsSSHInputs(t *testing.T) {
	targets := []string{
		"git@github.com:its-hixye/chainfault.git",
		"ssh://git@github.com/its-hixye/chainfault.git",
	}
	for _, target := range targets {
		err := validateTarget(target)
		if err == nil {
			t.Errorf("validateTarget(%q) = nil, want an error", target)
			continue
		}
		want := `only https:// repository URLs and local paths are supported, got "` + target + `"`
		if err.Error() != want {
			t.Errorf("validateTarget(%q) = %q, want %q", target, err, want)
		}
	}
}

func TestScanRejectsSSHInputWithCleanMessage(t *testing.T) {
	installFakeTool(t, "gitleaks", versionBanner("gitleaks", "8.18.0"))
	installFakeTool(t, "trufflehog", versionBanner("trufflehog", "3.99.2"))

	target := "git@github.com:its-hixye/chainfault.git"
	code, out := runCLI(t, "scan", target)
	if code != exitIncomplete {
		t.Fatalf("scan %s = %d, want %d\n%s", target, code, exitIncomplete, out)
	}
	want := `only https:// repository URLs and local paths are supported, got "` + target + `"`
	if !strings.Contains(out, want) {
		t.Errorf("scan output %q does not contain %q", out, want)
	}
	if strings.Contains(out, "does not exist") {
		t.Errorf("scan output still calls the SSH remote a missing path:\n%s", out)
	}
}

func TestMissingToolMessagePrintedOnce(t *testing.T) {
	// Build the repository before replacing PATH: cleanRepo needs git.
	repo := cleanRepo(t)
	t.Setenv("PATH", t.TempDir())

	code, out := runCLI(t, "scan", repo)
	if code != exitIncomplete {
		t.Fatalf("scan without helper tools = %d, want %d\n%s", code, exitIncomplete, out)
	}
	if got := strings.Count(out, "missing helper tool(s)"); got != 1 {
		t.Errorf("missing helper tool message printed %d times, want once:\n%s", got, out)
	}
	if strings.Contains(out, "not found in PATH") {
		t.Errorf("missing tool information was printed twice:\n%s", out)
	}
}

func TestScanHelpIncludesDepthNote(t *testing.T) {
	_, out := runCLI(t, "scan", "--help")
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{"last N commits", "deleted inside those commits", "may still be reported"} {
		if !strings.Contains(flat, want) {
			t.Errorf("scan --help does not mention %q:\n%s", want, out)
		}
	}
}
