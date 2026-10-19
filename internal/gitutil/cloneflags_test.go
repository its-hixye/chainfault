package gitutil

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGitArgv recovers the argv the fake git executable recorded, one argument
// per line.
func fakeGitArgv(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fake git recorded nothing at %s: %v", path, err)
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func indexOfArg(argv []string, want string) int {
	for i, a := range argv {
		if a == want {
			return i
		}
	}
	return -1
}

// TestClonePassesHookAndSubmoduleGuards asserts that Clone hands git the two
// hardenings CHAINFAULT_DOC.md §19 requires: hooks are disabled via
// `-c core.hooksPath=/dev/null` and nested repositories are refused via
// `--no-recurse-submodules`. A hostile repository must be able to neither
// execute code nor pull in further repositories.
//
// The two guards are placed where git requires them: `-c core.hooksPath=/dev/null`
// is a git-level option and must precede the `clone` subcommand, whereas
// `--no-recurse-submodules` is an option *of* `clone` and must follow it. This
// test pins that ordering, because a guard passed on the wrong side of `clone`
// is not a guard at all — git would reject the command line.
//
// A fake `git` is placed first on PATH so the assertion is on the real argv
// Clone builds, not on a reimplementation of it.
func TestClonePassesHookAndSubmoduleGuards(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "argv.txt")

	fakeDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeDir, 0o755); err != nil {
		t.Fatalf("create fake bin dir: %v", err)
	}
	// Each argument is written on its own line so ordering is preserved
	// unambiguously. `exit 0` makes Clone believe the clone succeeded; Clone
	// does nothing after the git process returns.
	script := "#!/bin/sh\n" +
		"for arg in \"$@\"; do\n" +
		"\tprintf '%s\\n' \"$arg\" >> \"$FAKE_GIT_ARGV\"\n" +
		"done\n" +
		"exit 0\n"
	fakeGit := filepath.Join(fakeDir, "git")
	if err := os.WriteFile(fakeGit, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}

	t.Setenv("FAKE_GIT_ARGV", record)
	t.Setenv("PATH", fakeDir)

	src := "https://example.com/owner/repo.git"
	dst := filepath.Join(dir, "clone")
	if err := Clone(context.Background(), src, dst); err != nil {
		t.Fatalf("Clone with a fake git that exits 0 = %v, want nil", err)
	}

	argv := fakeGitArgv(t, record)
	t.Logf("fake git argv: %q", argv)

	cloneIdx := indexOfArg(argv, "clone")
	if cloneIdx < 0 {
		t.Fatalf("git was not asked to clone: argv = %q", argv)
	}
	if n := strings.Count(" "+strings.Join(argv, " ")+" ", " clone "); n != 1 {
		t.Errorf("expected exactly one clone invocation, recorded %d: argv = %q", n, argv)
	}

	hooksIdx := indexOfArg(argv, "core.hooksPath=/dev/null")
	if hooksIdx < 0 {
		t.Errorf("Clone did not pass core.hooksPath=/dev/null: argv = %q", argv)
	} else if hooksIdx > cloneIdx {
		t.Errorf("core.hooksPath=/dev/null came after clone (idx %d > %d): argv = %q", hooksIdx, cloneIdx, argv)
	}

	cIdx := indexOfArg(argv, "-c")
	if cIdx < 0 {
		t.Errorf("Clone did not pass -c: argv = %q", argv)
	} else if cIdx+1 >= len(argv) || argv[cIdx+1] != "core.hooksPath=/dev/null" {
		t.Errorf("-c is not immediately followed by core.hooksPath=/dev/null: argv = %q", argv)
	}

	submoduleIdx := indexOfArg(argv, "--no-recurse-submodules")
	if submoduleIdx < 0 {
		t.Errorf("Clone did not pass --no-recurse-submodules: argv = %q", argv)
	} else if submoduleIdx < cloneIdx {
		// It is an option of the clone subcommand; before `clone` git would
		// reject it as an unknown global option.
		t.Errorf("--no-recurse-submodules must follow clone (idx %d < %d): argv = %q", submoduleIdx, cloneIdx, argv)
	}

	if indexOfArg(argv, src) < 0 || indexOfArg(argv, dst) < 0 {
		t.Errorf("Clone did not pass source and destination: argv = %q", argv)
	}
}
