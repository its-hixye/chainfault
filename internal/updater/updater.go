// Package updater locates the two helper tools Chainfault drives. v0.1.0 never
// installs or updates anything: it reports where a tool is, and where to get it
// when it is missing (CHAINFAULT_DOC.md §5, §8, §12).
package updater

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// unknownVersion is what doctor reports for a tool that is installed but whose
// --version output carries no version number. Finding the executable is what
// makes a tool installed; reading its version is best-effort, so a tool that
// prints a build-process banner ("version is set by build process") is still
// reported OK.
const unknownVersion = "installed (version unknown)"

// versionPattern matches the dotted version numbers tools print in their
// --version banner: "gitleaks version 8.18.0" and "trufflehog 3.99.2" both
// yield just the number, so doctor never repeats the tool name.
var versionPattern = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z.]+)?`)

// toolPages maps each helper tool to its official project page, taken verbatim
// from CHAINFAULT_DOC.md §5. The page is where the tool's Releases live.
var toolPages = map[string]string{
	"gitleaks":   "https://github.com/gitleaks/gitleaks/releases",
	"trufflehog": "https://github.com/trufflesecurity/trufflehog/releases",
}

// ReleasesPage returns the official page a helper tool can be downloaded from,
// or "" when Chainfault does not know the tool. doctor and the scan error both
// use it to point at the tool's Releases (CHAINFAULT_DOC.md §5, §12).
func ReleasesPage(name string) string {
	return toolPages[name]
}

// Status describes one helper tool.
type Status struct {
	Name    string
	Path    string
	Version string
	OK      bool
	Reason  string
}

// Lookup reports where a tool is installed and which version it reports. It
// never installs anything.
//
// Being on PATH is what makes a tool installed: once the executable is found
// the status is OK, and the version is best-effort. A tool whose --version
// prints a banner without a version number (gitleaks: "version is set by build
// process"), prints nothing, or exits non-zero still reports OK with
// "installed (version unknown)".
func Lookup(name string) Status {
	st := Status{Name: name}
	path, err := exec.LookPath(name)
	if err != nil {
		st.Reason = "not found in PATH"
		return st
	}
	st.Path = path
	st.OK = true

	// A failing --version is not a lookup failure: the tool is on PATH, so we
	// keep OK and fall back to the unknown-version label.
	out, _ := exec.Command(name, "--version").CombinedOutput()
	st.Version = extractVersion(firstLine(string(out)))
	if st.Version == "" {
		st.Version = unknownVersion
	}
	return st
}

// extractVersion pulls the version number out of a tool's --version banner. It
// returns "" when the banner carries no dotted number, which is the signal to
// report the tool as installed with an unknown version.
func extractVersion(line string) string {
	return versionPattern.FindString(line)
}

// firstLine collapses a tool's version banner down to its first non-empty line.
func firstLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

// Ensure makes sure every required tool is available before a scan starts.
//
// v0.1.0 never installs anything: when a tool is missing it returns an error
// that names the tool and its official Releases page, and the caller exits 2
// (CHAINFAULT_DOC.md §8, §12).
func Ensure(ctx context.Context, tools []string) ([]Status, error) {
	_ = ctx
	statuses := make([]Status, 0, len(tools))
	var missing []string

	for _, name := range tools {
		st := Lookup(name)
		statuses = append(statuses, st)
		if !st.OK {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return statuses, nil
	}
	return statuses, missingToolsError(missing)
}

// missingToolsError names every missing tool and points at its official
// Releases page (CHAINFAULT_DOC.md §5), so the user knows where to get it.
func missingToolsError(missing []string) error {
	var b strings.Builder
	b.WriteString("missing helper tool(s):")
	for _, name := range missing {
		if page := ReleasesPage(name); page != "" {
			fmt.Fprintf(&b, "\n  %s — install it from %s and make sure it is in PATH", name, page)
			continue
		}
		fmt.Fprintf(&b, "\n  %s — install it and make sure it is in PATH", name)
	}
	return errors.New(b.String())
}
