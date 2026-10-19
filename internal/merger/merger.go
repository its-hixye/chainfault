// Package merger collapses the findings of both scanner tools into one list
// with no duplicates (CHAINFAULT_DOC.md §16).
package merger

import (
	"sort"

	"github.com/its-hixye/chainfault/internal/normalizer"
)

// group collects every finding that shares one merge key.
type group struct {
	items  []normalizer.Finding
	commit map[string]struct{}
}

// Merge deduplicates findings from both tools.
//
// The merge key is the normalized path plus the normalized secret value — not
// the line number or commit hash, because both move as the file changes. Same
// secret on several lines or in several commits of one file becomes one finding
// showing the smallest line number and the number of commits it was seen in.
func Merge(in []normalizer.Finding) []normalizer.Finding {
	order := make([]string, 0, len(in))
	groups := make(map[string]*group, len(in))

	for _, f := range in {
		key := normalizer.MergeKey(f.FilePath, f.SecretValue)
		g, ok := groups[key]
		if !ok {
			g = &group{commit: make(map[string]struct{})}
			groups[key] = g
			order = append(order, key)
		}
		g.items = append(g.items, f)
		if f.CommitHash != "" {
			g.commit[f.CommitHash] = struct{}{}
		}
	}

	out := make([]normalizer.Finding, 0, len(order))
	for _, key := range order {
		g := groups[key]
		f := representative(g.items)
		f.SeenInCommits = len(g.commit)
		if f.SeenInCommits == 0 {
			f.SeenInCommits = 1
		}
		f.FoundBy = unionTools(g.items)
		if f.SecretType == "" || f.SecretType == normalizer.TypeLabelGeneric {
			if moreSpecific := pickType(g.items, f.SecretType); moreSpecific != "" {
				f.SecretType = moreSpecific
			}
		}
		out = append(out, f)
	}
	return out
}

// representative picks the single finding a merged group is displayed from.
//
//   - line: the smallest start line reported by either tool (the first
//     appearance)
//   - tie-break on the same line: most recent commit, then shortest hash, so
//     the choice never depends on map or goroutine ordering
//   - entropy / verified: taken from the best candidate that has them
func representative(items []normalizer.Finding) normalizer.Finding {
	cands := append([]normalizer.Finding(nil), items...)
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.CommitDate != b.CommitDate {
			return a.CommitDate > b.CommitDate
		}
		if len(a.CommitHash) != len(b.CommitHash) {
			return len(a.CommitHash) < len(b.CommitHash)
		}
		return a.CommitHash < b.CommitHash
	})

	best := cands[0]
	// Gitleaks is the only tool that reports entropy; keep it when present.
	for _, c := range cands {
		if c.Entropy > best.Entropy {
			best.Entropy = c.Entropy
		}
		if c.Verified {
			best.Verified = true
		}
		if best.MaskedSecret == "" && c.MaskedSecret != "" {
			best.MaskedSecret = c.MaskedSecret
		}
	}
	best.DecodedFrom = pickDecoder(items)
	return best
}

// pickDecoder resolves TruffleHog's duplicate-decoder case deterministically
// (CHAINFAULT_DOC.md §16): TruffleHog can emit the same secret twice, once as
// PLAIN and once decoded from BASE64. When they merge, keep the one whose
// decodedFrom is not PLAIN; if several qualify, take the alphabetically first.
func pickDecoder(items []normalizer.Finding) string {
	best := ""
	for _, it := range items {
		d := it.DecodedFrom
		if d == "" || d == "PLAIN" {
			continue
		}
		if best == "" || d < best {
			best = d
		}
	}
	return best
}

// unionTools returns the sorted set of tools that reported the group.
func unionTools(items []normalizer.Finding) []string {
	seen := make(map[string]struct{}, len(items))
	for _, it := range items {
		for _, tool := range it.FoundBy {
			if tool != "" {
				seen[tool] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for tool := range seen {
		out = append(out, tool)
	}
	sort.Strings(out)
	return out
}

// pickType implements the specificity rule of CHAINFAULT_DOC.md §10: when two
// tools label the same secret differently, the concrete label wins over the
// generic one.
func pickType(items []normalizer.Finding, current string) string {
	best := ""
	for _, it := range items {
		if it.SecretType == "" || it.SecretType == normalizer.TypeLabelGeneric {
			continue
		}
		if best == "" || it.SecretType < best {
			best = it.SecretType
		}
	}
	if best == "" {
		return current
	}
	return best
}
