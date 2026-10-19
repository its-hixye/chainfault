# Contributing to Chainfault

Chainfault finds leaked secrets across a repository's whole git history by
running Gitleaks and TruffleHog and merging their findings. Bug reports, new
secret-type rules and fixes are welcome.

## Ground rules

- Never print or commit a real secret. Test fixtures use fabricated
  credentials, and fake tokens are built by joining two string parts so GitHub
  push protection does not flag them.
- `templates/report.html` must stay one self-contained file: no external
  fonts, scripts, images or network requests, because the report must open
  offline.
- Risk scores are integers. Never introduce a float score.
- Exit code 2 (a scanner failed or the scan was interrupted) always wins over
  exit code 1.

## Project layout

```
cmd/chainfault/       CLI entry point and the live wait screen
internal/gitutil/     clone, rev-list, git show
internal/scanner/     running Gitleaks and TruffleHog
internal/normalizer/  unified secret shape, masking, merge key, type table
internal/merger/      deduplication
internal/risk/        integer scoring and severity bands
internal/reporter/    terminal report, HTML report, shared view model
internal/updater/     helper-tool discovery; it never installs anything
internal/integration/ end-to-end tests against the real helper tools
templates/            embedded report.html, config.toml and embed.go
```

## Code quality

- One package, one job. If a package needs a comment explaining what it is
  *also* for, it wants to be two packages.
- Small functions, no cleverness that needs a comment to decode.
- Every exported identifier carries a doc comment that says why, not what.
- Errors are wrapped with context; never discard one.
- Scores are integers. Never introduce a float score.

## Before you open a pull request

```sh
gofmt -w .
go vet ./...
staticcheck ./...
go test -count=1 ./...
go build -o chainfault ./cmd/chainfault
```

Then run it against a small fixture repository and check that:

- a repository's own `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow`
  comments do not hide findings;
- a secret deleted from the working tree is reported as `history only`;
- the terminal output has no `Entropy:` or `Found by:` line;
- the exit code is 0 for a clean scan, 1 for findings, and 2 for a failed or
  interrupted scan.

## Reporting problems

Describe the issue without pasting a real secret into a public issue. Replace
any real value with a fake one.
