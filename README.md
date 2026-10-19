# Chainfault

Find leaked secrets across a repository's whole git history by running Gitleaks
and TruffleHog in parallel and merging their findings.

[![CI](https://github.com/its-hixye/chainfault/actions/workflows/ci.yml/badge.svg)](https://github.com/its-hixye/chainfault/actions/workflows/ci.yml)

## Quick start

```sh
go build -o chainfault ./cmd/chainfault
./chainfault doctor
./chainfault scan <path-or-url>
```

## Requirements

- Linux
- Go 1.26 or newer (to build)
- `gitleaks` and `trufflehog` on `PATH`

`chainfault doctor` reports where the two tools are and which version they
report. It only finds tools; it never installs anything.

## Install

```sh
go build -o chainfault ./cmd/chainfault
```

## Usage

```
chainfault scan <path-or-url> [options]
chainfault doctor
chainfault version
```

The target is a local path or an `https://` URL.

### Scan options

| Option | What it does |
|---|---|
| `--depth=N\|full` | how many commits to scan (default: `full`) |
| `--html` | also write a self-contained HTML report |
| `--output=<file>` | where to write the HTML report; requires `--html`, must end in `.html` |
| `--verify` | let TruffleHog check the discovered secrets against the real services |
| `--reveal` | print full secrets instead of masking them |

`--depth` scans the last N commits. A secret deleted inside those commits may
still be reported.

`--verify` contacts the real services. Use it only on repositories you are
allowed to test.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | both scanners finished, no secrets found |
| `1` | both scanners finished, secrets found |
| `2` | a scanner failed, the scan was interrupted, or the input was invalid |

Failure always wins over findings: a partial scan must never be mistaken for a
clean one.

## Example terminal output

```
[Critical 9/10] AWS key (history only)
Path:     src/config/database.py:14
Commit:   f48a19c — 2024-03-12 — Ahmed
Secret:   AWS_SECRET_KEY = "AKIA****************XMPL"
Verified live: yes
Seen in:  3 commits

Total: 1 finding across 1 file
```

## How it works

Chainfault runs Gitleaks and TruffleHog in parallel and merges duplicate
findings into one list. Each secret gets one risk score from 1 to 10. The scan
runs on a temporary clone, which is deleted afterwards, including on Ctrl+C.
The repository's own ignore files are removed from the clone, so they cannot
hide secrets.

## Risk score

| Category | Score |
|---|---|
| Cloud keys (AWS, Google Cloud, Azure) | 9 |
| Private keys (SSH, certificates) | 9 |
| Database passwords | 8 |
| Account tokens (GitHub, GitLab, Slack) | 8 |
| Payment keys (Stripe and alike) | 8 |
| General account passwords | 7 |
| Service API keys (Twilio, SendGrid) | 6 |
| Webhook URLs | 5 |
| Suspicious random text | 4 |
| Anything not in the table | 5 |

A secret inside a test, mock or fixture file is still reported, tagged
`(test file)`, and loses two points (floor 1). Bands: critical 9–10, high 7–8,
medium 4–6, low 1–3.

Secrets are always masked unless `--reveal` is used.

## HTML report

`--html` writes one self-contained page that opens offline. Each finding
becomes a card with severity, location and commit info; the page has filters
and a search box. The file is written with permission `0600`. With `--reveal`,
the file contains full secrets, so delete it after use.

The default file name is:

```
chainfault-report-<project>-<YYYY-MM-DD-HHMM>.html
```

## Limitations

- Finds secrets only; it does not scan dependencies for vulnerabilities.
- Linux only.
- No JSON output.
- Private repositories work only when `git` can access them without prompting,
  for example through a credential helper. Chainfault has no login or token
  option.

## License

MIT — see [LICENSE](LICENSE).

Gitleaks and TruffleHog are independent programs. Chainfault runs them; it does
not copy their code.
