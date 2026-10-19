# Changelog

All notable changes to Chainfault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0]

First release.

### Added

- `chainfault scan <path-or-url>` with `--depth`, `--html`, `--output`,
  `--verify` and `--reveal`.
- Temporary-clone scanning: the repository is cloned before scanning and the
  clone's `.gitleaks.toml` and `.gitleaksignore` are deleted, so a repository
  cannot change the scan rules or hide its own findings. The clone is removed
  afterwards and on Ctrl+C.
- Parallel execution of Gitleaks and TruffleHog; one failing never stops the
  other.
- Merge of both tools' findings into one de-duplicated list keyed on the file
  path plus the secret value, with a deterministic tie-break for TruffleHog's
  duplicate PLAIN/BASE64 findings.
- A unified secret-type naming table: raw tool names are never displayed and
  both tools produce the same label for the same secret.
- Integer risk scoring from 1 to 10 with test-file penalty and severity bands.
- Terminal report and a self-contained HTML report built from one shared data
  object, so no field can exist in one report and be missing from the other.
- Length-based secret masking and control-character sanitization of every value
  taken from a repository.
- `chainfault doctor` and `chainfault version`.

### Known limitations

- The helper tools are installed manually; when one is missing, Chainfault
  reports it and exits 2.
- Only `https://` clone URLs and local paths are supported. Private
  repositories and non-Linux platforms are out of scope.
- A report is written in the current directory, not inside the scanned
  repository.
