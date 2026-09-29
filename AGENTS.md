# AGENTS.md

## Start here

- Read the one explicitly approved task in
  `backlogs/good_bear_1_0_russian_pki_container_backlog_2026-08-22.md`.
- Read only the relevant sections of the normative inputs under `project-inputs/`.
- Follow `BACKLOG_CREATION_PLAYBOOK.md` only when creating or revising a backlog.
- Inspect the pinned Firefox/Gecko owners and adjacent tests named by the approved task before
  expanding context.

## Scope discipline

- Do not execute backlog tasks merely because the backlog exists. Each task needs explicit
  maintainer approval.
- Keep Good Bear changes localized and rebase-friendly; preserve Mozilla and third-party notices.
- Treat all security boundaries as fail-closed. Never globalize the Russian PKI trust anchor,
  bypass normal X.509/TLS validation, replay a request body across a container boundary, or infer
  trust from certificate names.
- Do not recursively scan the Firefox source tree. Prefer targeted owners, adjacent tests, and
  focused search paths.

## Output boundary

- Current project outputs are source code, tests, build/release tooling, required bundled legal
  notices, and Ubuntu and Windows distribution artifacts.
- Do not add product documentation, a documentation site, PDFs, a documentation index/manifest,
  release notes, or changelog work unless the maintainer explicitly expands scope.
- Planning/control files (`AGENTS.md`, this playbook, backlogs, and `project-inputs/`) are not product
  documentation deliverables.
- Ubuntu LTS amd64 and Windows x64 are Good Bear 1.0 distribution targets. macOS may remain
  compatible at source level but receives no 1.0 packaging task. Do not claim Debian or another
  Debian-based Linux distribution as supported merely because an Ubuntu `.deb` might install there:
  that requires its own pinned environment and clean-machine acceptance work.

## Verification

- Run the narrowest relevant check first, then the milestone gate.
- Every security-sensitive positive test needs a negative/adversarial counterpart.
- Commands that may run longer than one minute must expose flushed, real-work progress on stdout.
- Never treat a successful compilation as sufficient security evidence.

## Host paths and Russian-locale contract

- Do not compose Good Bear source, object-directory, l10n, toolchain, or
  `MOZCONFIG` paths by hand. Resolve them through
  `tools/host_build_context.py`; the script derives the project root from its
  own location and rejects a source or object path outside the project.
- Use `tools/build_host_russian.py` for an Ubuntu candidate. Its last phase is
  `installers-ru`. Until M12 implements and verifies the separate Windows pipeline, its output is
  the only candidate that may be described as a Russian Good Bear build.
- The non-localized Firefox base build intentionally consumes upstream
  `en-US` inputs. This is an internal language-repack prerequisite, not a
  product locale and not evidence of a Russian UI. It must be followed by the
  `ru` repack before UI, screenshot, startup-locale, or distribution claims.
- `ru` is the sole shipped locale. `en-US` may appear only as an upstream
  source/fallback or a temporary internal base-package input; it must not be
  added to a release artifact, a package claim, or a localized-smoke result.
- Before a `mach` build or test, print and validate the canonical host context
  with `python3 tools/host_build_context.py --objdir <relative-objdir>
  --intent <engine-test|russian-repack|localized-smoke>`. Report the intent
  with the result so that a base-engine check cannot be mistaken for a Russian
  artifact check.
