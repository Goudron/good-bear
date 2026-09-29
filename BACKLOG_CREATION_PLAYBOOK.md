# Good Bear Product Backlog Creation Playbook

Adapted from Browser Policy Manager's `docs/epic-backlog-creation-runbook.md` on 2026-08-22 for the
Good Bear repository.

This playbook is for planning versioned Good Bear product work. It preserves BPM's task sizing,
model selection, approval, verification, dependency-currency, progress, and final-quality rules,
but removes the BPM documentation pipeline. Good Bear currently produces source code and Ubuntu
distribution artifacts, not a documentation portal, PDFs, README release surfaces, or changelog.

## Required inputs

Collect before writing a backlog:

| Field | Required | Example |
| --- | --- | --- |
| Target Good Bear version | yes | `1.0` |
| Epic/theme | yes | `Russian PKI Container` |
| Backlog date | yes | `2026-08-22` |
| Scope boundary | yes | Code, tests, release tooling, Ubuntu artifacts |
| Security and privacy invariants | yes for security work | Russian root is never globally trusted |
| Known non-goals | recommended | No GOST, no macOS package |
| Release risk | recommended | Low, medium, high, or critical |
| Distribution target | yes for a release | Ubuntu LTS amd64 `.deb` and Windows x64 installer |

Normalize a version such as `1.0` to:

- version: `1.0`;
- compact epic ID: `GB100`;
- filename prefix: `good_bear_1_0`.

## Backlog file

Create one maintained backlog under `backlogs/`:

```text
backlogs/good_bear_<version_with_underscores>_<short_topic>_backlog_<yyyy-mm-dd>.md
```

Do not create a docs index, documentation manifest, README entry, changelog entry, documentation
site, PDFs, screenshots for manuals, or release-note task as a side effect of backlog creation.

## Required backlog structure

Every backlog contains:

1. target version, date, epic ID, and release risk;
2. scope summary and explicit output boundary;
3. current-state assessment;
4. approved assumptions and non-goals;
5. security/privacy/legal/branding invariants when relevant;
6. meaningful milestones with numbered task tables;
7. a final quality and distribution milestone;
8. a task-by-task approval protocol.

Use this table shape:

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M1-01` | Pin the upstream Firefox revision. | Select the exact stable source baseline and record reproducible provenance. | GPT-6 Astra | High | The revision and source hash are pinned; High reasoning is required because the baseline controls security support, rebase cost, and release compatibility. |

Task IDs use:

```text
<EPIC_ID>-M<milestone_number>-<two_digit_task_number>
```

## GPT-6 Astra model and reasoning fields

Every task names exactly one approved model and one minimum reasoning level. Model selection and
reasoning effort are independent.

Maintainer execution decision, 2026-09-19: use `GPT-6 Astra` (subagent tool identifier
`gpt-6-astra`) for the continuing Good Bear work and its focused subagents. This replaces the
previous GPT-5.6 tier policy. The source of this choice is the maintainer's instruction in the
current session; it is not a claim about an externally verified OpenAI model catalog.

| Model | Use when |
| --- | --- |
| `GPT-6 Astra` / `gpt-6-astra` | All approved Good Bear tasks; select reasoning for the task's complexity and security/release impact rather than substituting another model tier. |

Project reasoning vocabulary:

| Level | API equivalent | Use when |
| --- | --- | --- |
| `Light` | `low` | Mechanical, directly specified, immediately verified work. |
| `Medium` | `medium` | Focused subsystem work with clear owners and adjacent tests. |
| `High` | `high` | Cross-file behavior, browser integration, packaging, migration, or security test design. |
| `Extra High` | `xhigh` | Release-critical architecture, adversarial security reasoning, or broad hard-to-reproduce failure analysis. |

Choose reasoning by the work:

1. Use Light only for mechanical, directly specified edits with immediate verification.
2. Use Medium for bounded engineering with clear owners and no security or release decision.
3. Keep at least High for security-sensitive work, cross-file browser behavior, packaging, and
   verification of release evidence. Use Extra High for adversarial trust/isolation analysis,
   security UI rebases, update trust chains, and release-critical decisions.
4. Preserve an existing High or Extra High minimum when changing the model. Retain task-specific
   risk rationales as reasons for the reasoning level; model availability does not reduce risk.
5. Split oversized tasks into bounded owners before increasing reasoning or adding subagents.

The 2026-09-19 continuation also explicitly permits independent subagents for the current task and
requests a separate Firefox 156 address-bar RU/shield appearance check. Record that authorization
in the backlog with its exact scope; it is not approval of every later task or of release.

## First milestone: version, upstream, and toolchain baseline

The first milestone must:

- pin the exact stable Firefox/Gecko upstream revision from an authoritative Mozilla source;
- establish Good Bear version, product, channel, package, and build identities without blindly
  changing deep application IDs;
- define a rebase-friendly source/patch layout;
- inventory direct runtime, build, test, browser/toolchain, packaging, and release dependencies from
  authoritative sources;
- apply every compatible stable update with pins, locks, checksums, provenance, and focused tests;
- record a time-bounded owner, evidence, review date, and follow-up task for every justified
  non-update;
- pin the Ubuntu LTS amd64 build and clean-install test environment.

The dependency audit covers only code, tests, build/release tooling, and packaging. There is no
documentation toolchain in current scope.

## Security-first milestone rules

For certificate, trust, container, credential, or navigation work:

- perform targeted source reconnaissance before editing NSS/PSM or browser routing;
- convert architectural assumptions into typed APIs, machine-readable manifests, build guards, and
  executable positive/negative tests rather than standalone design documents;
- preserve standard certificate validation and the original or most relevant failure;
- identify trust anchors cryptographically, never from CN/O/OU/issuer/subject strings;
- prove that ordinary browser state, referrer, opener, authentication data, and request bodies do
  not cross the container boundary;
- make fallback behavior fail-closed;
- keep the special trust policy scoped to the real Firefox `userContextId`/`OriginAttributes`
  container;
- verify that successful STANDARD connections do not pay the secondary-verification cost;
- keep production certificate provenance and redistribution decisions explicit and reproducible.

## No-documentation output boundary

Do not add backlog tasks for:

- README authoring or refresh;
- changelog or release notes;
- user, administrator, API, architecture, threat-model, or design documents;
- docs index/manifest/search maintenance;
- documentation localization, screenshots, sites, or PDFs;
- documentation package/install targets.

Where the input specification requests a document, translate the underlying requirement into code,
tests, typed contracts, build checks, UI copy, machine-readable release metadata, or the backlog's
acceptance criteria. Do not silently discard the underlying security or legal invariant.

Bundled license texts, third-party notices, About/Legal UI, source-offer metadata, SBOMs, certificate
manifests, checksums, signatures, and package metadata are release artifacts and remain in scope.
Planning/control files under the repository root, `backlogs/`, and `project-inputs/` are also in
scope but are not product documentation deliverables.

## Milestone and task sizing

Group milestones by product or subsystem ownership. Do not create one catch-all implementation
milestone.

Split a task when it:

- crosses unrelated owners;
- combines an architecture decision with bulk edits;
- cannot be verified by one focused command or one tightly related check group;
- requires a recursive source-tree scan to understand;
- contains more than one independently approvable security boundary.

Every task names its likely verification layer in acceptance: focused unit, gtest/xpcshell/mochitest,
browser integration, upstream regression, packaging, clean-install smoke, or reproducibility.

## Distribution boundary

Good Bear 1.0 produces an Ubuntu LTS amd64 `.deb`, a Windows x64 installer, and the corresponding
source/patch release set. The backlog must not claim support for another Debian-based Linux merely
because the Ubuntu package can be installed there; that claim requires a separately pinned target
and clean-machine validation.
The backlog must include:

- a pinned Ubuntu build/test environment and deterministic toolchain inputs;
- Good Bear package/application/desktop identities;
- install, launch, browser sandbox, desktop integration, upgrade, rollback, and uninstall checks;
- preservation of upstream licenses and a corresponding-source offer for MPL-covered code;
- third-party inventory, SBOM, provenance, checksums, and signing with a maintainer-supplied key;
- clean-machine smoke tests and reproducibility comparison;
- an explicit release blocker when approved artwork, redistribution permission, or signing authority
  is missing.

For Windows, the backlog must additionally include:

- a pinned supported Windows x64 version/VM and toolchain/SDK inputs;
- a chosen reproducible installer format and code-signing inputs, without inventing a signing key;
- Russian locale, launcher, file association/default-browser, sandbox, upgrade, rollback, and
  uninstall acceptance on a clean Windows VM;
- a release blocker for an unsigned or otherwise unapproved public Windows installer.

macOS, Snap, Flatpak, AppImage, mobile, and non-Ubuntu/Debian Linux distribution packages are out
of scope unless the maintainer explicitly expands the backlog.

## Long-running command progress

Every command that can run longer than one minute, or whose duration is materially uncertain, must
emit flushed progress derived from real work: current phase, completed/total units when available,
cache/retry state, and a terminal success/failure boundary. Do not fabricate percentages or ETAs.

If an upstream command cannot expose units, add a read-only observer for independently verifiable
state. Preserve safe interruption, quarantine partial artifacts, and promote outputs atomically.

## Final quality and release milestone

Every backlog ends with tasks that:

1. run the maintained format, lint, static-analysis, and compiler-warning gates;
2. run focused Good Bear tests, affected upstream NSS/PSM/browser tests, and the maintained broader
   regression suite;
3. measure the declared Good Bear code/decision coverage surface and bring it to 100%, including
   negative/fail-closed branches; upstream Firefox as a whole is not a 100% coverage target;
4. perform an adversarial review of every security invariant;
5. verify branding, trademark separation, license provenance, corresponding source, certificate
   redistribution, SBOM, and required About/Legal release surfaces;
6. build the Ubuntu artifacts once from clean inputs, install and smoke-test them on the supported
   Ubuntu LTS target, then reproduce and compare them;
7. create a reviewed local release commit and tag only after explicit maintainer approval.

This repository starts without a remote. Do not add a remote, push, publish a package, upload an
artifact, or create a public release without a separate explicit maintainer request.

## Approval protocol

When executing a backlog interactively:

1. Show exactly one next task with ID, essence, acceptance, model, and minimal reasoning.
2. Obtain explicit approval if it has not already been given; preserve session authorization to
   continue an interrupted task.
3. Execute only the approved task through one focused subagent using `GPT-6 Astra`
   (`gpt-6-astra`) and at least the row's reasoning level. When independent parallel agent work is
   explicitly authorized, split that same task into bounded non-overlapping owners; each subagent
   uses Astra and the appropriate minimum reasoning. If Astra is unavailable, report it and obtain
   approval for a replacement rather than silently selecting a former tier.
4. Keep the primary agent as maintainer-facing coordinator; report task start, meaningful phase
   changes, blockers, and terminal verification.
5. Do not relay raw command streams unless requested. Long-running commands still emit their own
   real stdout progress.
6. Present the next task only after completion, unless a sequential batch was explicitly approved.

The existence of a backlog is never approval to implement it.

## Backlog creation acceptance checklist

Before declaring a backlog ready, confirm:

- target version, date, epic ID, scope, non-goals, assumptions, risk, and Ubuntu boundary exist;
- milestones are meaningfully grouped and tasks are small enough for one focused pass;
- every task has exactly one GPT-6 Astra model and one allowed reasoning level;
- security/release tasks retain at least High reasoning, with Extra High for adversarial or
  release-critical decisions, and their existing task-specific risk rationales remain explicit;
- the first milestone pins upstream, product/version identities, dependencies, and Ubuntu toolchain;
- security work starts with targeted reconnaissance and executable fail-closed contracts;
- certificate provenance, redistribution, exact fingerprints, role separation, and rotation are
  covered;
- ordinary state, credentials, body, referrer, opener, subresources, and early data receive positive
  and adversarial tests;
- product UI distinguishes container identity from certificate trust state without color alone;
- final artwork and signatures remain explicit release blockers until supplied/approved;
- final quality includes static analysis, affected upstream regressions, 100% Good Bear coverage,
  adversarial security review, clean Ubuntu install, and reproducibility;
- no README, changelog, docs-site, PDF, docs-index, user-manual, or design-document work appears;
- execution requires task-by-task approval and exact model/reasoning selection; focused subagents
  stay within the authorized task, with independent parallel owners only when explicitly allowed;
- no remote, push, upload, tag, or public release occurs without explicit approval;
- long-running commands expose real flushed stdout progress.
