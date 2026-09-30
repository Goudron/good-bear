# Good Bear 1.0 Russian PKI Container Product Backlog

Date: 2026-08-22

Last revised: 2026-09-23

Target version: `1.0`

Epic ID: `GB100`

Release risk: **critical**. Good Bear changes certificate validation, navigation timing, browser-state
partitioning, credential behavior, public product identity, and redistribution of a Firefox-derived
binary. A defect could globalize a trust anchor, leak ordinary-profile state across a trust-domain
boundary, replay sensitive request data, weaken standard TLS validation, misrepresent product
affiliation, or ship a non-reproducible/unlicensed package.

**Model-policy revision, 2026-09-23.** The 2026-09-19 Astra choice is historical. The maintainer
has returned Good Bear execution to the GPT-5.6 family because Astra's token use is unsuitable for
this work. Before each approved task or bounded independent subtask, the coordinator selects and
records the exact GPT-5.6 type: `gpt-5.6-luna` for direct, tightly verified mechanical work;
`gpt-5.6-terra` for bounded implementation and analysis; and `gpt-5.6-sol` for security,
cross-system, adversarial, or release-critical work. The task-row value `GPT-5.6 (tier selected at
execution)` deliberately does not preselect a subagent type. The selected type must meet the row's
minimum reasoning and be reported with the task start. Reasoning remains independent: High
(`high`) is the minimum for security-sensitive browser integration and release evidence; Extra High
(`xhigh`) is required for adversarial trust/isolation work, security UI rebases, update trust, and
release-critical decisions. Existing High/Extra High minima and task-specific risk rationales are
preserved.

**Current continuation authorization, 2026-09-23.** The maintainer explicitly requested continuation
of the interrupted work with suitable GPT-5.6 subagents and this backlog update. The
current task is the unfinished M15-11 Firefox `155.0.1 -> 156.0` transition, including a separate
comparison of the address-bar `RU` indicator with Firefox 156's shield and surrounding native UI.
Independent source/gate, UI, and planning owners may run as bounded subagents within this task.
This records continuation authority only; it does not approve all future backlog tasks, claim a
completed migration, waive manual UI promotion, or grant a new release/publication approval.

## Scope summary

- Base Good Bear 1.0 on an exact stable desktop Firefox/Gecko revision selected at execution time
  from authoritative Mozilla sources.
- Add scoped support for certificate chains ending at an exact, pinned Russian Trusted Root CA
  without making that root globally trusted.
- Route eligible top-level sites into a real, built-in Firefox container identified by
  `userContextId` / `OriginAttributes`.
- Keep ordinary cookies, storage, service workers, password/autofill state, authentication state,
  referrer, opener, request bodies, and early data from crossing into the Russian PKI context.
- Distinguish `STANDARD`, `RUSSIAN_PKI`, and `INVALID` in one typed source of truth and expose the
  result to routing and security UI.
- Implement persistent origin assignment, sticky-container behavior, trust-domain history, safe
  handling of redirects and body-carrying requests, and blocking of Russian PKI subresources in an
  ordinary page.
- Deliver only a Russian-language Good Bear build. Good Bear-specific UI is shipped and verified in
  Russian for the container marker, Russian PKI trust indicator, security popup,
  trust-change/body interstitials, settings, and assignment management. Upstream-required `en-US`
  source/fallback resources may remain internal build inputs but do not form a separately shipped
  or supported English product build.
- Rebrand public product identity as Good Bear while preserving Mozilla and third-party provenance,
  MPL-2.0 obligations, and non-affiliation requirements.
- Produce source code, automated tests, build/release tooling, required bundled notices/metadata,
  an Ubuntu LTS amd64 `.deb`, a Windows x64 installer, and corresponding source/patch artifacts.
- Publish approved release inputs and verified distribution artifacts in the maintainer-provided
  public repository `https://github.com/Goudron/good-bear`, without publishing a Firefox source
  mirror.
- Keep the authoritative Good Bear source and patch worktree on the maintainer's local machine;
  perform compilation, packaging, and clean-target validation on dedicated Ubuntu and Windows
  Server build VMs. Transfer only a pinned, checksummed source snapshot and declared inputs to a
  disposable remote workspace; return artifacts, checksums, provenance, and logs for local review.
- Rebase Good Bear from Firefox 154 to the currently stable Firefox 155 release line, pinning the
  exact 155.x source revision at execution time from Mozilla's signed release provenance.
- Continue the already-started M15-11 transition from Firefox `155.0.1` to the locally pinned
  `156.0` input; reopen affected source, security, UI, localization, and release gates against
  those exact new inputs before any promotion.
- Treat the Good Bear product version and the Firefox base version as two independent, mandatory
  release values. Every candidate, package, provenance record, update decision, and About surface
  carries both; the Russian About UI uses the canonical visible form
  `Good Bear <версия Good Bear> (Firefox <точная версия Firefox>)`.
- Ship RusSpell Lab Russian Hunspell dictionary 1.0.8 (or a later locally verified immutable
  RusSpell release selected at execution time) as Good Bear's primary Russian dictionary, while
  retaining an English dictionary and enabling spell checking by default for Russian and English
  editing contexts.
- Signed Firefox MAR updates, authenticated update metadata, and automatic update delivery are a
  future post-1.0 M15 capability, not a condition of the Good Bear 1.0 release. Good Bear 1.0 has
  no application auto-update on either platform. Until a maintainer-controlled APT repository
  exists, a later Ubuntu update path may only be an explicit terminal procedure: fetch a versioned
  GitHub Release asset, verify its published SHA-256 checksum, then run `sudo apt install` on that
  local file. The browser may show and copy that command, but must not write over package-manager-owned files.

## Output boundary

The only product deliverables in this backlog are source code, tests, build/release tooling,
machine-readable security/release metadata, required bundled legal notices, brand assets supplied
or approved by the maintainer, and Ubuntu and Windows distribution artifacts.

There are no tasks for README, changelog, release notes, user/admin/API/design/threat-model
documents, documentation localization, docs indexes/manifests, documentation sites, PDFs, or manual
screenshots. Where the input specification asks for such a document, this backlog preserves the
underlying requirement through typed code, executable tests, build guards, UI copy, release
metadata, and acceptance criteria.

The backlog, playbook, `AGENTS.md`, and immutable files under `project-inputs/` are planning/control
inputs, not product documentation outputs.

Maintainer-approved exception: M14 produces one Russian-language `README.md` as the repository's
release-navigation surface. It is limited to build/source-offer instructions, provenance, safety
boundaries, and prominent direct links to the verified Ubuntu and Windows release artifacts; it
does not create a documentation pipeline, site, PDF, changelog, or user manual.

## Current-state assessment

- The public GitHub repository `Goudron/good-bear` is prepared by the maintainer. It is the planned
  home for Good Bear patches, reproducible-build inputs, a Russian README, and verified release
  artifacts; it must not become a mirror of Firefox plus Good Bear sources.
- The normative product inputs are the three files under `project-inputs/`; their embedded Codex
  directions are interpreted as product requirements, not authorization to start implementation.
- Good Bear 1.0 has no approved final logo, mascot, color palette, Russian PKI badge artwork,
  installer imagery, package signing key, or confirmed certificate redistribution decision.
- Firefox 154 is the existing implementation baseline. Firefox 155 was the current stable rapid
  release on 2026-09-12 according to Mozilla; the exact 155.x revision, supported Ubuntu LTS point
  release, compiler/toolchain inputs, deep application IDs, and Russian PKI certificate bytes must
  be pinned during approved execution from authoritative sources.
- Superseding in-progress baseline state, observed 2026-09-19: `config/firefox-baseline.json`
  selects Firefox `156.0` on 2026-09-16 at revision
  `3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1`, with source archive hashes and Mozilla signature
  provenance fields. Dependent M15 gate records still refer to `155.0.1`; they are prior-baseline
  evidence and do not establish a passing Firefox 156 migration. M15-11 remains in progress and
  must regenerate affected evidence rather than relabel old results. Earlier 154/155 task
  descriptions below remain the historical rebaseline scope.
- Good Bear's current product version is `1.0`. It is never conflated with the Firefox base version:
  user-visible About copy, package/update metadata, MAR eligibility, source offer, SBOM, and build
  provenance record the ordered pair. For example, a build based on Firefox `155.0` displays
  `Good Bear 1.0 (Firefox 155.0)` in Russian UI.
- The maintainer is provisioning two remote builders: Ubuntu and Windows Server 2025, each with
  four vCPUs, 16 GiB RAM, and SSD storage. Windows Server is an acceptable native x64 build host
  once its SDK/MSVC/toolchain and installer behavior are pinned and verified; it does not expand
  Good Bear's end-user Windows support claim beyond Windows x64.
- Cloud.ru accepts the Windows builder only from a prepared user image. The planned temporary build
  host is an official Windows Server 2025 Evaluation installation with Desktop Experience; it is
  free for its documented 180-day evaluation period, requires online activation within its initial
  activation window, and must be replaced or licensed before expiry. This is a build-host choice,
  not a redistribution component of Good Bear.
- Superseding M15-03 execution decision, 2026-09-14: the available Cloud.ru Marketplace image
  `wind-2022-dc-evo-prod` is an approved replacement build host. M15-03 creates the tagged
  Windows Server 2022 builder directly through the Cloud.ru API in `ru.AZ-2` with 4 vCPUs,
  16 GiB RAM and a 250 GiB SSD. The unsuccessful local Server 2025 RAW-preparation VM is not a
  release input and has been removed; no local Windows VM acceptance run is required.
- RusSpell Lab's locally verified release 1.0.8 is at commit
  `a8561a2d8ca6cb294e5bb663d618602d5b3ec7a8`; its Mozilla dictionary manifest declares version
  `1.0.8` and MPL-2.0 licensing. Its `.dic` and `.aff` bytes are pinned in M15 rather than copied
  by an unreviewed ad-hoc step.
- Remote publication is authorized by the maintainer on 2026-09-05, but only after all local release
  gates pass. GitHub is the release host; no other registry or host is implied.

## Security, privacy, legal, and branding invariants

1. Russian PKI trust is never global and is never enabled outside the dedicated real container.
2. A trust anchor is recognized by exact cryptographic identity, never by CN/O/OU/issuer/subject or
   other certificate strings.
3. Hostname, validity, signature, EKU, Key Usage, Basic Constraints, path length, chain, and every
   other standard Firefox validation remain enforced.
4. An intermediate is never promoted to a trust anchor.
5. STANDARD verification has priority; secondary Russian PKI verification does not run after
   ordinary success.
6. Secondary verification in an ordinary context classifies and redirects; it does not turn the
   original ordinary channel into an accepted connection.
7. Ordinary browser state, credentials, referrer, opener, request bodies, authentication headers,
   and early data never cross the boundary automatically.
8. Body-carrying navigation is never replayed after a container change.
9. Russian PKI subresources are blocked in ordinary pages; no hidden cross-container proxying is
   allowed.
10. Any uncertain or unsupported case fails closed. Compilation alone is never security evidence.
11. No Russian/GOST cryptography, WebExtension core implementation, binary runtime patching, MITM
    proxy, `LD_PRELOAD`, injection, or universal certificate exception is introduced.
12. The bear represents product identity; the Russian PKI badge represents certificate trust. UI
    never conflates them or relies on color alone.
13. Public identity is Good Bear, not Firefox/Mozilla or a government product; upstream notices and
    third-party rights remain intact.
14. Production certificate bytes are included only after official provenance, exact pinning, and a
    confirmed redistribution basis. Otherwise a controlled official-source import workflow is used.
15. Good Bear must not expose, enable, advertise, or silently route through Mozilla-operated
    subscription, account, proxy/VPN, relay, recommendation, telemetry, or other hosted service
    unless its independent operator, endpoint, privacy boundary, localisation, redistribution
    basis, and explicit maintainer approval are separately pinned and tested. In particular, the
    Firefox built-in VPN/IP Protection and Mozilla VPN surfaces are disabled in the Good Bear
    distribution; an upstream rebase must fail if they reappear without a separate approved task.
16. Every non-user-directed network service in the product has one declared disposition:
    `disabled`, `Good Bear-operated and pinned`, `user-configured passthrough`, or
    `security feed with a pinned, auditable supplier`. An unclassified Mozilla/partner endpoint,
    experiment, recommendation, upload, account, or model/dictionary download fails the release
    gate. This invariant does not permit disabling certificate-revocation, anti-phishing, or other
    security feeds without an approved equally protective replacement.

## Assumptions and non-goals

- Distribution scope is Ubuntu LTS amd64 and Windows x64. Exact supported Ubuntu LTS/point release
  and supported Windows x64 version are pinned in M1/M12.
- Release locale is `ru`; the package starts in Russian and no separate English or multilingual
  Good Bear distribution is built, published, or claimed for 1.0.
- The final package formats are an Ubuntu `.deb` and a Windows x64 installer whose exact format is
  selected and verified in M12; Snap, Flatpak, AppImage, macOS, mobile, and arm64 packages are
  outside 1.0.
- Source-level changes should remain cross-platform where practical. Ubuntu and Windows alone
  receive 1.0 release engineering and release claims. An Ubuntu `.deb` does not by itself claim
  support for Debian or other Debian-based Linux distributions.
- GOST algorithms, electronic signatures, CryptoPro/PKCS#11-specific GOST integration, Firefox
  Sync of assignments, remote root updates, a custom updater outside Firefox's native update
  subsystem, and a container-aware password store are out of scope.
- Password saving and autofill in the Russian PKI container are disabled if safe container-aware
  isolation cannot be proven with the selected upstream.
- Private Browsing support is conditional on proving safe `privateBrowsingId + userContextId`
  behavior; otherwise Russian PKI use in Private Browsing is blocked and fails closed.
- Final original artwork is supplied and approved outside this backlog. Development placeholders
  may exercise injection points but can never pass a public-release gate.
- A maintainer-supplied signing key/authority is required only for a future signed package and
  auto-update channel. Its absence does not block the explicitly unsigned Good Bear 1.0 public release,
  provided each asset has the declared SHA-256, SBOM, provenance, source offer, legal notices, and
  Russian verification instruction; it remains a blocker for any claim of signing or auto-update.
- Build-time policy: development builds, focused tests, and intermediate milestone/package
  candidates use the non-LTO configuration. Full link-time optimization is run once only in the
  final release task, after all code changes and ordinary verification are green; it consumes the
  complete accumulated change set and is followed by the final installed-artifact smoke. For the
  explicitly approved Firefox 155 M15 source-freeze path, M15-10 does not create a standalone
  non-LTO package candidate: its source/test gates feed directly into the one M13-06 LTO build.
  No task may introduce an additional full-LTO pass unless a maintainer explicitly approves an
  exception.
- Live-site smoke may use `https://fstec.ru/` only as mutable manual evidence; automated tests use
  local PKI fixtures and never depend on a government site.
- The public repository contains Good Bear patches and reproducible-build inputs, not a complete
  copy of Firefox source. The Russian README begins with direct versioned links to the Ubuntu `.deb`
  and Windows x64 installer in the GitHub Release, followed by their SHA-256 checksums.
- Remote builders are untrusted as source authorities: they receive only an immutable, checksummed
  source snapshot and approved public build inputs; build credentials, GitHub release credentials,
  private signing keys, browser profiles, and unpublished local artifacts never travel to them.
  A failed or interrupted remote run is quarantined and cannot replace a reviewed local artifact.
- A Windows Server 2025 builder is a build/test host, not a new binary distribution target. Ubuntu
  and Windows release artifacts retain their existing declared target boundaries.

## Milestone 1: Repository, upstream, version, and Ubuntu baseline

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M1-01` | Pin the stable Firefox/Gecko baseline. | Select the exact current stable desktop source revision, release channel, source URL, signature/hash, and security-support basis from Mozilla. High reasoning is required because a wrong baseline changes the security model, patch owners, and release viability. | GPT-5.6 (tier selected at execution) | High | One immutable upstream revision and verified source provenance drive checkout/build; no floating branch or mirror is accepted; the supported rebase boundary is explicit in machine-readable build metadata. |
| `GB100-M1-02` | Establish the Good Bear source and patch layout. | Create a rebase-friendly split between pristine upstream source, Good Bear-owned code/assets, ordered patches, tests, build tooling, and artifacts. | GPT-5.6 (tier selected at execution) | High | A clean upstream checkout plus ordered Good Bear inputs reproduces the working tree; generated/build outputs remain ignored; focused bootstrap validation succeeds. |
| `GB100-M1-03` | Set Good Bear 1.0 product and build identities. | Apply version, display name, release locale `ru`, channel, package, executable, desktop, and update/crash identity decisions without blindly changing compatibility-sensitive application IDs. High reasoning is required because identity changes can break profiles, localization, updates, sandboxing, and trademark separation across many owners. | GPT-5.6 (tier selected at execution) | High | All selected identities are internally consistent, public surfaces say Good Bear in Russian UI, compatibility-sensitive IDs have explicit tested dispositions, the package starts with locale `ru`, no separate English build is produced, and no release build presents itself as official Firefox. |
| `GB100-M1-04` | Audit direct dependencies and toolchain currency. | Inventory runtime, compiler, Rust, Node, Python, build, test, packaging, browser/driver, and release dependencies from authoritative upstream sources. | GPT-5.6 (tier selected at execution) | High | Every supported direct component has current pin/floor, latest stable candidate, source, license/provenance impact, compatibility evidence, and update/non-update disposition. |
| `GB100-M1-05` | Apply compatible stable component updates. | Update every supported newer stable component and regenerate pins, locks, vendored outputs, archives, checksums, and focused compatibility checks. | GPT-5.6 (tier selected at execution) | High | All safe stable updates land with deterministic verification; each non-update has evidence, owner, review/expiry date, and a same-backlog follow-up dependency; no floating unverified range remains. |
| `GB100-M1-06` | Pin the Ubuntu LTS amd64 Russian build/test environment. | Select the maintained Ubuntu LTS target and reproducible compiler, linker, SDK, package-tool, `ru` localization inputs, `ru_RU.UTF-8` test locale, timezone, and container/VM inputs. | GPT-5.6 (tier selected at execution) | High | Clean bootstrap and a minimal Russian-localized upstream browser build succeed in the pinned environment; first launch is Russian, no separate English/multilingual candidate is produced, host leakage is detected, and Ubuntu is the only Linux distribution platform claimed by 1.0. |

## Milestone 2: Security reconnaissance and executable contracts

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M2-01` | Map the current NSS/PSM verification path. | Trace standard verification, trust-anchor selection, error taxonomy, transport-security result ownership, and the earliest safe secondary-check hook. Extra High reasoning is required because incorrect timing could accept a failed ordinary channel or bypass core TLS validation. | GPT-5.6 (tier selected at execution) | Extra High | Targeted owner paths and focused upstream tests are identified in backlog evidence; executable probes confirm the selected hook sees exact failure causes before application data is released. |
| `GB100-M2-02` | Map container and navigation ownership. | Trace `OriginAttributes.userContextId`, built-in contextual identities, top-level channel creation, redirects, session restore, and `window.open`. Extra High reasoning is required because routing at the wrong layer can leak state or create a cosmetic rather than real container. | GPT-5.6 (tier selected at execution) | Extra High | Executable probes demonstrate where the real container identity enters channel/storage keys and where navigation can be cancelled/recreated without body, referrer, or opener transfer. |
| `GB100-M2-03` | Audit credential, Private Browsing, and early-data partitioning. | Determine actual upstream behavior for password/autofill, HTTP auth, TLS client auth, connection reuse, 0-RTT, service workers, caches, and `privateBrowsingId + userContextId`. Extra High reasoning is required because undocumented global caches can silently cross the intended boundary. | GPT-5.6 (tier selected at execution) | Extra High | Focused probes classify every listed state as partitioned, disabled, or requiring a Good Bear guard; unknown cases fail closed and receive an implementation/test owner. |
| `GB100-M2-04` | Define the typed trust-domain data flow. | Establish one C++ source of truth for `Standard`, `RussianPKI`, and `Invalid`, including transport exposure, lifetime, serialization boundaries, and rebase guards. High reasoning is required because duplicated or stale trust classification would let routing and UI disagree about security state. | GPT-5.6 (tier selected at execution) | High | One normalized type/API owns classification; UI contains no issuer-string inference; compile-time/contract tests fail on missing states, unsafe defaults, or owner drift. |
| `GB100-M2-05` | Build the executable invariant and PKI fixture matrix. | Create local Standard/Test Russian roots, intermediate/leaf fixtures, negative variants, and a machine-readable T01-T25 mapping to concrete test owners. | GPT-5.6 (tier selected at execution) | High | Fixtures cover exact anchor, same-name fake root, hostname, expiry, bad signature, EKU/constraints/path, missing intermediate, state isolation, routing, persistence, and early data without any live-site dependency. |

## Milestone 3: Production certificate supply chain

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M3-01` | Establish official certificate provenance and redistribution disposition. | Retrieve current root/intermediate metadata only from an official source, validate exact identities, and choose bundled bytes or controlled import based on verified redistribution rights. High reasoning is required because technical authenticity and legal redistribution are independent release-critical decisions. | GPT-5.6 (tier selected at execution) | High | Official source, retrieval time, SHA-256 certificate/SPKI hashes, serial, subject, validity, role, and redistribution evidence are recorded; ambiguous rights select the non-bundled fail-safe workflow. |
| `GB100-M3-02` | Implement the Russian PKI manifest contract. | Add a versioned machine-readable schema supporting multiple explicit anchors and separate intermediates without string-based trust. | GPT-5.6 (tier selected at execution) | High | Schema validation rejects missing/duplicate identities, role confusion, malformed hashes, expired policy metadata, and any intermediate declared as a root. |
| `GB100-M3-03` | Implement deterministic certificate acquisition/import. | Build an official-source retrieval or bundled-input path with TLS/source checks, exact byte pinning, quarantine, atomic promotion, and offline rebuild behavior. | GPT-5.6 (tier selected at execution) | High | Hash mismatch, source drift, partial download, wrong role, and unavailable network fail before compilation; verified cached inputs are reusable and runtime browsing performs no certificate download. |
| `GB100-M3-04` | Enforce build-time tamper and rotation tests. | Verify DER-to-manifest consistency, certificate parsing, role/basic constraints, multiple-anchor rotation, removal, and production/test trust separation. | GPT-5.6 (tier selected at execution) | High | Build and tests fail on byte replacement, same-name fake root, intermediate promotion, manifest drift, unreviewed new anchor, or test anchor leakage into production. |
| `GB100-M3-05` | Expand reviewed Russian PKI issuer coverage. | Enumerate currently deployed candidate issuing certificates from public certificate-transparency and live-chain observations, then accept a candidate only after retrieval from its official source, exact source-byte/DER/SPKI pinning, CA and path validation to an already approved exact root, quarantine, and reviewed manifest promotion. Extra High reasoning is required because this task expands production trust inputs and must distinguish discovery evidence from authorization to trust. | GPT-5.6 (tier selected at execution) | Extra High | Every supported deployed chain ends at an existing exact root and has an explicit pinned intermediate; every candidate lacking an official source, exact identity, valid role/path, or approved root is rejected. No new root, string-based recognition, global trust, runtime download, or claim of exhaustive Internet coverage is introduced. |

## Milestone 4: Scoped trust-domain verification

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M4-01` | Implement the normalized trust-domain type. | Add the single typed enum/result and safe defaults used by verifier, transport, routing, logging, and UI. | GPT-5.6 (tier selected at execution) | High | Unknown/uninitialized maps to fail-closed `Invalid`; callers cannot invent parallel boolean/string classifiers; focused compile/unit tests pass. |
| `GB100-M4-02` | Implement standard-first ordinary classification. | Run secondary Russian PKI validation only for narrowly eligible standard trust-anchor failures and classify without accepting the ordinary channel. Extra High reasoning is required because accepting or resuming the original channel could send ordinary state under alternate trust. | GPT-5.6 (tier selected at execution) | Extra High | STANDARD success returns immediately; eligible alternate success yields only `RUSSIAN_PKI_REQUIRED`; the ordinary channel remains unusable and original non-eligible errors are preserved. |
| `GB100-M4-03` | Implement container-scoped Russian PKI acceptance. | Allow the exact Russian anchor only when the channel has the dedicated container's real origin attributes. Extra High reasoning is required because any scope confusion would globalize trust. | GPT-5.6 (tier selected at execution) | Extra High | The same valid Russian chain succeeds in the dedicated container and fails normally elsewhere; disablement and missing/recreated-container cases never fall back to ordinary trust. |
| `GB100-M4-04` | Preserve complete X.509/TLS validation. | Reuse upstream path building and enforce hostname, time, signature, EKU/KU, constraints, path length, algorithms, and intermediate rules in the alternate trust domain. Extra High reasoning is required because a partial reimplementation could create silent universal exceptions. | GPT-5.6 (tier selected at execution) | Extra High | Every negative fixture remains a TLS error; only the permitted exact anchor differs from STANDARD; no custom crypto or browser-JS certificate verification exists. |
| `GB100-M4-05` | Expose trust results and bound performance. | Carry immutable trust state through transport security info to routing/UI, add safe caching where valid, and instrument secondary-check frequency. | GPT-5.6 (tier selected at execution) | High | Routing/UI consume the same result; successful STANDARD traffic performs no secondary path; stale/cross-origin results are impossible; performance regression thresholds and tests pass. |

## Milestone 5: Built-in container and persistent assignment

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M5-01` | Create the managed Russian PKI container. | Add stable internal purpose `goodbear-russian-pki` using native Firefox container infrastructure and safe create/repair behavior. | GPT-5.6 (tier selected at execution) | High | The container has a real stable `userContextId`, cannot be replaced by color/pref/window emulation, and is recreated safely when support is enabled and user-visible state was removed. |
| `GB100-M5-02` | Implement enable/disable fail-closed behavior. | Wire the feature preference so disablement removes all Russian PKI trust applicability without deleting or leaking unrelated profile state. High reasoning is required because a disable-path defect could leave hidden global trust active. | GPT-5.6 (tier selected at execution) | High | Disabled mode matches upstream Firefox trust behavior in every context; assignments do not grant trust; reenabling restores only the dedicated scoped path. |
| `GB100-M5-03` | Persist exact-origin assignments. | Store local routing metadata keyed by scheme, host, and effective port with schema/version validation and reset operations. | GPT-5.6 (tier selected at execution) | High | Assignments survive restart, do not sync, contain no credentials/cookies, do not automatically cover subdomains, and corrupt entries fail closed. |
| `GB100-M5-04` | Route known origins directly and keep tabs sticky. | Start known origins in the dedicated container before ordinary network traffic and preserve that context through STANDARD navigation and child tabs. | GPT-5.6 (tier selected at execution) | High | Known origin visits avoid ordinary requests where the platform permits; same-tab and default `window.open` flows retain `userContextId`; STANDARD destinations never auto-move back. |
| `GB100-M5-05` | Preserve container identity across restore and Private Browsing decisions. | Restore tabs with the correct origin attributes and either prove combined private/container isolation or block Russian PKI in Private Browsing. | GPT-5.6 (tier selected at execution) | High | Restart/session restore retains the correct container; no private path globalizes trust or state; unsupported private behavior shows a safe recovery path to a non-private Russian PKI container. |

## Milestone 6: Safe navigation, redirects, and subresources

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M6-01` | Stop unknown Russian PKI navigation before ordinary application data. | Coordinate certificate classification, channel suspension/cancellation, speculative/preconnect behavior, and application-data release. Extra High reasoning is required because timing errors can leak cookies/headers/body before routing knows the trust domain. | GPT-5.6 (tier selected at execution) | Extra High | Tests prove no ordinary HTTP application data or early data reaches a subsequently classified Russian PKI connection; uncertain timing fails closed. |
| `GB100-M6-02` | Reopen eligible GET/HEAD navigation safely. | Create an active tab in the managed container and transfer only the destination URL, never state, referrer, opener, form data, or session storage. Extra High reasoning is required because cross-context recreation spans network and browser ownership with privacy-critical semantics. | GPT-5.6 (tier selected at execution) | Extra High | First eligible visit lands in the real container, old technical navigation closes safely, `SEC_ERROR_UNKNOWN_ISSUER` is absent there, and explicit tests prove each forbidden transfer is absent. |
| `GB100-M6-03` | Handle POST/PUT/PATCH and other body methods. | Block automatic replay and show a dedicated choice to open only the address in the Russian PKI container or go back. High reasoning is required because method/body handling spans browser history, channel recreation, and irreversible disclosure risk. | GPT-5.6 (tier selected at execution) | High | Body bytes and body-derived headers are never sent/replayed across the boundary; certificate view is available; cancellation/back navigation is deterministic. |
| `GB100-M6-04` | Enforce redirect boundary semantics. | Classify each redirect hop, strip cross-container referrer/state, and preserve the first valid STANDARD response without sharing its context. High reasoning is required because redirect method rewriting and channel reuse can bypass a superficially correct top-level boundary. | GPT-5.6 (tier selected at execution) | High | STANDARD-to-Russian redirects enter the dedicated container before the Russian request carries ordinary state; loops, method changes, and body-preserving redirects fail safely. |
| `GB100-M6-05` | Enforce subresource and embedded-content policy. | Block Russian PKI scripts/images/CSS/fetch/iframes/media/WebSockets in ordinary pages while allowing STANDARD and valid Russian PKI resources inside the dedicated container. High reasoning is required because resource-type and process/network interactions create many hidden cross-context data paths. | GPT-5.6 (tier selected at execution) | High | No hidden proxy/container response is returned to an ordinary page; ordinary cookies are absent; clear non-sensitive console diagnostics and positive/negative browser tests pass. |

## Milestone 7: Trust history and trust-domain changes

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M7-01` | Persist minimal observed trust history. | Store origin-scoped last confirmed domain and transition metadata without leaf fingerprints, credentials, telemetry, or Sync. | GPT-5.6 (tier selected at execution) | High | History survives restart, validates its schema, contains only routing/trust metadata, and cannot itself grant certificate trust. |
| `GB100-M7-02` | Complete first-visit Russian PKI assignment. | Auto-route an unknown origin only after complete alternate validation and atomically record the assignment/history. | GPT-5.6 (tier selected at execution) | High | GET/HEAD first visit routes once, no partial assignment survives failure, and optional informational UI does not imply general safety or endorsement. |
| `GB100-M7-03` | Block STANDARD-to-Russian PKI transitions pending consent. | Detect prior STANDARD success, present a blocking trust-source change decision, and assign only after explicit isolated-open confirmation. Extra High reasoning is required because silent continuation could expose state to a newly different trust domain. | GPT-5.6 (tier selected at execution) | Extra High | No ordinary data is sent before the decision; Back preserves prior state; confirm opens isolated without body/referrer/opener and records the new assignment atomically. |
| `GB100-M7-04` | Keep Russian assignment through later STANDARD chains and support reset. | Continue routing assigned origins into the dedicated container until the user removes one/all assignments. | GPT-5.6 (tier selected at execution) | High | `RUSSIAN_PKI -> STANDARD` never auto-returns ordinary; one/all reset works atomically; the next visit is freshly classified with no stale trust decision. |

## Milestone 8: Browser-state, credential, and early-data isolation

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M8-01` | Prove cookies and origin-storage separation. | Test bidirectional separation for cookies, localStorage, IndexedDB, origin storage, and Cache API using the selected upstream's real container keys. | GPT-5.6 (tier selected at execution) | High | Ordinary and Russian container identities cannot read or mutate each other's state; every unsupported/global store is guarded or explicitly disabled. |
| `GB100-M8-02` | Prove service-worker and cache isolation. | Test registration, control, update, interception, and cached response ownership across the boundary. | GPT-5.6 (tier selected at execution) | High | An ordinary service worker never controls Russian-container clients and vice versa; restart and eviction paths retain isolation. |
| `GB100-M8-03` | Isolate password manager and autofill. | Disable ordinary saved-login suggestions, password saving, address autofill, and payment autofill unless container-aware separation is positively proven. Extra High reasoning is required because silent global credential reuse would defeat the primary privacy boundary. | GPT-5.6 (tier selected at execution) | Extra High | Same-origin ordinary credentials never appear in the Russian container; no mixed global store write occurs; UI truthfully reports disabled behavior and recovery. |
| `GB100-M8-04` | Isolate HTTP auth, TLS client auth, and connection state. | Partition or disable reuse of Basic/Digest credentials, client-cert decisions, connection-auth state, and relevant caches. Extra High reasoning is required because these privileged caches may live outside normal web storage partitioning. | GPT-5.6 (tier selected at execution) | Extra High | Bidirectional adversarial tests prove no automatic credential/client-auth reuse; unsupported caches force reauthentication or fail closed. |
| `GB100-M8-05` | Enforce 0-RTT and connection-reuse invariants. | Disable early data globally or for unknown/assigned domains and prevent unsafe coalescing/reuse across trust/container identity. Extra High reasoning is required because leaked early HTTP data precedes the very classification meant to protect it. | GPT-5.6 (tier selected at execution) | Extra High | T25 proves no ordinary cookies, headers, or body leave as early data; resumption/coalescing keys cannot cross the boundary; performance optimization never weakens isolation. |

## Milestone 9: Security UI, settings, localization, and diagnostics

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M9-01` | Implement independent container and certificate indicators. | Keep a persistent neutral container marker separate from the `RUSSIAN_PKI` certificate badge. | GPT-5.6 (tier selected at execution) | High | Normal+STANDARD shows neither special state; container+Russian shows both; container+STANDARD keeps only the container marker; icon shape, accessible name, and text/tooltip work without color. |
| `GB100-M9-02` | Implement the Russian PKI security popup. | Show connection status, hostname, leaf/issuer/root, exact trust source, scoped-anchor explanation, and certificate viewer action from immutable verifier data. | GPT-5.6 (tier selected at execution) | High | Popup never infers from strings, never says the site/browser is generally safe/certified, and exposes verified chain details with keyboard/screen-reader support. |
| `GB100-M9-03` | Implement trust-change, body, and failure surfaces. | Add blocking `STANDARD -> RUSSIAN_PKI` and body-request interstitials while preserving standard Firefox errors for invalid chains. | GPT-5.6 (tier selected at execution) | High | Required Russian actions and messages, Back, certificate viewing, focus order, reload/history behavior, and fail-closed error mapping pass browser tests in the shipped `ru` build. |
| `GB100-M9-04` | Implement Russian PKI settings and assignment management. | Add enable/disable state, assigned-origin list, single/all reset, and honest credential-isolation state. | GPT-5.6 (tier selected at execution) | High | Settings cannot globalize trust, validate origins, confirm destructive clear-all, expose no credentials, and update live/restart behavior consistently. |
| `GB100-M9-05` | Complete Russian Fluent localization and accessibility/theme coverage. | Add idiomatic Russian Good Bear strings through normal Fluent ownership while retaining only upstream-required `en-US` source/fallback inputs; verify keyboard, screen reader, zoom, light/dark, high contrast, and non-color states. | GPT-5.6 (tier selected at execution) | High | No Good Bear UI string is hard-coded in JS/C++; the shipped `ru` locale is complete and is the startup locale; no separate English/multilingual package is generated; missing-variable and accessibility tests pass. |
| `GB100-M9-06` | Add privacy-safe diagnostics. | Provide dev-pref/log-module events for verification, routing, and trust transitions without sensitive data. | GPT-5.6 (tier selected at execution) | High | Logs include actionable phase/result identifiers but never passwords, cookies, form/body data, auth headers, private keys, or full browsing history; disabled release logging is quiet. |

## Milestone 10: Branding, licensing, and public-identity gates

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M10-01` | Build a machine-readable branding/provenance inventory. | Classify user-visible assets/strings as product marks, neutral UI, legal attribution, technical identifiers, or third-party materials and enforce status with tests. | GPT-5.6 (tier selected at execution) | High | Inventory covers app/package/About/onboarding/error/update/launcher assets without treating a grep result as a decision; prohibited public identity fails the release build. |
| `GB100-M10-02` | Produce three original Good Bear visual-branding candidates for maintainer selection. | Create three independently original visual systems centred on a kind, intelligent bear in modern glasses: primary mark, monochrome icon direction, welcome/onboarding pose, and illustrative style. The bear may be broadly sturdy in build, but must not be a portrait or claim likeness. Public photographs of Valery Ledovskoy may be used only as a reference after he explicitly confirms the exact source images; record their source and usage basis. Do not reuse, trace, recolour, or compose from Firefox/Mozilla art. | GPT-5.6 (tier selected at execution) | High | Exactly three clearly distinct candidates are presented with rights/provenance records and light/dark/16px legibility samples; no candidate enters a release artifact until Valery Ledovskoy explicitly selects one; no government symbol or security-state claim appears in mascot artwork. |
| `GB100-M10-03` | Build the approved Good Bear mascot and artwork system. | After the maintainer selects one M10-02 candidate, create the original Good Bear mascot master and state set: logo/icon, neutral/welcome, thinking/setup, concerned/generic-error, success, devices/sync, backup/restore, empty-state, and first-run animation frames. Replace every audited Firefox-specific fox/logo/animation surface with the approved corresponding Good Bear asset; retain neutral functional UI icons. | GPT-5.6 (tier selected at execution) | High | Every replaced asset is mapped to an audited upstream surface, has documented authorship/license and required Ubuntu sizes, and is visually independent of Firefox; the bear remains product identity only, never certificate/trust-state evidence; first-run animation and all audited mascot contexts use Good Bear artwork. |
| `GB100-M10-04` | Complete Good Bear product rebranding. | Replace public Firefox/Mozilla product identity with Good Bear using the M10-03 approved asset system, while preserving descriptive upstream attribution, source identifiers, licenses, and required notices. High reasoning is required because broad rebranding can unlawfully erase provenance or break deep compatibility identifiers. | GPT-5.6 (tier selected at execution) | High | Display name, executable/package/desktop surfaces use Good Bear; no Firefox logo, fox mascot, modified Firefox artwork, or Mozilla product identity remains on audited public surfaces; upstream legal/technical strings remain where required; compatibility tests pass. |
| `GB100-M10-05` | Implement approved asset injection and placeholder blocking. | Provide clean, build-validated slots for the selected original icon/logo/mascot/animation/badge sizes and allow obvious development placeholders only in non-release builds. | GPT-5.6 (tier selected at execution) | High | Release build requires approved ownership/license metadata, the selected M10-02 variant ID, full Ubuntu icon sizes, and all required mascot/animation assets; placeholder, Firefox-derived, unapproved, or incomplete artwork hard-fails; mascot and security-state resources remain separate. |
| `GB100-M10-06` | Implement About/Legal, non-affiliation, and author-link surfaces. | Bundle required MPL/third-party notices and Good Bear, Mozilla, and Russian-government non-affiliation copy as product UI/package artifacts. In the About window, replace all four public links with Russian labels and these exact targets: `Статьи автора на Хабре` → `https://habr.com/ru/users/Goudron/articles/`; `Поддержать автора` → `https://boosty.to/goodbear`; `Пригласить автора на работу` → `https://hh.ru/resume/08072c72ff0c8e15930039ed1f73616e327262`; `Другие открытые проекты автора` → `https://github.com/Goudron`. | GPT-5.6 (tier selected at execution) | High | Notices are reachable in the installed browser/package, preserve upstream rights, claim no Mozilla/government endorsement or GOST/SKZI certification, and pass string/legal-surface contracts; the four About links have exactly the prescribed Russian visible labels and HTTPS targets, with no Mozilla project/donation links remaining on that surface. |
| `GB100-M10-07` | Enforce source-availability and third-party release inventory. | Generate component/asset provenance, licenses, modification status, certificate disposition, and corresponding-source offer inputs from the build graph. High reasoning is required because omissions can make binary redistribution non-compliant even when code works. | GPT-5.6 (tier selected at execution) | High | Every Good Bear addition, including selected mascot/animation assets, has owner/license/source/redistribution status; MPL-covered corresponding source/patch revision is exact; unresolved rights block the public artifact. |

## Milestone 11: Automated and manual security evidence

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M11-01` | Complete verifier unit and integration coverage. | Exercise exact anchors, chain building, role separation, all negative X.509 cases, disabled mode, and error preservation. | GPT-5.6 (tier selected at execution) | High | T01, T04-T07, T21-T22 and all constraints/algorithm negatives pass in production-equivalent code paths; test-only roots cannot enter release inputs. |
| `GB100-M11-02` | Complete navigation and trust-history browser coverage. | Exercise first/known visits, sticky tabs, redirects, POST, referrer, opener, subresources, transitions, persistence, and reset. | GPT-5.6 (tier selected at execution) | High | T02-T10, T16-T20, T23-T24 pass with network-level assertions showing forbidden ordinary data was absent. |
| `GB100-M11-03` | Complete storage and credential browser coverage. | Exercise cookies, localStorage, IndexedDB, Cache API, service workers, password/autofill, HTTP auth, client auth, and restarts bidirectionally. | GPT-5.6 (tier selected at execution) | High | T11-T15 plus auth/cache cases prove separation; no test passes merely by checking a UI marker or preference. |
| `GB100-M11-04` | Complete UI, accessibility, Private Browsing, and early-data coverage. | Test state combinations, popup/interstitial/settings behavior, the shipped Russian Fluent locale, themes, safe private behavior, and 0-RTT. | GPT-5.6 (tier selected at execution) | High | Russian startup/locale and accessibility gates pass; no separate English build is emitted; T25 has packet/server evidence; Private Browsing is either proven isolated or predictably blocked. |
| `GB100-M11-05` | Run affected upstream regressions, performance gates, and live smoke. | Run targeted NSS/PSM/network/container/browser suites, verify STANDARD fast path, then run the opt-in `tools/run_m11_fstec_live_russian_pki.py` check against FSTEC from a fresh profile; it is not an offline build dependency. | GPT-5.6 (tier selected at execution) | High | Affected upstream tests are green; secondary validation never runs for successful STANDARD traffic; the live check rejects certificate overrides and proves ordinary first visit → dedicated container → `RussianPKI` native domain → visible `RU`, or records an honest external blocker without weakening local gates. |
| `GB100-M11-06` | Maintain a live Russian PKI regression corpus. | Keep a test-only, deduplicated list of publicly reachable candidate sites; discover broadly from CT/live observations, probe each endpoint at execution time, and retain only results that currently prove a supported exact-root chain and successful isolated-container navigation. | GPT-5.6 (tier selected at execution) | High | The corpus records endpoint, observation time, leaf/intermediate/root fingerprints, ordinary-context failure, and container result; stale or unreachable entries are marked rather than treated as passes. It never alters the production trust manifest, never becomes a runtime allowlist, and does not make external availability a mandatory local test dependency. |

## Milestone 12: Ubuntu LTS amd64 and Windows x64 distribution

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M12-01` | Implement deterministic Ubuntu and Windows release build inputs. | Add clean, pinned, non-networked-after-fetch build phases with real progress, quarantine, atomic artifact promotion, and an explicit non-LTO candidate mode for all intermediate package verification. Pin Ubuntu LTS amd64 and Windows x64 build/VM/toolchain inputs independently. Remote builders may execute builds but never become the source authority. | GPT-5.6 (tier selected at execution) | High | Clean builds produce only declared platform outputs; inputs are hashed; interrupted/failed candidates never replace verified artifacts; progress is flushed and evidence-based; intermediate work does not invoke full LTO; a remote build can be traced to an immutable locally selected source snapshot. |
| `GB100-M12-02` | Build the Russian Good Bear `.deb` and desktop integration. | Package Russian-localized amd64 binaries, sandbox helpers, launcher, MIME/default-browser integration, icons, required `ru` locale resources, notices, and package scripts under Good Bear identity. | GPT-5.6 (tier selected at execution) | High | Package ownership/modes/dependencies are minimal and correct; launcher starts Good Bear in Russian; no separate English/multilingual artifact is present; no public surface identifies the package as official Firefox; lintian-equivalent checks pass. |
| `GB100-M12-03` | Prepare the Russian Good Bear Windows x64 installer and desktop-integration workflow. | Select and pin a reproducible supported Windows NSIS installer format, source-owner inputs, Russian-localized launcher/icons/file associations/default-browser integration, required `ru` resources, notices, Windows media, SDK, and MSVC prerequisites. Do not create an intermediate non-LTO Windows binary: the first Windows candidate is the native full-LTO source-freeze build in M13-06. | GPT-5.6 (tier selected at execution) | High | The Windows workflow is pinned and fails closed until verified media/SDK/MSVC inputs exist; it cannot promote an English/multilingual, Firefox-identified, or invented-trust artifact. The native Windows x64 LTO installer and its manual validation are mandatory M13-06 release gates. |
| `GB100-M12-04` | Verify Ubuntu automatically; prepare Windows lifecycle validation. | Exercise the Ubuntu path on a clean automated target. Preserve the Windows x64 lifecycle checklist—fresh install, normal launch, profile creation, default-browser registration, upgrade, failed-upgrade recovery, and uninstall—for the first native Windows LTO candidate in M13-06. | GPT-5.6 (tier selected at execution) | High | Ubuntu clean-target tests pass. The Windows checklist is not represented as an M12 automated pass; it is a mandatory manual M13-06 release gate. User profiles are not silently deleted and rollback claims remain limited to behavior actually proven per platform. |
| `GB100-M12-05` | Assemble source, SBOM, provenance, notices, and signing metadata. | Produce the exact source/patch set, MPL source offer, third-party inventory, SBOM, build provenance, SHA-256 sums, and Ubuntu/Windows maintainer-signing inputs. | GPT-5.6 (tier selected at execution) | High | Every binary maps to source/upstream/Good Bear revision; hashes verify; missing approved signing authority yields clearly marked local candidates and blocks public release rather than inventing trust. |
| `GB100-M12-06` | Run Ubuntu package security and clean-machine smoke; prepare Windows smoke. | Validate Ubuntu sandbox/hardening, file permissions, no unexpected privileged services/network calls, first run, STANDARD browsing, Russian PKI flow, and uninstall on a clean target. Preserve the equivalent Windows x64 checklist for the native Windows LTO candidate in M13-06. | GPT-5.6 (tier selected at execution) | Extra High | Ubuntu package behavior matches source tests; no Good Bear server/telemetry for assignments/history exists; security failures quarantine the candidate. Windows clean-machine smoke is a mandatory manual M13-06 release gate and no unsupported-platform release claim is emitted. |
| `GB100-M12-07` | Reproduce and compare the Ubuntu candidate; prepare the Windows reproducibility check. | Rebuild the available Ubuntu artifact from the same declared inputs in an independent clean environment and compare normalized artifacts and provenance. Preserve the equivalent Windows x64 reproducibility checklist for the native Windows LTO candidate in M13-06. | GPT-5.6 (tier selected at execution) | High | Reproducibility command reports real progress and exact differences for Ubuntu; byte-identical or explicitly normalized-equivalent Ubuntu outputs pass; any unexplained delta fails and is escalated rather than guessed at. Windows comparison is a mandatory manual M13-06 release gate and no unsupported-platform reproducibility claim is emitted. |

## Milestone 13: Final quality and local release closeout

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M13-01` | Pass maintained format, lint, static-analysis, and compiler-warning gates. | Run the selected upstream and Good Bear code-quality contours and fix in-scope findings. | GPT-5.6 (tier selected at execution) | High | All maintained gates are green with no new suppressions that hide security-sensitive warnings; generated outputs are not hand-edited. |
| `GB100-M13-02` | Pass the complete focused and affected upstream test contour. | Run all Good Bear suites plus selected NSS/PSM/network/container/UI/package regressions from a clean state. | GPT-5.6 (tier selected at execution) | Extra High | Exact commands and results are retained as local release evidence; no skip, flaky retry, fixture weakening, or suite deletion substitutes for a pass. |
| `GB100-M13-03` | Reach 100% declared Good Bear decision coverage. | Measure all new Good Bear-owned code and security decisions, including fail-closed/negative branches; exclude upstream Firefox only by explicit ownership mapping. | GPT-5.6 (tier selected at execution) | Extra High | The declared Good Bear surface is 100% covered; unreachable code is removed or mechanically proven; coverage cannot improve by shrinking fixtures or excluding live code. |
| `GB100-M13-04` | Perform the final adversarial security review. | Attempt to globalize the root, spoof names, bypass TLS errors, leak each state/credential class, replay bodies, cross subresources, reuse early data, and desynchronize UI/routing. Extra High reasoning is required because independent cross-system attack reasoning is the final defense against locally passing but unsafe behavior. | GPT-5.6 (tier selected at execution) | Extra High | Every invariant has a passing attack-oriented test/evidence item; any uncertain result blocks release; the final checklist answers global trust, string detection, hostname/expiry bypass, body replay, cookie transfer, and GOST addition with `NO`. |
| `GB100-M13-05` | Pass final branding, legal, certificate, and artifact gates. | Recheck approved artwork/rights, Mozilla and government separation, certificate provenance/redistribution, MPL source availability, SBOM, installed notices, and the temporary unsigned-distribution disclosure. High reasoning is required because these cross legal, supply-chain, branding, and technical release boundaries requiring a combined review. | GPT-5.6 (tier selected at execution) | High | Every release-blocking item is proven. Until a separately approved signing authority exists, public binaries may be explicitly marked unsigned only if each exact asset has SHA-256, SBOM, provenance, a Russian verification instruction, and no auto-update claim; missing artwork, rights, redistribution basis, source offer, or any of those hash-based controls keeps the artifact non-public and the milestone open. |
| `GB100-M13-06` | Build and record the approved Good Bear 1.0 release on remote builders. | After M13-01–M13-05 pass, freeze the exact locally selected source/patch/config/input revision. Create the Russian Windows x64 installer with full LTO on the pinned native Windows Server builder and perform its manual lifecycle, security, and reproducibility checks. Without any source, patch, configuration, or declared-input change, create the Russian Ubuntu amd64 `.deb` with full LTO on the pinned Ubuntu builder; return unsigned provenance, SHA-256 hashes, logs, SBOM inputs, and artifacts for local review. Extra High reasoning is required because source-freeze integrity, two native release builds, and artifact promotion must agree across independent security and supply-chain gates. | GPT-5.6 (tier selected at execution) | Extra High | Exactly one final full-LTO build per platform is used for the release candidate, both from the same frozen local revision. Any intervening change invalidates both candidates and requires rebuilding both. Each remote workspace is traceable to the immutable source bundle and is quarantined on interruption/failure. Source/patch set, SBOM, provenance, notices, and checksums agree; every distributable is clearly marked unsigned and auto-update remains disabled; the local Git status is clean; approved local commit/tag are recorded; no push, upload, or public release occurs without its separate authorization. |

**M13 closure, 2026-09-30 (maintainer decision).** Milestone 13 is complete as the local
release-closeout milestone. The maintainer accepted the already assembled Russian unsigned
Firefox 156.0 candidates and expressly did not authorize a rebuild: the Ubuntu amd64 `.deb`
is recorded in `artifacts/m13-firefox156-ubuntu-candidate/`, and the Windows x64 installer in
`artifacts/m13-06-windows-candidate/`. Their SHA-256 records, locale `ru`, Good Bear 1.0 /
Firefox 156.0 identity, source/provenance references and the completed local verification
evidence remain the release record. This closure does not turn either local candidate into a
signed or public distribution, does not authorize M14 publication, and does not erase the
candidate records' stated runtime, provenance, or future-release boundaries. Any later source
change, public promotion, signing, updater activation, or new platform build requires its own
reviewed freeze and the applicable verification evidence; it must not be inferred from this
administrative closeout.

## Milestone 14: GitHub publication and release discoverability

Maintainer authorization for the remote actions in this milestone was received on 2026-09-05. It
does not waive any M10-M13 release gate, source-offer, provenance, checksum, or verification
requirement. This is the complete public Good Bear 1.0 release in an explicitly unsigned release
mode: no signing key, MAR, updater endpoint, or auto-update claim is required or permitted. Every
binary must instead be labelled unsigned and paired with its exact SHA-256, SBOM, provenance,
source offer, notices, and Russian verification instruction.

**M14 closure, 2026-09-30.** Milestone 14 is complete. The public release is the sole GitHub
Release `v1.0.0` for Good Bear 1.0 and contains exactly the reviewed eight assets: the Ubuntu
package, Windows installer, SHA-256 list, SBOM, provenance, notices, and source-offer metadata
and bundle. Its tag and public source boundary were independently checked; the pinned Firefox
156.0 source was verified from Mozilla without a Firefox mirror, and all 54 ordered Good Bear
patches applied in a clean clone. The Russian README and source-offer contracts pass. This is a
full unsigned 1.0 release: it makes no signature, MAR, updater, or auto-update claim. The
independent audit directory and all temporary extracted sources were removed after verification.

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M14-01` | Assemble the minimal public corresponding-source repository. | Prepare the exact ordered Good Bear patch set, pinned Firefox source revision/hash, reproducible-build scripts, required build inputs, source-offer metadata, notices, SBOM, provenance, and checksums for `Goudron/good-bear`. Include documented native Windows and Ubuntu paths with platform-specific preflight and recovery. The Windows source patch set must include the complete Good Bear NSIS branding tree and validate all `BRANDING_FILES` through `mozmake -n -C browser/installer/windows instgen/helper.exe` before any LTO; installer-only recovery must not rerun `mach configure` or top-level `mach build`. The Ubuntu path must likewise validate its actual package prerequisites and use a package-only recovery path when source/build configuration is unchanged. Exclude the full Firefox source tree, object directories, caches, profiles, credentials, private keys, local candidates, and unreviewed artifacts. | GPT-5.6 (tier selected at execution) | High | A clean clone contains the declared material needed to fetch the pinned upstream and reproduce both native builds; every patch applies; Windows and Ubuntu preflight/recovery contracts pass before expensive LTO; a machine check rejects Firefox-source copies, build outputs, secrets, and undeclared files. |
| `GB100-M14-02` | Create the Russian GitHub README and release navigation. | Add a Russian-only README. Its first visible section contains direct versioned GitHub Release links to the Ubuntu `.deb` and Windows installer assets, their checksums, and the source-offer entry point. Keep those asset links prominent so the project can record and analyse GitHub Release download counts as aggregate distribution counts, never as unique active users or product telemetry. The README then gives a concise product overview; states that Good Bear is supplied under the free MPL 2.0 license; explains the reviewed differences from Firefox without a Mozilla, certification, or government-endorsement claim; and retains provenance, non-affiliation, Russian PKI safety boundaries, and concise build instructions. It also includes a clearly voluntary project-support link to `https://boosty.to/goodbear`; a donation grants no product capability, endorsement, support entitlement, or licence exception. Its final visible section names the author `Валерий Ледовской`, the maintainer `Анрей Ковалёв`, the contact address `valery@ledovskoy.com`, and the rule that only messages whose subject contains `[GB]` are accepted. | GPT-5.6 (tier selected at execution) | Medium | The rendered README is entirely Russian. Its first visible section has direct versioned links to the exact Ubuntu and Windows release assets, checksums, and source offer; it accurately describes download counts as aggregate release-asset counts only. It contains the required product, MPL 2.0, Firefox-difference, provenance/non-affiliation, Russian PKI, voluntary Boosty link `https://boosty.to/goodbear`, author, maintainer, and `[GB]` contact information; its final visible section preserves the exact named contacts, address, and subject-marker rule. It contains no unsupported-platform, certification, Mozilla or government-endorsement, signing, auto-update, telemetry, unique-user, donation-entitlement, or licence-exception claim; link and content contracts pass. |
| `GB100-M14-03` | Publish the reviewed unsigned Good Bear 1.0 source release and distribution assets. | Push the source offer to `Goudron/good-bear`, create the approved tag and GitHub Release, and upload only the verified Ubuntu `.deb`, Windows installer, checksums, SBOM, provenance, notices, and source-offer bundle. Label both binaries unsigned, link the Russian SHA-256 verification instruction next to them, and make no signing, MAR, updater-endpoint, or auto-update claim. High reasoning is required because irreversible public delivery reconciles authority, exact artifacts, licenses, sensitive-data exclusion, and GitHub state. | GPT-5.6 (tier selected at execution) | High | The public repository and release expose exactly the reviewed 1.0 revision and approved assets; every binary has its exact SHA-256, SBOM, provenance, source offer, visible unsigned disclosure, and Russian verification instruction; direct asset URLs resolve; no full Firefox source, local profile/cache/credential/key, unapproved artifact, signature claim, or auto-update claim is public. |
| `GB100-M14-04` | Verify the published unsigned Good Bear 1.0 release independently. | From a new clone and separate downloads, verify the public tag, README links, hashes, SBOM/provenance links, source-offer contents, unsigned disclosures, Russian verification instructions, and reproducible-build entry point; record any GitHub discrepancy as a publication blocker. | GPT-5.6 (tier selected at execution) | High | Downloads match hashes, both distribution links work, the source script selects the pinned upstream and applies patches without a Firefox mirror, the release visibly identifies both binaries as unsigned, and no signing or auto-update claim appears. |

## Milestone 15: Remote builders, Firefox 155 rebase, RusSpell, and native updates

M15 is a controlled rebaseline of the in-progress 1.0 candidate, not an assertion that the Firefox
154 candidate may be released. Completion of a source-changing M15 task invalidates dependent
M10-M13 evidence and requires the affected gates to be rerun against the new frozen Firefox 155
tree. M14 publication remains last.

**M15-11 continuation, 2026-09-19.** The pinned input is now Firefox 156.0; the `155.0.1 -> 156.0`
leg is active and unfinished. Every dependent gate whose source/configuration changed, including
M15-04/M15-05 migration contracts, M15-10 source-freeze evidence, M15-12 hosted-service checks,
and affected M9/M11/M13 UI/security/release checks, must be reopened for the exact 156.0 inputs.
Do not infer acceptance from source materialization, a version-number replacement, or a prior
155.0.1 pass. The `156 -> 157` leg remains future work subject to its own execution approval.

The separately requested RU/shield check belongs to this M15-11 leg: compare the actual pinned
Firefox 156 address-bar shield assets, dimensions, padding, alignment, hover/focus treatment,
theme/contrast behavior, and accessible interaction with Good Bear's `RU` indicator and its
surrounding native controls. Adapt affected Good Bear owners when verified upstream changes
require it, keeping container identity and certificate trust distinct. Record source-owner
comparison and deterministic `ru` visual evidence at matched viewport/theme/scale; do not claim
that users will see no visual difference until those checks and the manual promotion gate pass.

**Source checkpoint, 2026-09-19 (not milestone or release acceptance).** Mozilla online
freshness, tag and signed-summary checks passed for the pinned Firefox 156.0 input; the local
archive matched both pinned hashes. All 41 ordered patches were applied to a fresh 156.0
worktree. The 20-module focused regression run passed 145 tests; actual materialized-source
checks confirmed 62 product/optional-service preferences and preserved upstream Safe Browsing,
certificate-revocation/Remote Settings and local autofill defaults. The four shield SVGs and
native identity CSS are byte-identical across the pinned 155.0.1/156.0 inputs; visible RU styling
is unchanged, with an added Russian accessible description scoped to native Russian-PKI trust.
Malformed patch hunk counts were corrected, and the materializer now rejects ignored text tails.
Its expanded focused suite passed 12 tests, including five new regressions; all 41 patches and
345 hunks passed the new validation (150 distinct tests across the combined focused checks).
Source/package/update contracts select 156.0 and reject stale 155 evidence. M15-10 explicitly
blocks release while M15-11 visual/manual review or M15-12 security-supplier review is pending.

Continue from the canonical 156.0 worktree via `tools/host_build_context.py`. Remaining evidence
includes the complete Fluent/visual matrix on Russian Ubuntu and Windows binaries, native
security/migration/spellcheck/update/package runs, refreshed decision coverage and builder
provenance. Safe Browsing and certificate protection remain enabled while supplier disposition
is unresolved; neither a disabled security feed nor an unreviewed supplier is release acceptance.
No Firefox 156 binary, native runtime pass, new release freeze or publication is claimed here.

**M13 continuation authorization, 2026-09-19.** The maintainer explicitly instructed continued
execution through M13 completion, using the already authorized Astra subagents, with a full
progress report every three minutes. This authorizes the necessary reopened M15/M10-M12 gates
and M13-01--M13-06 work in dependency order; routine continuation does not require another
task-by-task permission request. It does not mark any acceptance item complete or waive named
manual UI review, frozen-source integrity, supplier disposition, or native runtime evidence.
M14 publication remains governed by its separate authorization and acceptance conditions.

The first complete local Python baseline run covered 86 modules and 521 tests: 488 passed,
25 failed and 8 errored, with no skips. Exact results are retained under
`build/m13-firefox156-local-20260919/`; these are local contract checks, not native Firefox
runtime evidence. Failures include stale 155 toolchain/source-inventory/coverage bindings and
the upstream tabbrowser owner move. Both pinned cloud builders were inspected and stopped;
no 156 remote build has started. The Windows encrypted-source workflow now rejects stale 155
payloads before materialization; its old transport asset pins must be replaced by a newly
verified immutable transport before dispatch.

**Sber compatibility investigation, 2026-09-19.** The maintainer reported that `sberbank.ru`
shows its own missing-Ministry-certificates page in Good Bear while Firefox with the same
approved roots opens it. The current public endpoint supplies the complete approved RSA
chain; a validated TLS connection can still receive the site's `waf / user_blocked` page.
A controlled comparison using the same historical Russian Good Bear 155.0.1 binary and
separate fresh profiles reproduced that page with `GoodBear/155.0.1` and opened the full
`https://www.sberbank.ru/ru/person` page when only the UA product token became
`Firefox/155.0.1`. Both runs remained in the managed container with native trust domain 2;
no certificate override was created. This exposes an implementation gap in the existing
Firefox-UA compatibility contract, not evidence that TLS or container isolation needs a
site exception. Repair the native build identity, add HTTP/DOM UA regression coverage and
rerun the Sber scenario on the actual 156 binary. Historical-155 diagnosis does not close
the 156 runtime or release gates; retain sanitized reproduction evidence under the current
local M13 validation directory.

**Unsigned distribution gate alignment, 2026-09-20 (Moscow).** M13-05/M13-06 and M14
already authorize explicitly unsigned packages with native auto-update disabled and exact
checksums, SBOM, provenance, corresponding source and Russian verification instructions.
The M15-10 matrix now encodes that existing release mode explicitly: each returned platform
artifact needs its own runtime/evidence record proving those controls and negative tamper,
missing-metadata and checksum cases; Ubuntu also proves hash verification before escalation.
The complete signed-MAR test declaration remains recorded as an unaccepted deferred feature,
not as a passed or skipped suite. Enabling updater endpoints or inventing a ready/signing
status rejects this unsigned mode. A future signed-update release still needs separate
approval and all original signed-MAR positive/negative runtime evidence. This policy repair
is not acceptance of any current artifact or closure of M13.

**M13 implementation checkpoint, 2026-09-20 (Moscow).** The 48-patch series passes
strict ordered application against 134 named Firefox 156 source owners. Patches 0044/0046
close reviewed scope-revocation paths at alternate verification, asynchronous result delivery
and connection reuse; Russian-PKI session resumption is refused, including legacy cache
records with the exact alternate root or missing chain metadata in a nondefault context.
The default Standard cache path remains unchanged. Patch 0047 binds certificate details to
the current native verified chain, makes stale-tab/document viewing fail closed and localizes
the container marker independently of TLS. It changes no address-bar shield geometry.
Patch 0048 removes dead About-version selection and makes the 0-RTT fixture require observed
TLS resumption, so a second full handshake cannot masquerade as an early-data test.

The last complete local run had 601 tests: 600 passed and one errored, without skips. The
remaining stale hook assertion was corrected and all seven tests of that module then passed;
this is not a claim that a fresh complete run has passed. Maintained JavaScript fixes pass
the pinned staged linter, and the two LoginManager warnings exactly match pristine 156.
The final full run, materialization hashes and Fluent audit must include the pending M9-03
interstitial, not the earlier source checkpoint. Actual Gecko tests, compiler/static-analysis
results, instrumented decision coverage and both Russian visual/manual matrices remain open.

The Cloud Windows executor currently permits only its bounded whole-VM isolation selftest.
Its 36 local parser/state/order tests pass, but no Windows isolation result is claimed.
Networking can return only after a different boot, verified quiescence and ephemeral-account
cleanup; configure/engine execution remains blocked until exact native selftest/recovery
evidence is bound, and full LTO retains the M13-01--M13-05 prerequisites. The separate manual
selftest workflow verifies the exact source bytes before invoking the executor and collects
only the recovered job's evidence. A new immutable encrypted 156 transport is still required
before dispatch. Neither cloud VM has been started for this checkpoint. Ubuntu access remains
pending the previously requested login and SSH-key path or an alternative connection method.

**Additional runtime and supplier findings, 2026-09-20 (Moscow).** A fresh-profile local
TLS 1.3 experiment on the historical 155 binary confirmed a Standard-trust regression:
the first request reports Standard, while a genuinely resumed second request reports Invalid
with the same certificate, no TLS error and no certificate override. The local server also
confirms resumption. The temporary test CA exists only in that disposable profile and is not
a Russian trust anchor. Patch 0050 must preserve an explicit typed trust result through cache
serialization, cloning and restoration; legacy untyped records require a fresh handshake,
and Russian-PKI sessions remain excluded. This is diagnostic evidence, not a 156 runtime pass.

The supplier audit found no configured Google Safe Browsing API key in any of the six build
configurations. Native SafeBrowsing code clears list-update/gethash URLs for the missing-key
sentinel, so enabled protection preferences alone cannot prove working protection. Supplier
eligibility, a project-owned key and actual update/privacy/failure evidence remain required;
no Firefox key is borrowed. The maintainer has been asked for an existing supplier/key-file
reference or the intended commercial-use constraint. The maintainer confirmed MPL 2.0,
no planned commercial use and no existing supplier or key. This establishes product intent,
not a provider account or runtime acceptance. Official Google documentation permits
noncommercial Safe Browsing use and requires a project-owned API key; its v4 API is deprecated.
The pinned Firefox 156 source already enables and prioritizes its native google5 provider,
so a speculative protocol rewrite or fallback to v4 is unnecessary. Account/API activation,
key provisioning, applicable service terms and real provider responses remain unresolved.
The maintainer then explicitly authorized the agent to perform Google Cloud/Safe Browsing
setup with assisted account access and requested Firefox for authentication. Official
Google Cloud CLI 585.0.0 was downloaded from the linked Google archive, checked against
its published SHA256 and installed outside the repository; OAuth completed through Firefox.
Project creation initially required the maintainer to accept Cloud terms. After confirmation,
the agent created `goodbear-sb-20260920`, enabled Safe Browsing and API Keys, and created a key
restricted to `safebrowsing.googleapis.com`; no billing account was linked. The key is stored
outside the repository with mode 0600 and its exact file hash is recorded in
`config/m15-12-safebrowsing-build-input.json`. A real v5 hash-list request returned HTTP 200
with the key and HTTP 403 without it; sanitized responses are represented by hashes in
`build/m13-firefox156-local-20260919/safebrowsing-api-readiness.json`. This proves supplier
API access only, not native browser updates, warning behavior or download reputation.
Account credentials remain outside source and transport inputs. This authorization permits
setup, not a claim that supplier integration or runtime protection already passes.
The signed certificate-revocation feed
is `security-state/cert-revocations`; the former contract label `crlite-filters` was stale.
Its corrected native-owner audit and positive/negative contract checks pass all 22 tests.
Neither this metadata repair nor the supplier audit authorizes a release.

**Current M13 source/tooling checkpoint, 2026-09-20 (Moscow).** All 50 patches
now pass strict application against 140 named Firefox 156 owners and are materialized in
the canonical worktree. Patch 0049 supplies the tab-bound Russian-PKI interstitial and
fail-closed body/navigation handling; patch 0050 carries an explicit typed Standard/Invalid
result through session-cache serialization and restoration. Russian-PKI and legacy untyped
cache entries require a fresh handshake. These changes supersede the earlier 48-patch
checkpoint; they do not yet have Firefox 156 native runtime acceptance.

Pinned clang-format passes all 35 changed C/C++ owners. Strict `mach lint --warnings`
returns exit 1 with zero errors: four rule warnings and one ignored preprocessed-pref file
exactly reproduce on pristine Firefox 156. New findings are zero, but the strict gate is
not recorded as green and no suppressions were introduced. The final Fluent audit checks
173 messages and 154 actual bindings without findings; this does not substitute for the
Ubuntu/Windows visual and manual RU/shield matrices. Decision coverage remains unmeasured.

The restricted project-owned Safe Browsing key is integrated as an explicit external build
input in the Ubuntu caller; 55 focused helper/context/caller tests pass. Each mach phase
revalidates the key, supplier contract and effective mozconfig; repack-only requires a
successful base-package receipt bound to those inputs. Source/transport manifests carry
only public input hashes, and source/log scanning rejects API key bytes. Native browser
updates, warnings, freshness, download reputation and supplier acceptance remain pending.
A bounded supplier audit is checking notice/API-v5 behavior before the next source freeze.

Ubuntu access is now verified using the maintainer-provided SSH key and the Cloud API's
recorded login. The VM is Ubuntu 24.04.4, four CPUs and approximately 32 GiB RAM, with
120.6 GB free at preflight; SSH and noninteractive sudo work. Docker is absent, so an
isolated development engine route still needs preparation. Existing workspaces are retained.
The VM is stopped after bounded preflight work. Windows native selftest/recovery binding
and private-input integration are still in progress. Neither a new 156 remote engine nor
a Russian release artifact has been built. M13 remains open; full LTO, final freeze,
manual acceptance and publication are not implied by this checkpoint.

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M15-01` | Establish the local-authority and remote-builder transport contract. | Implement a reviewable transfer workflow from the local Good Bear source authority to disposable Ubuntu and Windows Server 2025 workspaces: exact upstream revision, ordered patch set, declared public inputs, source-bundle hash, build invocation, log/artifact return, quarantine, and atomic local promotion. Exclude profiles, caches, GitHub tokens, private keys, and unpublished artifacts. | GPT-5.6 (tier selected at execution) | High | A dry run proves that each remote command derives from one locally created manifest and immutable source bundle; tampering, a mismatched hash, an undeclared input, failed copy, or interrupted build fails before promotion; credentials cannot enter source bundles or logs. |
| `GB100-M15-02` | Pin and validate the Ubuntu remote builder. | Configure the maintainer-provided four-vCPU/16-GiB Ubuntu VM through the existing host-build context, pin OS/toolchain/locales/package inputs, confirm SSD workspace capacity, and execute the smallest Russian Firefox build and smoke test remotely. | GPT-5.6 (tier selected at execution) | High | The host is identified by a recorded non-secret fingerprint and declared OS/toolchain versions; `ru_RU.UTF-8` and the sole shipped `ru` locale work; build outputs, hashes, and logs return to the local authority; no host-specific path or credential is committed. |
| `GB100-M15-03` | Prepare, import, pin, and validate the headless API-managed Cloud.ru Windows Server 2025 remote builder. | From the official Windows Server 2025 Evaluation ISO, create a local KVM/`virt-install` VM using a RAW VirtIO disk and VirtIO SCSI/network drivers. Use a versioned `autounattend.xml` plus signed/hashed VirtIO and bootstrap inputs to install unattended: locale, OpenSSH or WinRM, Cloudbase-Init, current Windows updates, and the build-user access path; no graphical click-through is a normal dependency. Generalize with `sysprep /oobe /generalize /shutdown`, upload the powered-off RAW disk as a Cloud.ru user image, and retain serial/VNC console only as an audited recovery mechanism. **Maintainer decision, 2026-09-14:** after the local workflow exposed and corrected a scheduled-task serialization defect, do not repeat the full local Windows Update/SDK/VirtIO/Sysprep acceptance run; local KVM is only the reproducible RAW-preparation transport. The Cloud.ru builder is the sole end-to-end acceptance environment and must prove every runtime gate below. Define an API/IaC control-plane contract against the official Cloud.ru API: externally supplied, outside-the-repository API-endpoint and authentication-secret references, non-secret project/region/image/flavor identifiers, and idempotent create, inspect, start, stop, and delete operations for only the uniquely tagged Good Bear Windows builder. Create the maintainer-authorized parity builder from that image with four vCPUs, 16 GiB RAM, 250 GB SSD workspace storage, declared network/subnet and least-privilege security group, attached public IP, and SSH/WinRM access restricted to approved maintainer source ranges; provision the isolated build workspace and M15-01 remote transport. Pin Visual Studio Build Tools/MSVC, Windows SDK, Rust, Python, Node, NASM, and packaging tools. Add a fail-closed cost/lifecycle guard: inspect before mutation, reject an untagged or unexpected resource, stop/delete after an unsuccessful or completed run under the declared retention policy, and require explicit recorded authorization before any retention exception. Record non-secret VM/image/network/security-group/public-IP identifiers, lifecycle actions, cost guard decisions, toolchain versions, source-bundle hash, and returned artifact/log hashes in local inventory; redact/reject credentials, tokens, passwords, and private keys. Manual maintainer action is allowed only for unavoidable Cloud account/billing/quota or secret provisioning, Windows Evaluation activation, and provider console recovery when no documented API/IaC path exists; routine image/VM lifecycle and remote build control remain headless API/IaC operations. | GPT-5.6 (tier selected at execution) | High | The local RAW preparation is unattended and reproducible: its answer-file, bootstrap, configuration-ISO and input hashes are recorded; no local desktop/GUI acceptance is required. Cloud.ru boots the imported image with working VirtIO disk/network, Cloudbase-Init, and restricted remote SSH/WinRM access. An offline contract test proves idempotent inspect/create/start/stop/delete planning, rejects missing external endpoint/secret references, untagged or mismatched resources, broad ingress, missing public-IP/remote-access configuration, and a lifecycle action that could exceed the cost/retention guard; it makes no Cloud API call and logs no credential. The source RAW is retained locally only until Cloud boot is proven and contains no Good Bear source, build output, credentials, or private key. The Evaluation expiry/activation state is recorded and blocks work after expiry. A minimal native Russian build and package-smoke pass on the Server host; toolchain versions, non-secret inventory, returned artifact/log hashes, and source-bundle hash are recorded; produced artifacts target Windows x64 rather than Windows Server only; no local VM/object directory is treated as a release input. |

**M15-03 direct-cloud execution override (2026-09-14).** The available provider Marketplace
image `wind-2022-dc-evo-prod` replaces the unavailable Server 2025 user-image route. Create the
same tagged 4-vCPU/16-GiB/250-GB-SSD builder directly through the documented `POST /api/v1.1/vms`
API in `ru.AZ-2`. **Maintainer transport decision, 2026-09-14:** the image's externally published
WinRM endpoint closes connections before HTTP/TLS despite verified local listeners, exact `/32`
security-group rules, and a valid bootstrap; raw SSH is closed before its protocol banner as well.
Use a GitHub self-hosted runner registered through one-time VNC recovery and maintained solely by
outbound HTTPS. The security group exposes no public ingress, including RDP, SSH, and WinRM; the
runner is limited to explicitly reviewed manual workflows and no pull-request-triggered workflow
may target it. Direct API creation, headless provisioning and native Windows build smoke are
mandatory; a local Windows VM, RAW image, VirtIO-media staging, Sysprep and image upload are not.
The Windows Server 2022 host is solely a build host and never expands Good Bear's Windows x64
distribution claim.

**Обязательное правило VNC Cloud.ru (2026-09-24).** Для builder-а M15-03 VNC открывается
только по ранее проверенной уникальной ссылке web-консоли Cloud.ru, без промежуточного входа
в Cloud.ru ID, в Chromium на экране `eDP-1` (не на `HDMI-1`). Прямой VNC WebSocket, Remmina,
локальный TCP/WebSocket-proxy и любые иные клиенты запрещены; они не должны запрашивать,
сохранять или выводить console URL, токены либо учётные данные. Визуальный recovery и
настройка self-hosted runner выполняются только в этой web-консоли.

**Обязательное правило управления облачными VM (2026-09-15).** Любая Good Bear builder-VM
включается только непосредственно перед подтверждённой работой (сборкой, проверкой, передачей
артефактов или recovery) и должна быть остановлена сразу после успешного либо неуспешного
прогона, а также на время ожидания ручного действия или внешнего ресурса. Перед остановкой
необходимо проверить, что журналы и нужные артефакты сохранены или возвращены; остановка не
равна удалению диска или VM. Перед каждой мутацией обязательна проверка точной tagged-идентичности
ресурса и фактического состояния. Исключение из этого правила допускается только при явно
записанном решении maintainer с причиной и сроком хранения включённой VM.

**Обязательное правило preflight удалённого builder-а (2026-09-15).** До передачи большого
source bundle и до materialize/build для каждого нового либо очищенного remote workspace план
обязан явно зафиксировать и выполнить: проверку точной VM/образа и свободного места, установку
закреплённых системных пакетов, установку и криптографическую проверку закреплённого toolchain,
проверку `ru_RU.UTF-8`, отдельную M3-04-проверку PKI и минимальный build-context probe. Только
после успешного preflight допускаются передача bundle, materialize и создание objdir. Отсутствие
любой bootstrap-команды в immutable transport plan является блокером, а не поводом выполнить
ручную установку вне плана. Повторный прогон после изменения plan получает новый manifest,
workspace и objdir; неполные workspace удаляются после сохранения журнала причины.

| `GB100-M15-04` | Pin the Firefox 155 source baseline, migration delta, and dual-version contract. | Obtain the exact current supported Firefox 155.x desktop release source, signature/hash, source revision, and security-support disposition from Mozilla; compare the Firefox 154 baseline only through targeted owners of Good Bear patches, build files, localization, branding, PSM/NSS, containers, and updater. Define the ordered Good Bear-product/Firefox-base version pair in machine-readable build metadata and the canonical Russian About form `Good Bear <версия Good Bear> (Firefox <точная версия Firefox>)`. Extra High reasoning is required because a bad rebase or version boundary could silently discard a security fix, misapply trust-routing code, or offer an unsafe update. | GPT-5.6 (tier selected at execution) | Extra High | Machine-readable metadata pins one immutable 155.x source input and verifies its Mozilla provenance; every candidate/provenance/SBOM/source offer carries both versions; About shows the exact same pair; every Good Bear patch has an owner/disposition; unsupported or ambiguous upstream changes block migration rather than being force-applied. |
| `GB100-M15-05` | Rebase Good Bear patches and executable security contracts onto Firefox 155. | Reapply/rewrite the ordered Good Bear patch series on the pinned Firefox 155 tree, preserving scoped Russian-PKI verification, real-container routing, isolation, Russian UI, product branding, and rebase guards. Extra High reasoning is required because this crosses security-sensitive browser owners and upstream behavioral changes. | GPT-5.6 (tier selected at execution) | Extra High | A clean Firefox 155 checkout plus the updated ordered patches reproduces the working tree; targeted compile and existing Good Bear negative/positive contracts pass; no Firefox 154 compatibility shim, string-based trust inference, or weakened fail-closed behavior remains. |
| `GB100-M15-06` | Import the pinned RusSpell dictionary as Good Bear's Russian primary dictionary. | Import RusSpell Lab's validated Mozilla-compatible `ru.dic` and `ru.aff` from its selected immutable release (currently 1.0.8, commit `a8561a2d8ca6cb294e5bb663d618602d5b3ec7a8`) through Good Bear's rebase-friendly input/patch layout; retain MPL-2.0 provenance, hashes, author attribution, and update procedure. | GPT-5.6 (tier selected at execution) | High | The release build contains exactly the pinned RusSpell bytes or a later explicitly reviewed immutable RusSpell release; license/notice and source mapping are present; a packaging test rejects substitution, missing `.aff`, unknown release metadata, or a second competing Russian primary dictionary. |
| `GB100-M15-07` | Enable Russian and English spell checking by default. | Configure the Russian RusSpell dictionary as the Good Bear default for Russian editing contexts, retain the standard English dictionary for English contexts, and turn on browser spell checking in a fresh profile without overriding a user's later language choice. | GPT-5.6 (tier selected at execution) | High | Fresh Russian Good Bear profiles enable spell checking; Russian and English controlled misspellings are marked using their respective bundled dictionaries; correct words are not marked; selection behavior follows content language/user choice and never downloads a dictionary at runtime. |
| `GB100-M15-08` | Design the native signed application-update channel. | Adapt Firefox Application Update rather than building a custom updater: define Good Bear product/channel/build identity and the ordered Good Bear-product/Firefox-base version pair, HTTPS update metadata, complete MAR first, signature chain/rotation, rollout/rollback behavior, error UX, telemetry/privacy boundary, and GitHub Releases artifact mapping. Extra High reasoning is required because a flawed update trust chain can remotely compromise every installed browser. | GPT-5.6 (tier selected at execution) | Extra High | The design is encoded as versioned build/update configuration and executable contracts; update eligibility compares both declared versions under an explicit monotonic policy; unsigned, wrong-product, wrong-channel, replayed, downgraded, modified, mismatched-Firefox-base, or mismatched-platform updates are rejected; no private signing material is committed; lack of an approved update-signing authority blocks public auto-update. |
| `GB100-M15-09` | Implement GitHub-backed Windows update delivery and the interim Ubuntu terminal update path. | Produce and validate signed Windows complete MARs and immutable GitHub Release assets/metadata compatible with Firefox's native update checker. Until a Good Bear APT repository on a maintainer-controlled domain is separately approved, Ubuntu UI may only report availability and copy/show one version-pinned terminal command that downloads the exact GitHub Release `.deb`, verifies its published SHA-256 file, and invokes `sudo apt install` on the verified local file. | GPT-5.6 (tier selected at execution) | Extra High | A clean Windows x64 installation checks the declared endpoint, verifies signed metadata/MAR, stages and applies an allowed update, and rolls back on injected failure; GitHub API/release failure is non-fatal and fails closed. The generated Ubuntu command has no floating `latest` URL, refuses missing/mismatched checksum or download failure before `sudo`, preserves dpkg ownership, and is tested in a clean Ubuntu target. No update check leaks browsing/profile data beyond declared update fields. |
| `GB100-M15-09a` | Prepare the inactive Good Bear metrics UI and download-count foundation. | Keep all Firefox/Mozilla telemetry disabled. Add only a visible Good Bear telemetry placeholder with its user setting enabled by default but clearly marked unavailable until a separately approved collector is implemented. The placeholder must create no identifier, queue, DNS lookup, connection, request, or fallback endpoint; turning it off remains durable. For M15, collect only GitHub Release distribution download counts through a reproducible maintainer-side snapshot/dashboard input contract. Future active-installation DAU/WAU/MAU requires a separate task covering a Good Bear-controlled HTTPS collector, schema, retention, privacy notice, and security review. | GPT-5.6 (tier selected at execution) | High | Fresh and restarted profiles make zero product-metrics network requests regardless of the placeholder preference. The UI cannot represent the inactive placeholder as live telemetry. Tests reject any telemetry endpoint, queue, identifier, DNS/network API, Mozilla/partner fallback, or dashboard claim that downloads are unique active users. The download snapshot records release/version/platform asset counts and remains independently reproducible. |
| `GB100-M15-10` | Verify migration, dictionary, and updater gates before the release freeze. | Run targeted upstream and Good Bear tests on Firefox 155, including profile migration from the 154 candidate, Russian PKI/container scenarios, RusSpell Russian/English checks, updater negative paths, and Ubuntu package ownership. Do not create a standalone non-LTO package candidate for this approved source-freeze path: after these source/test gates pass, rerun M13-01--M13-05 and obtain the independent remote Ubuntu/Windows artifact hash and provenance evidence exactly once from M13-06's full-LTO builds. Extra High reasoning is required because the combined migration security and supply-chain review must challenge apparently passing paths. | GPT-5.6 (tier selected at execution) | Extra High | Migration preserves supported profile data without widening trust or container state; all declared Good Bear decision branches remain covered; M15-10 produces no releasable binary; exactly one frozen local manifest is used by both M13-06 LTO builders; any platform-specific discrepancy or updater security uncertainty blocks M13/M14. |
| `GB100-M15-11` | Run the upstream UI watch and regression gate for Firefox 155 -> 156 -> 157. | Before each approved rebase, pin the exact Firefox 155/156/157 source revision, release artifact URL, signature/hash, retrieval time, and Mozilla release/security provenance; compare only the relevant upstream owner sets for browser UI, Good Bear branding, Fluent/l10n, and security UI. Treat Project Nova and any equivalent upstream UI architecture, styling, component, accessibility, or localization change as elevated-risk: produce an owner-attributed diff disposition; audit all affected Fluent message IDs, attributes, selectors, access keys, Russian translations, and fallback exposure; and run deterministic visual screenshot/regression checks for every Good Bear surface (container marker, Russian PKI trust indicator, security popup, trust-change/body interstitials, settings, assignment management, About, updater/error UX, and installer/launcher entry points where applicable). For the active 155.0.1 -> 156.0 leg, separately compare the address-bar RU indicator and native shield geometry, spacing, alignment, hover/focus, themes, contrast, and accessibility against the exact pinned Firefox 156 owners. Extra High reasoning is required because a UI rebase can conceal a security-state regression, misbrand the product, or replace reviewed Russian security copy. | GPT-5.6 (tier selected at execution) | Extra High | The watch record contains immutable upstream pins/provenance and an explicit UI/branding/l10n/security owner disposition for every 155 -> 156 and 156 -> 157 delta. Fluent audit and baseline-versus-candidate screenshot/regression output cover all Good Bear surfaces at declared viewport, theme, scale, locale `ru`, and accessibility states; unexplained visual or string drift fails closed. No upstream UI patch, Project Nova adaptation, generated screenshot-baseline update, or localization change is promoted unattended: a named maintainer records manual Russian UI verification, exact candidate/build hashes, browser/platform matrix, observed evidence references, and an explicit promotion decision. Missing, ambiguous, or unverified evidence blocks the rebase and M13/M14 promotion. |
| `GB100-M15-12` | Establish and enforce the hosted-service boundary. | Audit all Firefox 155 networked product features and encode an allowlisted machine-readable disposition for every endpoint and remote-config collection. Disable and remove the public entry points for Firefox Account/Sync, Firefox Relay, Firefox Monitor, Pocket/Discovery Stream, sponsored and online suggestions, Mozilla VPN/IP Protection, Normandy/Shield experiments, telemetry/Glean submission, crash-report upload, Mozilla system-add-on/dictionary discovery and automatic add-on update. Keep only local screenshots, bookmarks, passwords, containers, tracking protection, and local history. For web push, automatic DoH/ODoH, geolocation provider, translation/model download, extension installation/update, Safe Browsing, CRLite/OneCRL, and Remote Settings security collections, declare either a user-configured path or a separately pinned, auditable security supplier; do not silently retain a Mozilla/partner default. Extra High reasoning is required because a blanket switch-off can regress certificate revocation, anti-phishing, or other protections, while an unnoticed hosted endpoint breaks the product's privacy and provenance promise. | GPT-5.6 (tier selected at execution) | Extra High | Fresh profiles contain no account, Sync, Relay, Monitor, Pocket, VPN/IP Protection, experiment, sponsored-content, telemetry, crash-upload, Mozilla dictionary-download, automatic add-on-update, or unclassified Mozilla/partner hosted-service surface; outbound-request contracts reject their endpoints. Security feeds remain enabled only when their supplier, signatures, update semantics, privacy boundary, and failure mode are explicitly recorded and tested. The policy is re-run by M15-04/M15-05 and every later upstream rebase; newly introduced service endpoints fail closed. |

## Milestone 16: Reproducible Firefox version-upgrade playbooks

| ID | Task | Essence | Model | Minimal reasoning | Acceptance |
| --- | --- | --- | --- | --- | --- |
| `GB100-M16-01` | Create native version-upgrade build playbooks, starting with Firefox 157. | Create maintained, executable Windows and Ubuntu playbooks for each new Firefox base: pin and verify source/provenance, apply the ordered Good Bear patch set, check Good Bear branding and Russian l10n inputs, run platform-specific prerequisite and exact package-target preflights, perform native full-LTO build, verify artifacts, and record provenance. Include a recovery decision tree that preserves a successful objdir: installer/package-only repairs run the exact downstream target without `mach configure` or top-level build; source/configuration changes explicitly require a fresh full-LTO build. Windows preflight must enumerate the selected branding's complete NSIS `BRANDING_FILES`, verify the pinned `7zz.exe`, and pass `mozmake -n -C browser/installer/windows instgen/helper.exe`; the exact single-locale RU path must prove `default.locale == ru` and a `*.ru.win64.*` candidate before promotion. Ubuntu must validate its actual package prerequisites before LTO. | GPT-5.6 (tier selected at execution) | High | A clean supported Windows or Ubuntu host can follow the same versioned playbook for Firefox 157 without manual file discovery; both playbooks fail before LTO for a missing tool, branding input, l10n anchor, or package prerequisite; injected installer/package failure demonstrates downstream recovery without relinking `xul.dll`; version pins, logs, artifact hashes, SBOM/provenance inputs and Russian runtime checks are recorded. |

## Suggested execution order

Execute strictly by milestone and task ID unless a task's acceptance explicitly proves that a later
task is independent. M1 and M2 gate all source modifications. M3 gates production Russian trust.
M4 gates routing acceptance. M5-M8 gate UI and release packaging. M9-M11 gate distribution. M12
gates final quality. M15 is the approved Firefox 155/remote-builder rebaseline and must run before
any new M13 release freeze; M15-11 is the required Firefox 155 -> 156 -> 157 UI watch gate.
Its approved `155.0.1 -> 156.0` leg is currently unfinished and reopens every gate whose inputs
changed before the rebase may advance. The `156 -> 157` leg remains future work. M13 closes the candidate on
the remote builders only with all required new evidence green. M14 publishes only that approved
candidate and its corresponding source inputs.

Long-running Firefox builds and test suites must expose flushed real-work progress in their own
stdout. While any such process is active, the maintainer receives an uninterrupted full structured
report at least every three minutes: current state, completed and active concrete objects, control
signals, free-space/resource state, and a recalculated ETA in minutes with a percentage margin.
Partial candidates remain quarantined and promotion is atomic.

## Execution protocol

1. Show exactly one next task with ID, essence, acceptance, model, and minimal reasoning.
2. Obtain explicit maintainer approval if it has not already been given. The 2026-09-19 instruction
   already authorizes continuation of the current M15-11 leg, its RU/shield check, the dependent
   reopened gates, and execution through M13 completion as recorded above.
3. Execute only the approved task through a focused GPT-5.6 subagent. Before starting, select
   `gpt-5.6-luna`, `gpt-5.6-terra`, or `gpt-5.6-sol` using the 2026-09-23 policy and record the
   selection with the task start; it must meet the row's reasoning level. The current continuation
   explicitly permits parallel subagents for bounded, independent parts of that task. A task may
   not silently use another family or lower its reasoning requirement.
4. The primary agent reports task start, meaningful phase transitions, material blockers, and final
   verification; raw command streams remain opt-in.
5. Run the narrowest focused validation first, then the task/milestone gate.
6. Every command expected to exceed one minute emits flushed real progress from the command itself;
   do not replace it with guessed percentages or chat timers.
7. Do not add a remote, push, publish, upload, sign with an unapproved key, or create a public
   release without separate explicit approval. M14 remote actions are authorized by the maintainer
   on 2026-09-05, subject to its acceptance gates.
8. Do not start implementation merely because this backlog exists.

## Backlog creation acceptance

- Target `1.0`, date, epic ID `GB100`, critical risk, scope, assumptions, and non-goals are explicit.
- Ubuntu LTS amd64 `.deb` and Windows x64 installer with shipped locale `ru` are the only
  distribution targets; no separate English or multilingual Good Bear build is planned, and no
  claim of support for another Debian-based Linux distribution is made without dedicated evidence.
- Every task belongs to the GPT-5.6 family, has one allowed reasoning level, and records the exact
  GPT-5.6 subagent type when execution begins.
- Security/release work preserves High or Extra High minima and task-specific risk rationales;
  the model change does not lower the evidence required.
- First milestone pins Firefox, identities, current dependencies, stable updates, and Ubuntu
  toolchain.
- Security reconnaissance precedes NSS/PSM/routing modification and becomes executable evidence.
- Exact anchor provenance, role separation, redistribution, tamper checks, and rotation are covered.
- STANDARD priority, scoped trust, routing, history, storage/credential isolation, body/referrer/
  opener boundaries, subresources, 0-RTT, and Private Browsing have fail-closed tests.
- UI separates product/container/certificate semantics and provides complete accessible Russian
  copy in the shipped build.
- Branding, Mozilla/government non-affiliation, MPL source, notices, SBOM, artwork, and signing gates
  block public release when unresolved.
- Final quality includes affected upstream regressions, 100% Good Bear decision coverage,
  adversarial security review, clean Ubuntu and Windows package smoke, and reproducibility.
- No changelog, release-note, docs-site, PDF, docs-index, user-manual, architecture-document, or
  threat-model-document work is included. The sole exception is the Russian M14 `README.md` for
  source-offer and release navigation.
- Task execution requires explicit approval and exact model/reasoning selection; the current
  continuation's independent subagents stay within M15-11 and its explicitly requested checks.
- The public GitHub repository is limited to Good Bear patches, reproducible-build inputs, a
  Russian README, and approved release assets; M14 remote delivery is explicitly authorized but
  remains gated on all local release evidence.
