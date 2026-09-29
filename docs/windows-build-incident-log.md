# Windows build incident log

This log records repeatable failures discovered on the native Windows builder.
It contains no credentials, private source contents, console URLs, or product
artifacts. A release candidate is never accepted on the basis of an entry here.

## 2026-09-29 — preflight before a native Windows full-LTO build

**Failure.** Several expensive Firefox 156 Windows build attempts reached
late configuration or packaging boundaries before discovering an incomplete
execution environment. In particular, NSIS was installed but omitted from the
effective build `PATH`; configure therefore did not generate the Windows
installer subtree and the later Russian multi-locale packaging target failed.

**Root cause.** Tool paths and isolated executable probes were checked, but
the exact environment used by `mach` was not exercised end-to-end before the
full-LTO build was armed. A late packaging failure then required another
long link cycle merely to reach the next validation point.

**Permanent guard.** Before every fresh Windows full-LTO build, preserve the
main objdir and run a disposable, separate-objdir preflight using the exact
`MOZCONFIG`, `PATH`, Visual Studio wrapper, locale base, and tool versions
that the real build will use. The preflight must pass all of the following:

- tool and path matrix: Python, Clang/LLD, Rust/Cargo, Node, NASM, Git,
  mozmake, WASI SDK, cbindgen, NSIS/makensis, and the Windows SDK resource
  compiler;
- the WASI C++ wrapper must select the `wasm32-wasip1/noeh` libc++ headers
  before the C headers and its matching `noeh` libc++/libc++abi library
  directory; merely finding the SDK root is insufficient;
- `mach configure` in the disposable objdir, with generated
  `browser/installer/windows` and NSIS Makefiles present;
- Russian locale inputs and generated locale paths; and
- a non-mutating `mozmake -n` dry-run of the installer graph in the configured
  main objdir.

The real full-LTO job may start only after one timestamped preflight report
records every check as passed. A failed preflight is repaired and rerun before
any compilation; it must never be discovered by another multi-hour build.

**Acceptance rule.** A successful compiler or linker invocation alone is not
evidence that the Windows release is buildable. The release requires a passed
four-part preflight, a successful package step, and the normal runtime and
localization checks.

## 2026-09-27 — Rust LLVM/LLD version selection during direct Windows builds

**Failure.** The first direct Windows launcher used Rust 1.90 (LLVM 20.1.8)
with the Firefox 156 Clang 22.1.8 toolchain. Its default linker rejected LLVM
22 bitcode; forcing LLD 22 moved the failure to Rust's own LLVM 20 reader,
which then failed to enumerate C++ LTO members and reported false undefined
symbols from `glslopt`.

**Root cause.** Firefox 156's release branch uses Rust 1.97.0, whose LLVM is
22.1.6. The provisioned Rust 1.90 was an obsolete build input. In addition,
setting `MOZ_CARGO_WRAP_LD` only in the outer launcher is insufficient because
nested Cargo execution can receive a different linker environment.

**Permanent guard.** The materialized Windows build wrapper
`build/cargo-linker` pins its Windows linker to the installed LLVM 22.1.8
`lld-link.exe`, using forward-slash form because the wrapper's argument splitter
would otherwise treat backslashes as escapes. The direct launcher uses Rust
1.97.0 and clears the prior Cargo target directory before a resumed build. It
must record `rustc -vV` (LLVM 22.1.6) and an LLD 22 wrapper self-check first.

## 2026-09-25 — M13 r23 offline-worker recovery

**Failure.** Provisioning the restricted worker's source write-deny ACL failed
after the whole-VM offline transition. The worker never started. A later manual
network restoration removed the owned outbound-deny rule, so the scheduled
recovery task correctly refused to issue a recovery receipt.

**Root cause.** Firefox's source tree contains paths beyond the ordinary Windows
path limit. Recursive `icacls` calls without an extended-length (`\\?\\`) path
can return failure after a partial traversal.

**Permanent guards.**

- All fallible worker provisioning, including source ACLs and native Job Object
  setup, happens before firewall or adapter changes. The account is disabled
  until the VM is confirmed offline.
- Recursive ACL changes for the source root use an extended-length path.
- A self-test is eligible only when a fresh-boot recovery removed the owned deny
  rule and restored every adapter. A job that was manually restored may only be
  cleaned up; it cannot receive a self-test receipt.
- The regression suite covers the provisioning-before-disconnect order and the
  extended-length source ACL calls.

**Acceptance rule.** r23 is invalid. A newly materialized r24 source bundle must
pass a fresh native self-test and recovery before any Windows full-LTO build is
armed.

## 2026-09-25 — M15 encrypted transport hand-off

**Failure.** The Windows materialization workflow initially could not decrypt
the renewed source transport. After the source transport was corrected, it also
rejected the older PKI transport during its source-binding check.

**Root causes.** A text Actions secret can acquire representation differences
at the platform boundary. Separately, a PKI transport is deliberately bound to
the exact source manifest and bundle that existed when it was prepared; a PKI
transport from an earlier source revision must not be reused.

**Permanent guards.**

- Source and PKI passphrases are distinct byte-stable Base64 secrets and are
  decoded directly to their temporary Windows key files.
- The materialization workflow uses a separate key for each encrypted asset.
- Every renewed source bundle receives a newly prepared, encrypted PKI
  transport with matching source-manifest and source-bundle bindings.
- Immutable release assets are pinned by both ciphertext and plaintext hashes.

**Acceptance rule.** Decryption alone is insufficient. Windows materialization
must verify the source and PKI hashes, their mutual bindings, and emit only
source-free evidence before a self-test or build can run.

## 2026-09-25 — r24 source ACL traversal

**Failure.** The renewed r24 self-test again rejected the source write-deny
provisioning step before any network change. The extended-length prefix did not
make recursive `icacls` dependable for the Firefox tree.

**Permanent guard.** The materialization workflow creates the restricted-worker
group and seeds its inheritable read/deny-write ACL on the empty confidential
workspace before extraction. The worker joins that group only after all source
files have inherited the rule. Its designated artifact workspace is then
explicitly detached from that inheritance and made writable.

**Acceptance rule.** No native job may use a recursively retrofitted source
ACL. The next source transport must prove the pre-extraction inherited ACL
route in a fresh self-test.

## 2026-09-25 — r25 offline-worker group provisioning

**Failure.** r25 materialized the encrypted source successfully, but its native
self-test stopped during restricted-worker provisioning before the offline
transition. The required local isolation group was absent, so the worker could
not be added to it.

**Root cause.** The remote materialization workflow had not received the group
seeding step introduced with the r25 source-ACL design. Its prior best-effort
probe also did not prove that group creation persisted.

**Permanent guard.** Workspace preparation now creates the named local group
when absent, re-queries it, resolves its SID, and only then applies the
inheritable group ACL before extraction. Any failure aborts materialization; a
source-free receipt cannot be emitted.

**Acceptance rule.** A fresh materialization followed by a native self-test
must prove the group-backed ACL route before Windows full-LTO is armed.

## 2026-09-25 — Windows source-free evidence UTF-8 BOM

**Observation.** PowerShell's Windows `Set-Content -Encoding utf8` emitted the
source-free materialization receipt with a UTF-8 BOM. A strict UTF-8 JSON reader
rejected the otherwise valid document.

**Permanent guard.** Receipt consumers must parse Windows-generated JSON as
UTF-8 with optional BOM, then compare its complete allowlisted object and hashes.
This concerns only source-free evidence encoding; it does not weaken any
cryptographic transport check.


## 2026-09-25 — r25 artifacts-workspace ACL exception

**Failure.** After group provisioning was corrected, r25 created the temporary
worker but could not grant it write access to its one allowed artifacts workspace.
The parent source tree's group write-deny entry still applied to that child. The
job failed before network isolation and produced no receipt.

**Permanent guard.** The empty artifacts workspace now removes only the exact
offline-worker group allow/deny entries, disables inheritance, and installs a
complete explicit DACL for SYSTEM, Administrators, and the job-specific worker
SID in one operation before the worker is enabled.

**Acceptance rule.** r26 uses a new source and PKI transport and requires a
fresh-boot native self-test receipt before Windows full-LTO can be armed.

## 2026-09-25 — r26 job-stage ACL traversal

**Failure.** r26 reached the newly corrected writable artifacts workspace, then
stopped before the network transition while granting the worker read traversal
to the protected job stage. The preceding source and workspace ACL operations
had succeeded; the descriptor-read operation was never reached.

**Root cause.** A self-test used its first real offline-worker provisioning
attempt as the compatibility probe for every independent Windows ACL boundary.
That made the first unsupported `icacls` operation hide later failures.

**Permanent guard.** `acl-provisioning-preflight` now creates a one-time,
disabled worker and exercises every pre-network ACL mutation in one connected
sequence: inherited source-group access, writable workspace exception, protected
stage traversal, descriptor read, and protected private-input read. It verifies
the resulting ACLs, removes the worker and temporary directories, and never
creates a scheduled task or changes firewall/adapters. The emitted source-free
receipt is bound to the exact source manifest, source bundle, executor/helper
hashes, and VM identity. No self-test or full-LTO arm accepts a missing or
stale receipt.

**Acceptance rule.** r28 must materialize exact source bytes, pass the complete
ACL provisioning preflight, then pass a fresh-boot isolation self-test before
any Windows full-LTO job may be armed.

## 2026-09-25 — r28 ACL preflight descriptor grant

**Failure.** The first complete ACL preflight reached the descriptor-read
operation and rejected its `icacls` grant syntax before any network mutation or
scheduled native job. Its temporary worker and directories were cleaned up and
no receipt was issued.

**Permanent guard.** Descriptor read now uses the explicit replace form with
parenthesized read permission. The ACL preflight is a matrix rather than a
fail-fast chain: after one worker identity is created and disabled, it attempts
workspace, stage, descriptor, and private-input ACL mutations independently,
records every failed boundary, then cleans up. This lets one run report all
currently reachable ACL incompatibilities without escalating to a self-test.

**Acceptance rule.** r29 must pass the matrix preflight for its exact source
and VM binding before any self-test arm is permitted.

## 2026-09-26 — r29 effective frozen-source marker ACL

**Failure.** r29 passed its syntax/effective ACL matrix and completed the
fresh-boot recovery, but the disconnected worker exited with code 1 before its
offline socket probe. Its source-free worker result identified a denied read of
`source/worktrees/firefox-156.0/.good-bear-materialization.json`.

**Root cause.** The materializer moves a staged worktree whose marker can retain
an administrator-only DACL. The initial group ACL on the parent workspace did
not prove a read from the actual worker token after that move. The previous
matrix inspected ACL rules but did not execute the frozen-source read, so it
missed that non-inherited object ACL.

**Permanent guard.** Materialization now reapplies the exact offline-worker
read-only group ACL recursively to the completed worktree. The ACL preflight
also creates a bounded probe under the disabled worker's exact token and Job
Object. It must read the materialization marker, descriptor, and private probe,
and write/read/remove one file in the isolated workspace. The receipt now
includes `worker-io`; any failure prevents both receipt publication and network
mutation.

**Acceptance rule.** r30 must materialize the updated source, pass all six ACL
boundaries on the current VM, and then pass the fresh-boot self-test before any
Windows configuration or full-LTO work is armed.

## 2026-09-26 — r30 encrypted-transport key encoding

**Failure.** r30 downloaded and verified the immutable encrypted assets, then
stopped before source extraction because OpenSSL reported `bad decrypt` for the
source bundle. No source tree was materialized on the Windows VM.

**Root cause.** The release publisher used the base64 text representation of a
random key as the OpenSSL passphrase, while the workflow correctly decodes the
repository secret from base64 and supplies the resulting raw bytes to OpenSSL.
The two passphrase byte sequences differ.

**Permanent guard.** Every encrypted transport release now uses raw random key
bytes for OpenSSL and stores only their base64 representation in the GitHub
secret. Before a release is published, a local round-trip decrypt must produce
the declared plaintext SHA-256 using those raw bytes. The workflow remains
bound to the GitHub asset ciphertext digest and verifies the plaintext digest
before extraction. A new immutable r31 release is required rather than
modifying r30 assets.

**Acceptance rule.** r31 must download, decrypt, verify, and materialize the
same declared source and PKI plaintext; it must then pass the six-boundary ACL
preflight and the fresh-boot self-test before a Windows configuration or
full-LTO job may be armed.

## 2026-09-26 — r31 immutable asset name binding

**Failure.** The first r31 materialization run stopped during encrypted-source
download with HTTP 404, before any decryption or source extraction.

**Root cause.** The release upload retained the local r31 filename while the
workflow URL assumed an asset name supplied after `#` was a rename rather than
a display label. The ciphertext digest and release tag were correct; the asset
path was not.

**Permanent guard.** Before dispatch, the workflow's exact release URLs are
validated with redirect-following HTTP HEAD requests that must finish with 200,
and the release API asset names and SHA-256 digests are compared to the
workflow bindings. Existing immutable assets are reused only when both checks
pass.

**Acceptance rule.** The next materialization run must download the exact r31
asset names, verify ciphertext and plaintext hashes, and reach the worktree ACL
step before any ACL preflight is dispatched.

## 2026-09-26 — r31 lifetime of the offline-worker credential

**Failure.** The r31 materialization and static source/toolchain checks completed, but the six-boundary ACL preflight failed at `worker-io` before it could arm a native build. The failure was initially reported as an ACL-provisioning problem.

**Root cause.** The preflight created the bounded offline worker account and then cleared its temporary password before calling the worker-I/O probe. The probe therefore always launched with an empty credential. It could not validate the worker token and produced a misleading `worker-io` boundary failure; no independent ACL defect was established by that run.

**Permanent guard.** The credential remains in memory only through account creation and completion of the bounded worker-I/O probe. It is cleared immediately after the probe disables the account and before account removal. The focused Windows runner test now records the probe argument and requires it to be nonempty.

**Acceptance rule.** A newly bound r32 source transport must materialize exactly, then pass the complete six-boundary ACL preflight and fresh-boot self-test before any Windows configuration or full-LTO build is armed.

## 2026-09-26 — r32 explicit worker-probe file ACL

**Failure.** r32 materialized successfully and verified its source, pinned toolchains, and M3-04 PKI inputs. Its no-network ACL preflight then failed only at `worker-io`; no native build or network mutation was armed.

**Root cause.** The temporary `worker-acl-probe.py` is created inside an administrator-protected job stage. The worker received `RX` on the stage directory and a separate read grant on `job.json`, but no grant on the probe file itself. The worker process therefore authenticated with the corrected nonempty password yet could not read the script it was asked to run, and exited with code 1.

**Permanent guard.** The preflight grants `RX` to the exact probe file only, checks that effective ACE explicitly, and records `worker-probe` as its own receipt boundary. The offline self-test gate will require the exact seven-boundary receipt rather than merely counting boundaries.

**Acceptance rule.** r33 must bind this source immutably, materialize exactly, pass all seven ACL boundaries, and then complete the fresh-boot isolation self-test before any Windows configuration or full-LTO build is armed.

## 2026-09-26 — r33 opaque worker-I/O exit after probe-file ACL repair

**Failure.** r33 materialized successfully and its seven-boundary ACL preflight again reached `worker-io`, where the contained worker exited with code 1. The exact probe-file `RX` ACE had been granted and verified before the launch; no build or network mutation was armed.

**Root cause status.** The prior missing probe-file ACE was real and fixed, but the probe returned only a boolean exit result. It could not identify whether the contained process failed before script execution or at the marker, descriptor, private-input, or workspace operation. Treating the generic exit as another guessed ACL root cause would be unsound.

**Permanent guard.** The next transport must make the bounded worker probe write a source-free phase result in its existing worker-writable workspace. Preflight must surface that phase (or `launcher-or-script` when no result exists) before cleanup, while retaining the same no-network and no-source-return contract.

**Release correction.** r34 was kept local and was never encrypted, published, or sent to the VM: review found that it computed a worker phase but collapsed it back to generic `worker-io` during exception handling. r35 carries the corrected phase-preserving diagnostic and a focused regression test.

**Acceptance rule.** r35 must materialize exactly and report a phase-resolved worker-I/O result; only a fully passing seven-boundary receipt may arm the fresh-boot self-test. If r35 reports another real boundary failure, r36 will still use one complete immutable transport to validate the repair. Only another new r36 boundary failure authorizes changing later transports to hash-bound delta bundles.

## 2026-09-26 — r35 cross-platform binary passphrase transport mismatch

**Failure.** r35 downloaded and verified both published ciphertext assets. The source bundle decrypted to its exact pinned SHA-256, but the PKI transport decrypted to a different plaintext SHA-256. The run stopped before source-manifest verification, ACL preflight, network mutation, or any build.

**Root cause status.** r36 repeated the failure with random ASCII-hex bytes, so the initial binary-control-byte hypothesis was disproved. The only stable failing boundary is the PKI-specific `base64 secret -> temporary file -> openssl -pass file:` path; the source path succeeds in the same workflow. The exact discarded secrets are intentionally unrecoverable because local key files were deleted after dispatch.

**Permanent guard.** Keep one-time passphrases random ASCII hexadecimal text. For the PKI delta, bind the direct secret's SHA-256 before OpenSSL and pass it as an ASCII `pass:` argument; this removes the failing base64-to-temporary-file path while retaining ciphertext/plaintext round-trip verification before publication.

**Acceptance rule.** r36 rebuilt the complete immutable source and PKI transports and reproduced the PKI-specific failure. Per the agreed escalation rule, r37 is a hash-bound PKI-only delta: it reuses the r36 source ciphertext and its already successful source-secret path, but supplies a new immutable PKI ciphertext plus an exact direct-secret fingerprint check. It must materialize both pinned plaintexts before the phase-resolved seven-boundary ACL preflight can run.

## 2026-09-26 — r37 PKI plaintext hash transcription defect

**Failure.** r35 and r36 both downloaded verified ciphertexts and successfully decrypted the source bundle, but failed the PKI plaintext comparison. r37 added an exact fingerprint check for the direct PKI secret; that check passed, yet the same PKI plaintext comparison failed.

**Root cause.** `GOODBEAR_EXPECTED_PKI_TRANSPORT` in the materialization workflow contained a manually transcribed, incorrect SHA-256 beginning `b0d24b35379018d0…`. The locally verified and encrypted PKI transport hash is `b0d24b35379018d5a7ab585901ce86a9a714e9c6dd405915a5ce3332db894584`. The workflow was faithfully rejecting the correct decrypted file against the wrong expected value.

**Permanent guard.** Before dispatch, compare every workflow plaintext/cipher binding to the just-produced local transport plan and immutable release asset metadata. The r37 direct-secret fingerprint remains as an independent proof that the runner consumed the intended PKI secret.

**Acceptance rule.** Correct the single workflow hash binding and rerun the existing r37 PKI delta. A passing decrypt/manifest/materialization receipt is required before the phase-resolved ACL preflight; no new package is justified by this binding-only repair.

## 2026-09-26 — r37 contained worker fails before probe-script execution

**Failure.** The corrected r37 materialization completed and returned an exact source-free receipt. Its bound ACL preflight then passed source pins, all frozen toolchain checks, M3-04, and all static ACL boundaries, but failed at `worker-io:launcher-or-script`. The worker wrote no phase file; no network mutation, native job arm, or build occurred.

**Root cause status.** The source-free phase probe established that the failure is before Python executes the worker script. The remaining exact native stages are `LogonUserW`, `CreateProcessAsUserW`, Job Object assignment, and thread resume. The previous generic boundary result did not retain the Win32 error needed to distinguish them.

**Permanent guard.** A dedicated no-network launcher diagnostic now reuses the exact materialized source pins and `NativeJob` implementation, creates a disposable constrained worker, and returns only the failing native stage, Win32 last-error code, or contained child exit code. It removes the account and temporary paths in all outcomes.

**Diagnostic correction.** Its first local workflow revision used a 24-character token for the temporary job identifier, while the shared worker-ownership contract requires 32 hexadecimal characters. The next revision still prefixed the stage directory, while the same contract requires its basename to equal that exact identifier. Both receipts stopped before `LogonUserW`; the diagnostic now uses `uuid.uuid4().hex` directly as the stage basename, and local workflow assertions reject either shape error.

**Diagnostic correction (credential parity).** The next launcher-diagnostic
receipt stopped while creating its disposable account, before it reached
`NativeJob.start`. Its workflow had independently generated a 46-character
password, although the production route already uses the Server-Core-compatible
14-character `Gb1!` plus five random bytes-as-hex form. The diagnostic now
uses that exact credential form and the ACL-preflight `gbpre` account-name
prefix (rather than the final-job `gbeng` prefix), so account creation is no
longer a test-only difference.

**Diagnostic correction (failed-phase retention).** The diagnostic installed
operation markers, but its top-level exception handler replaced the marker with
the generic `controller` phase. This concealed the exact failed native call in
three no-network receipts. The handler now retains `failed_phase` separately;
the next receipt must identify the operation even when the native wrapper
appropriately suppresses private command output.

**Diagnostic correction (account lifecycle).** With `failed_phase` retained,
the next receipt identified `account-enable`. The diagnostic had created the
temporary user and skipped the production preflight's required
`disable_account` transition. `enable_account` correctly refused to enable an
already-enabled account. The diagnostic now performs the exact
`create → disable → ACL provision → enable` lifecycle before `NativeJob.start`.
This was a diagnostic-only false failure; it did not run a worker or alter VM
networking.

**Diagnostic correction (probe escaping).** The privilege-free launcher
fallback successfully created the contained process, but the diagnostic probe
wrote literal `\\n` characters into its temporary Python file. Python therefore
reported a `SyntaxError` before executing the marker write. The workflow now
generates physical newline characters and compiles the generated probe locally
before dispatch. This was diagnostic-only; it does not affect the immutable
r37 source or the VM's worker ACLs.

**Acceptance rule.** Run the launcher diagnostic before changing source or packaging again. Repair only the native stage it identifies, then deliver that repair as a hash-bound delta and re-run the existing ACL preflight.

## 2026-09-26 — recovered selftest receipt rejected by an untrusted ancestor owner

**Failure.** The r38 isolation selftest passed its native offline probes, the
worker exited successfully, the ephemeral account and scheduled tasks were
removed, and networking was restored after the reboot.  The SYSTEM recovery
coordinator nevertheless stopped before publishing `recovered-selftest.json`.
The bounded state recorded `coordinator-failed` with no worker or network
failure.

**Root cause.** The private-ACL verifier walked from the protected job stage
all the way to the filesystem root.  A higher source-workspace ancestor has an
owner that is legitimate for ordinary administration but is not a trusted
SYSTEM/Administrators principal.  The verifier therefore rejected that owner
after the job stage had already been independently protected.  The exact
source-free diagnostic confirmed `ancestor-untrusted-owner`; no receipt files
were created.

**Permanent guard.** Before each ACL preflight or native arm, create and seal
`native-offline-jobs` as an inheritance-disabled SYSTEM/Administrators-owned
root.  Receipt ACL verification now proves the target and every ancestor up to
and including that root, then stops.  It rejects a target escaping the root,
any reparse point, untrusted target ACE, or untrusted writable ancestor ACE.
A regression test exercises successful post-reboot receipt publication and
asserts that every receipt ACL check is bounded by this hardened root.

**Acceptance rule.** Ship this as a hash-bound source delta, re-run the
seven-boundary no-network ACL provisioning preflight, then arm and recover a
new isolation selftest.  Only its exact protected receipt can authorize
configure, engine-test, or full-LTO work.

## 2026-09-26 — r39 receipt-ACL hypothesis correction

**Evidence.** r39 sealed the job root and passed the complete seven-boundary
ACL preflight. Its subsequent fresh isolation selftest again completed the
worker probe, account/task removal, reboot, and network restoration, but
stopped before creating either receipt file. The source-free diagnostic then
repeated the ACL check from the job stage through the sealed root and reported
no violation.

**Conclusion.** The earlier `ancestor-untrusted-owner` finding was real for
r38's unbounded scan, and r39 fixed that defect. It was not the remaining
r39 coordinator failure. No further isolation selftest will be armed on that
assumption.

**Permanent guard.** ACL validation now returns one of a fixed set of
non-sensitive reason codes (`trusted-root-escape`, `reparse-point`,
`untrusted-owner`, `untrusted-target-access`,
`untrusted-ancestor-replacement`, or `native-acl-command`) rather than
collapsing an ACL-stage failure into a generic native-administration error.
The next hash-bound delta must first pass the no-network ACL preflight, then a
single fresh selftest will identify or clear the remaining receipt operation.

## 2026-09-26 — r40 trusted-root separator false escape

**Failure.** r40 passed its seven-boundary no-network preflight and its fresh
selftest completed the worker's offline probes, account/task cleanup, reboot,
and network restoration. Receipt publication then stopped with the new safe
reason `trusted-root-escape`; neither receipt file was created.

**Root cause.** The PowerShell embedded by the Python raw string appended two
literal `\` characters when testing whether a job-stage path begins with the
sealed `native-offline-jobs` root. Windows paths contain one separator, so a
legitimate descendant failed the prefix test.

**Permanent guard.** The trusted-root comparison now uses one Windows path
separator for both trim and descendant prefix operations. A focused source test
inspects the generated PowerShell and rejects the two-separator variant. r41
will ship this single-file behavioral repair in the required three-file
hash-bound overlay and must again pass the no-network ACL preflight before one
fresh selftest is armed.

## 2026-09-26 — full-LTO Safe Browsing key encoder overload

**Failure.** The first full-LTO arm validated its selftest reference, source
pins, supplier contract and secret presence, then stopped before a native job
was created. The `finally` cleanup removed the transient key file and cache;
no network transition occurred.

**Root cause.** Windows PowerShell could not resolve
`[Text.ASCIIEncoding]::new($false)` to a constructor overload in this runtime.
The key writer failed before calling the native executor.

**Permanent guard.** The workflow now passes the unambiguous static
`[Text.Encoding]::ASCII` instance to `WriteAllText`, which writes the required
ASCII key bytes without a BOM. The focused workflow-content test rejects the
ambiguous constructor expression. The existing r41 recovered selftest remains
the exact authorization for the retried full-LTO arm.

## 2026-09-26 — full-LTO temporary supplier key ACL boundary

**Failure.** The retry of the full-LTO arm completed exact source, toolchain,
M3-04, seven-boundary ACL, selftest-receipt, and supplier-contract checks,
then stopped before creating a native job with `native Windows ACL verification
failed`. No network or build action occurred.

**Root cause.** The workflow created `safebrowsing.key` inside a new operation
directory, but did not seal that directory before writing the key. The executor
validated the external key with an ACL walk that had no trusted stop boundary,
so it continued past the temporary directory into unrelated parents.

**Permanent guard.** The full-LTO workflow now seals the newly-created empty
operation directory as SYSTEM/Administrators-owned with inheritance disabled
before writing the key. The executor uses an ACL callback bounded by that
directory for the external key and by `native-offline-jobs` for staged inputs
and later configure validation. A regression test asserts sealing precedes key
creation and a unit test asserts the callback carries its explicit boundary.

**Acceptance rule.** Publish this as r42, repeat the no-network ACL preflight
and a fresh reboot-recovery selftest, then retry full-LTO using only that new
receipt.

## 2026-09-26 — r42 overlay partial-apply guard

**Failure.** The first r42 overlay copied the executor replacement, then found
that the workflow had an obsolete expected hash for a later worker file. It
stopped before recording the r42 contract, leaving a valid but mixed r41/r42
source state. No build or network action occurred.

**Root cause.** The overlay checked and copied each replacement in one loop.
A later validation error could therefore occur after an earlier file had been
changed.

**Permanent guard.** r42 first validates the full replacement set and all
current hashes before changing any source file. It accepts an already-present
file only when it exactly equals the r42 replacement, enabling safe recovery
from this interrupted attempt. Replacement copies keep rollback bytes and
verify their hashes; a copy failure restores every backed-up target. A focused
workflow test asserts the complete validation phase occurs before the first
copy.

## 2026-09-26 — FreeRDP automated-input layout corruption

**Failure.** Commands injected through the persistent FreeRDP session changed
`/` to `|` and produced an escaped `^\\` sequence for some literal path
separators. A diagnostic command consequently became `dir |od C:^\\...` and
failed before it could inspect the runner.

**Root cause.** The remote session's keyboard layout did not map `xdotool type`
special characters to the Windows console characters expected by the command.
The runner and network were not implicated.

**Permanent guard.** Automated RDP recovery now reads console text through the
redirected clipboard and avoids path punctuation when possible (`cd ..` and
relative components). It sends only commands verified by captured console
output; no GUI-injected command is assumed to have run merely because it was
sent.

## 2026-09-26 — full-LTO supplier input hash mismatch before native arm

**Failure.** The r42 full-LTO arm verified all frozen source bytes, the pinned
toolchain, M3-04 PKI evidence, and the recovered selftest, then stopped with
`private or frozen input SHA-256 mismatch`. It did not create a native job,
disable networking, or start compilation.

**Root cause under investigation.** The GitHub Safe Browsing secret bytes did
not match the immutable `key_file_sha256` in the frozen supplier contract. A
final CR/LF added during secret entry is a plausible representation difference;
a secret rotation is the alternative.

**Permanent guard.** The full-LTO workflow now accepts only a trailing CR/LF
normalization that reproduces the already pinned contract hash. It neither
logs the secret nor relaxes the exact hash requirement. Any other mismatch
continues to stop before native arm and requires a new explicitly frozen
supplier binding.

## 2026-09-26 — post-reboot runner dequeue and headless access

**Failure.** After a confirmed VM reboot, GitHub reported the Windows runner as
`online` and idle while a freshly dispatched self-test remained queued. The
same VM also accepted TCP connections on port 22 without returning an SSH
banner. This forced an otherwise avoidable recovery through the graphical
console.

**Root cause.** The base bootstrap installed OpenSSH and started `sshd`, but
treated those commands as sufficient evidence. It did not verify the resulting
capability state, automatic service start, or a persistent inbound firewall
rule. Runner registration alone was likewise treated as evidence that the
runner could dequeue a new job after reboot.

**Permanent guards.** The bootstrap now records and verifies that the OpenSSH
Server capability is installed, `sshd` is running with automatic start, and an
owned port-22 firewall rule is enabled. Remote build control will use SSH for
runner-health probes and a bounded service restart watchdog; RDP remains only
an exception for console recovery. A runner is healthy only after it begins a
new dispatched job, not merely when the Actions API says `online`.

## 2026-09-26 — r43/r44 source-overlay closure

**Failure.** The r43 overlay carried the Safe Browsing contract update but the
preflight allowlist still declared only the three native Python files. The
overlay self-test therefore rejected the replacement record before copying
source. No native job or offline transition was started.

**Root cause.** The overlay validator represented the allowed replacement
scope in a second, manually-maintained list. Adding a frozen build-input file
to the overlay changed the actual snapshot without changing that list.

**Permanent guard.** The r44 record is a complete four-file snapshot: the
frozen Safe Browsing contract and all three native implementation files. The
preflight allowlist and its regression fixture enumerate the same four paths,
and the test rejects an incomplete record. An overlay is accepted only after
all expected base hashes are validated before any copy operation.

## 2026-09-26 — r44 overlay passphrase fingerprint normalization

**Failure.** The first r44 overlay attempt downloaded the correct immutable
ciphertext but rejected its key fingerprint before decryption. The GitHub
Secret contained the intended hexadecimal passphrase, while the local
fingerprint had been calculated from the same text plus a trailing newline.

**Permanent guard.** Overlay key fingerprints are calculated from the exact
normalized Secret representation before publication. The workflow writes that
same representation as a temporary key file and checks the declared digest
before it ever invokes decryption. No passphrase value or digest-derived source
material is recorded in evidence.

## 2026-09-26 — direct SSH control path and cloud ingress gap

**Failure.** The Windows builder had an installed OpenSSH service, but the cloud security group did not permit TCP/22 and the bootstrap specification did not make the external ingress rule a required part of the VM contract. Recovery therefore fell back repeatedly to a graphical FreeRDP console and manual command entry after an offline job rebooted.

**Root cause.** Headless access was treated as a guest-only setup concern. The cloud security-group rule, Windows firewall rule, SSH service state, and key-based administrator access were not verified together as one readiness condition.

**Permanent guard.** The direct Windows lifecycle contract now requires TCP/22 in both cloud ingress and the guest firewall, verifies `sshd` is installed, automatic, and running, and uses a controller key in `administrators_authorized_keys`. M13 execution is now armed, observed, and collected through SSH/SFTP; the GitHub Actions runner is disabled for this route. Private supplier input travels only over SSH/SFTP into a one-time ACL-sealed directory, is hash-checked against the frozen contract, staged by the native executor, and deleted from the transfer directory before the offline worker starts.

## 2026-09-27 — direct live executor startup paths

**Failure.** The first direct live Windows executor reached its scheduled task
but stopped before `mach configure`: its Visual Studio environment script path
pointed to `C:\GoodBear\tools\vs-buildtools`, while the installed Build Tools
root is `C:\GoodBear\vs-buildtools`. After that correction, Firefox rejected
the frozen worktree because its canonical source path was 71 characters long;
a junction did not help because Firefox resolves it before applying its
62-character Windows source-path limit.

**Root cause.** The direct executor reused assumptions from the staged-tools
layout and did not preflight the actual Build Tools path or Firefox's source
path limit on the target VM.

**Permanent guard.** Direct Windows startup now tests the exact `VsDevCmd.bat`
path before scheduling a build. When the frozen tree exceeds Firefox's limit,
the controller materializes a fresh worktree directly from the pinned archive
into the short physical root `C:\gbp\source\worktrees\...`; it never moves a
worktree and never uses a junction. The materializer is repeatable, records its
patch series, and runs before normal configure/build/repackage evidence
collection.

## 2026-09-27 — direct executor dependency closure

**Failure.** The first direct `mach configure` runs found components that the
old Actions image had supplied implicitly: `cbindgen`, Windows App SDK, WASI
sysroot and runtime, `windows-rs`, DXC, and `mozmake`. Windows-style backslash
paths in `CC` and `WASM_CXX` were also normalized away by Firefox's configure
parser.

**Root cause.** The direct SSH launcher inherited only part of the historical
worker environment and did not run a complete, target-specific preflight. A
batch wrapper also wrote literal PowerShell newline escapes rather than DOS
line breaks.

**Permanent guard.** The direct preflight now verifies every required binary,
SDK file, runtime archive hash, and the short physical source root before it
schedules Firefox. It installs the pinned Windows dependency set from compact
verified caches, uses forward-slash forms for compiler variables, generates the
WASI wrapper with CRLF line endings, and sets `CBINDGEN`,
`MOZ_WINDOWS_APP_SDK_DIR`, `WASI_SYSROOT`, `WASM_CXX`, `MOZ_WINDOWS_RS_DIR`,
DXC state, `MAKE`, and `GMAKE` explicitly. The actual build begins only after
this closure passes.

## 2026-09-27 — release-input and Clang-plugin preflight gaps

**Failure.** A direct release invocation initially reached the configured
Firefox tree without the sealed private Russian PKI input. A later invocation
then stopped while linking `build/clang-plugin`: the pinned LLVM distributions
on the VM contain the compiler executables and runtime libraries, but not the
development import library `clang.lib` required by that build-time static
analysis plugin. A wrapper mozconfig could not override the source export
because Firefox applies that export later; assigning `0` was also invalid,
because this option takes no value.

**Root cause.** The direct launcher did not treat every private release input
as part of its startup contract, and its compiler preflight tested executable
availability rather than the optional analysis-plugin link dependency.

**Permanent guard.** The scheduler now validates the presence and access of
the sealed PKI directory before `mach configure`. The dependency preflight
distinguishes product requirements from build-time analysis tools: all release
compilers, full-LTO inputs, SDKs, WASI components, DXC, and packaging tools
remain mandatory. When `clang.lib` is not part of the pinned compiler kit,
the worktree materializer removes the `ENABLE_CLANG_PLUGIN` export from the
build-only `build/mozconfig.clang-cl` before configuration. This removes only
the non-shipping static-analysis plugin and preserves the release product and
full-LTO configuration. A future compiler-kit refresh must either provide a
verified compatible `clang.lib` or keep this transformation explicit.

## 2026-09-27 — Rust archive and linker version mismatch

**Failure.** The Rust `whatsys` build produced an object with LLVM 22.1.8,
but Cargo inherited Visual Studio's LLVM 19.1.5 `llvm-lib.exe` after
`VsDevCmd`. That older archiver rejected the object with `Unknown attribute
kind (102)`, and Cargo exited with code 101.

After the archive path was corrected, the `webrender` build script exposed the
same incompatibility in the Cargo linker wrapper: it invoked LLVM 19.1.5
`lld-link` on LLVM 22.1.8 bitcode and failed with the same attribute error.

**Root cause.** The direct launcher selected LLVM 22 for C/C++ compilation,
but allowed `VsDevCmd` to replace the target-specific Cargo `AR` variables and
the `MOZ_CARGO_WRAP_LD` linker wrapper. The preflight verified only the
compiler version, not the compiler, archiver, and linker version coherence.

**Permanent guard.** The launcher now checks the pinned LLVM 22
`llvm-lib.exe` and `lld-link.exe`, then explicitly sets `AR`,
`AR_x86_64_pc_windows_msvc`, `AR_x86_64-pc-windows-msvc`,
`MOZ_CARGO_WRAP_LD`, and `MOZ_CARGO_WRAP_LD_CXX` after `VsDevCmd` for both
configure and build. The preflight treats that compiler, archiver, and linker
as one versioned toolchain.

## 2026-09-27 — Good Bear Windows icon omitted from branding input

**Failure.** The direct release build reached `browser/app/desktop-launcher`
and stopped with `llvm-rc: Error in ICON statement (ID 1): no such file or
directory`. The configured value of `FIREFOX_ICO` was
`browser/branding/goodbear/firefox.ico`; after that file was restored, the
private-browsing proxy exposed the same omission for `PBMODE_ICO`. The Good
Bear branding directory contained only PNG variants.

**Root cause.** The branding overlay supplied image assets for the installer
and Windows shell but omitted the multi-resolution ICO set required by Windows
resource scripts. The previous linker diagnosis was incidental: that stage was
not reached until the missing resources could be compiled.

**Permanent guard.** The Windows release preflight now requires the complete
Firefox branding set (`firefox`, `firefox64`, `pbmode`, `document`,
`document_pdf`, `newtab`, and `newwindow` ICO files), validates each header,
and runs the pinned `llvm-rc` against every generated file before it schedules
`mach build`. The normal icons are generated as multi-size ICOs from the
maintained Good Bear 16/32/48/64/128 PNG assets; `pbmode.ico` is generated
from the maintained private-browsing images. This validates the same resource
compiler used by the build.

## 2026-09-28 — Локализованная Windows-сборка была ошибочно подтверждена без release-gate

**Сбой.** Успешная базовая Windows-сборка Good Bear M13 / Firefox 156.0 оказалась внутренним артефактом `en-US`, а не поставляемой сборкой `ru`: в `dist/bin/default.locale` был `en-US`, а русские каталоги chrome в артефакте отсутствовали. Запуск `mach package-multi-locale --locales ru` после передачи каталога локализации дошёл до упаковки, но завершился ошибкой `mozmake: *** windows: No such file or directory`: в object directory отсутствовал `browser/installer/windows`.

**Ошибка проверки.** Перед запуском LTO была проверена только конфигурация и существование корня l10n. Не были проверены обязательный русский файл-якорь `ru/browser/browser/appmenu.ftl`, фактический результат `default.locale` и наличие русских ресурсов в готовом пакете. Поэтому готовность локализации была подтверждена преждевременно. Это ошибка процесса проверки, а не дефект перевода.

**Дополнительный фактор.** Сокращённые команды упаковки не воспроизводили полное окружение основной сборки: сначала отсутствовали Rust/Cargo, затем `cbindgen`. После восстановления полного окружения `mach build browser/installer/windows` формально завершался успешно, однако требуемый объектный каталог для `package-multi-locale` не появился. Следующая попытка была вынуждена запустить полный инкрементальный `mach build` перед упаковкой.

**Обязательный постоянный gate.** До любого LTO-запуска для Windows:

1. Получать host-build context штатным скриптом проекта и проверять конкретный источник l10n, включая `ru/browser/browser/appmenu.ftl`, а не только корень дерева.
2. Для поставляемой русской сборки планировать `mach package-multi-locale --locales ru`; `mach repackage` не является заменой локализованной упаковки.
3. До заявления об успехе автоматически проверять `dist/bin/default.locale == ru`, наличие русских chrome-ресурсов и созданный пакет `*.ru.win64.*`.
4. До долгой LTO-сборки выполнять preflight точной цепочки упаковки в полном build environment, включая prerequisite для `browser/installer/windows` в object directory.
5. Перед выпуском запускать GUI-проверку: русские меню без пустых строк и корректное открытие панели информации о сайте по щиту в адресной строке.

**Статус исправления.** Русское l10n-дерево с подтверждённым файлом-якорем уже доставлено на ВМ. Текущая инкрементальная сборка восстанавливает недостающие результаты полного окружения перед повторной русской упаковкой; выпуск до прохождения всех перечисленных gate не считается готовым.

## 2026-09-28 — Двухчасовой лимит задания прервал LTO-линковку

**Сбой.** Локальное задание `GoodBear-RuPackageIncremental-20260928` было
остановлено планировщиком Windows ровно через два часа во время LTO-линковки
`xul.dll`. Компилятор и линкер не сообщили ошибку; `lld-link` был завершён до
публикации `dist/bin/xul.dll`, а задача получила результат остановки по лимиту
выполнения.

**Корневая причина.** У одноразового задания упаковки остался стандартный
`ExecutionTimeLimit=PT2H`. Для Firefox full-LTO на ВМ с 16 ГиБ RAM одного
двухчасового окна недостаточно, особенно если полная инкрементальная сборка
предшествует локализованной упаковке.

**Постоянный guard.** Перед запуском долгой Windows-сборки launcher экспортирует
XML задания и явно задаёт `ExecutionTimeLimit=PT23H`; затем повторно читает
настройку и подтверждает состояние `Running`. Мониторинг обязан различать
завершение `lld-link` и завершение задания по лимиту, а при последнем случае
продолжать только после снятия лимита, используя сохранённые object results.

**Статус исправления.** Лимит текущего задания изменён на `PT23H`; инкрементальная
сборка перезапущена с сохранёнными результатами компиляции. До успешной
русской упаковки и runtime-gate выпуск не считается готовым.

## 2026-09-28 — `package-multi-locale` дошёл до ZIP и упал на Windows-стадии

**Сбой.** После успешной full-LTO линковки `xul.dll` задача `GoodBear-RuPackageIncremental-20260928` выполнила jar maker для `ru`, сформировала ZIP, но `mach package-multi-locale --locales ru` завершился с ошибкой `mozmake[3]: *** windows: No such file or directory. Stop.` в `browser/installer`.

**Подтверждённые последствия.** `RU_FINAL_FAILURE` записан в журнал. Артефакт `*.ru.win64.*` не создан; `dist/bin/default.locale` остался `en-US`. LTO не является причиной этого сбоя и не должен перезапускаться ради исправления упаковки.

**Постоянный guard.** Перед следующей дорогой сборкой требуется отдельный preflight точного Windows install-package target в том же objdir и окружении. После каждого package-multi-locale release-gate обязан проверять итоговый пакет, `default.locale == ru` и chrome-ресурсы, прежде чем объявлять выпуск успешным.

## 2026-09-29 — Неполный Good Bear NSIS branding и повторная LTO после installer-fix

**Сбой.** Полная LTO-линковка `xul.dll` завершилась успешно, однако основной
`mach build` остановился на `instgen/helper.exe`: в Good Bear branding не было
`branding.nsi`. После его добавления точный dry-run того же target выявил ещё
шесть отсутствовавших ресурсов мастера NSIS: `stubinstaller/bgstub.jpg`, две
CSS-страницы и три bitmap-файла `wiz*`. Ранее общий `mozmake -n package` не
покрыл эти prerequisites и дал ложное ощущение готовности.

**Дополнительная ошибка процедуры.** Штатный скрипт восстановления всегда
запускал `mach configure`, а затем верхнеуровневый `mach build`. Даже
installer-only изменение после этого invalidated generated build graph и
запустило новую полную LTO-линковку `xul.dll`, хотя прежняя библиотека была
успешно собрана.

**Постоянный guard.** До запуска LTO Windows preflight обязан перечислить
полный `BRANDING_FILES` из `browser/installer/windows/Makefile`, проверить
каждый путь в выбранном branding и выполнить
`mozmake -n -C browser/installer/windows instgen/helper.exe`; только затем
разрешён верхнеуровневый build. Для installer-only исправления после успешной
LTO восстановление обязано запускать точный installer/package target в уже
настроенном objdir, без `mach configure` и без `mach build`. Good Bear
`branding.nsi` и обязательные NSIS-ресурсы должны быть частью исходного
branding-tree, а не создаваться вручную на ВМ.

## 2026-09-29 — `package-multi-locale` не заменяет русскую single-locale поставку

**Сбой процесса.** После успешной full-LTO сборки и исправления отсутствующего
`7zz.exe` команда `mach package-multi-locale --locales ru` завершилась с
`RU_FINAL_SUCCESS`, но создала только
`goodbear-1.0+firefox156.0.en-US.win64.installer.exe` и пакет с `en-US` как
базовой локалью. Это не проходит правило Good Bear: поставляемый Windows
кандидат обязан запускаться с `ru` и не может быть отдельным английским или
multi-locale кандидатом.

**Корневая причина.** Реализация Firefox `package-multi-locale` намеренно
сохраняет базовую конфигурацию и передаёт `MOZ_CHROME_MULTILOCALE`; она не
переключает `AB_CD`/default locale на `ru`. Поэтому успешный exit code этой
команды доказывает упаковку дополнительных ресурсов, но не доказывает
single-locale русскую поставку. Ошибка произошла потому, что имя команды было
принято за удовлетворение release-критерия без проверки финальных свойств.

**Постоянный guard.** Release preflight обязан проверять наличие и запуск
`C:\GoodBear\tools\7zip\7zz.exe`, а post-package gate — фактический
`default.locale == ru`, русский package identity и отсутствие отдельного
`en-US`/multi-locale кандидата. Для single-locale выпуска процедура выбирает
целевой `repackage-single-locales --locales ru` либо эквивалентный штатный
single-locale путь, после точного dry-run его installer target. После
успешной LTO разрешён только downstream locale/package recovery; верхний
`mach build` и повторная линковка `xul.dll` запрещены, пока диагностика не
докажет, что изменён объектный код.

## 2026-09-29 — У инсталлятора оставались Firefox-иконки

**Сбой.** Сформированный Windows installer использовал иконку Firefox. Причин
было две: внешний SFX берётся из `other-licenses/7zstub/firefox`, а внутренний
NSIS `setup.exe` по умолчанию копирует generic
`toolkit/mozapps/installer/windows/nsis/setup.ico`.

**Исправление.** Для Good Bear добавлен отдельный SFX с ресурсами Good Bear и
`browser/branding/goodbear/setup.ico`. Windows packaging-настройка выбирает
этот SFX и передаёт фирменную `setup.ico` в NSIS. При первой реализации
иконка была скопирована в каталог `instgen\\setup.ico\\setup.ico`: параметр
назначения `nsinstall -t` должен быть каталогом `instgen`, а не именем файла.

**Постоянный guard.** До single-locale упаковки preflight обязан проверять
наличие Good Bear SFX и `setup.ico`. После создания `instgen/setup.exe`
проверяются: существование `instgen/setup.ico`, отсутствие вложенного пути
`instgen/setup.ico/setup.ico`, совпадение SHA-256 с branding-иконкой и
VersionInfo `Good Bear Installer` / `Good Bear`. Выпускной EXE дополнительно
проверяется вручную в Windows Explorer: внешняя иконка и иконка мастера
установки должны быть Good Bear.

## 2026-09-29 — Смешанная locale в nominally en-US base ломала single-locale repack

**Сбой.** После `package-multi-locale --locales ru` файл с именем
`*.en-US.win64.zip` был использован как base для
`repackage-single-locales --locales ru`. Legacy l10n-repack завершался с
`Multiple app locales aren't supported: ru,en-US` и множественными
`already added` для `chrome/ru/...`.

**Корневая причина.** Имя ZIP описывало базовую конфигурацию, но не его
содержимое: в `goodbear/browser/omni.ja` остались Fluent-ресурсы `ru`, две
marketplace-иконки и manifest-запись от предыдущей multi-locale упаковки.
Корневой `omni.ja` был чистым, поэтому поверхностная проверка archive name или
одного JAR не обнаруживала загрязнение.

**Постоянный guard.** Single-locale pipeline хранит отдельный immutable base
ZIP и до repack разбирает оба вложенных JAR: `goodbear/omni.ja` и
`goodbear/browser/omni.ja`. Из manifest-файлов извлекаются фактические locale;
допускается только ровно `{en-US}`. При любом другом результате pipeline
останавливается до создания langpack/installer. Для recovery уже собранных
бинарников допускается детерминированная очистка только устаревшей locale
ветки из копии base, с повторным JAR-аудитом; новые воспроизводимые сборки
должны получать base из чистой package staging-area, а не после
`package-multi-locale`.

**Подтверждение исправления.** Проверенный base содержал только `en-US` в обоих
JAR. `repackage-single-locales --locales ru` затем завершился с
`RU_SINGLE_SUCCESS`; обе `omni.ja` итогового ZIP содержат только `ru`.

## 2026-09-30 — Кнопки навигации NSIS были созданы, но визуально прозрачны

**Сбой.** В русской Windows-сборке приветственная и финальная страницы
мастера Good Bear показывали фирменную иллюстрацию и текст, однако нижняя
панель не рисовала «Далее», «Назад» или «Отмена». Нативная инспекция показала,
что стандартные контролы `Button` с идентификаторами 1 и 2 существуют,
видимы и включены; дефект был именно в отрисовке Modern UI.

**Исправление.** Патч
`0054-good-bear-nsis-navigation-button-contrast.patch` добавляет
`EnsureNavigationButtonContrast` и вызывает его на страницах `showWelcome` и
`showFinish`. Макрос возвращает системные `BTNFACE`/`BTNTEXT`, отключает
унаследованную тему только для кнопок и явно показывает их. Русский
single-locale installer после этой правки был принят при ручной визуальной
проверке в Windows Server 2022.

**Постоянный guard.** Эта правка должна существовать только как элемент
`patches/series`, быть включена в source-inventory и в frozen source manifest.
Перед продвижением Windows-кандидата обязательны: проверка применения патча,
installer-only repack из этого freeze и визуальная проверка приветственной и
финальной страниц в нативной Windows-сессии. Наличие HWND или успешный exit
code NSIS не заменяют проверку видимых подписей кнопок.

## 2026-09-29 — NSIS-мастер сохранял штатную иллюстрацию Firefox

**Сбой.** Русский Good Bear installer получил правильные заголовок и иконки,
но на приветственном и завершающем экранах показал штатную иллюстрацию Firefox.
На удалённом рабочем столе также наблюдалось обрезание нижней панели, однако это
соответствовало артефакту масштабирования RDP и не стало поводом менять
геометрию NSIS без нативной проверки.

**Корневая причина.** Good Bear branding overlay не объявлял полный набор
обязательных NSIS bitmap-ресурсов: `wizWatermark.bmp`, `wizHeader.bmp` и
`wizHeaderRTL.bmp`. Поэтому `installer.nsi` взял изображения из upstream
Firefox branding-tree.

**Исправление и постоянный guard.** `tools/generate_nsis_branding_assets.py`
детерминированно создаёт три 24-bit BMP из утверждённой иллюстрации Good Bear;
контракт с размерами и SHA-256 хранится в
`config/m10-03-artwork-system.json`, provenance — в
`config/branding-provenance-inventory.json`. Перед каждой Windows-упаковкой
обязателен `tools/verify_nsis_branding_assets.py`: он проверяет комплект,
размеры, хеши и отличие от Firefox. Этот verifier вызывается самим
`tools/build_m12_03_windows_installer.py preflight` до проверки host/SDK и
до любого packaging command. После генерации требуется убедиться по
логу, что NSIS заново скомпилировал `setup.exe`. Визуальная проверка мастера
в обычной Windows-сессии остаётся выпускным ручным gate: иллюстрация должна
быть Good Bear, а нижние кнопки должны быть видны без артефактов клиента RDP.

## 2026-09-29 — Русская локализация не была воспроизводимым входом сборки

**Сбой процесса.** Рабочий каталог `source/l10n/firefox-l10n/ru` содержал
локальные изменения двух upstream Fluent-файлов и два добавленных файла Good
Bear. Каталог исключён из публичного репозитория как materialized input, а
старый bootstrap создавал только Firefox source tree. Значит, новый
воспроизводящий сборку пользователь получал бы другую русскую локаль либо
вообще не получал бы её до ручного копирования.

**Корневая причина.** В source-freeze учитывался результат текущей Windows
работы, но не были отдельно закреплены revision Mozilla l10n и минимальный
набор производных Good Bear переводов. Префлай проверял наличие файлов на
текущей ВМ, а не возможность чистой materialization из публичных исходников.

**Исправление и постоянный guard.**
`config/firefox-l10n-ru-lock.json` фиксирует URL, точный commit Mozilla,
путь sparse checkout и SHA-256 для четырёх изменяемых Fluent-файлов.
`tools/materialize_pinned_russian_l10n.py` получает только `ru` в detached
checkout, требует чистое upstream-дерево, сверяет два базовых файла и
отсутствие двух новых файлов, затем накладывает проверенный public overlay.
`tools/bootstrap_public_source.sh` вызывает этот шаг автоматически. Проверка
source-freeze и повторная Windows-сборка запрещены, если не проходит этот
materializer; локальные правки в checkout более не считаются допустимым
источником перевода.
