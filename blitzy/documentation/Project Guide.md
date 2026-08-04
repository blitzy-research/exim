# Blitzy Project Guide
## Exim — GnuTLS BDAT/CHUNKING Transfer-Buffer Use-After-Free Remediation

> **Branch** `blitzy-6348374b-7242-4e22-b436-0e4b9434bebe` · **HEAD** `087840983` · **AAP baseline** `8c8eec613` · **Working tree** clean · **24 commits**, all authored `Blitzy Agent <agent@blitzy.com>`

---

# 1. Executive Summary

## 1.1 Project Overview

This project remediates a remotely reachable, pre-authentication heap use-after-free write in Exim's GnuTLS-backed SMTP server, exposed whenever a TLS session is torn down while a `BDAT`/`CHUNKING` body transfer is still in progress. `tls_close()` released the per-session transfer buffer and destroyed the GnuTLS session while leaving both pointers dangling and every transfer-state field unreset, so readers bound to those objects kept being dispatched — writing attacker-influenced bytes into freed heap. Because `CHUNKING` and `STARTTLS` are advertised by default, any unauthenticated remote peer can reach it on a stock build. The work delivers the object-lifetime fix, reader-callback deregistration, fail-closed read paths, harness reproducers, and a full advisory package. Target systems are internet-facing Exim MTAs; impact is prevention of remote heap corruption and of a silent plaintext downgrade.

## 1.2 Completion Status

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'pie1':'#5B39F3', 'pie2':'#FFFFFF', 'pieStrokeColor':'#B23AF2', 'pieStrokeWidth':'2px', 'pieOuterStrokeColor':'#B23AF2', 'pieTitleTextSize':'16px', 'pieSectionTextSize':'14px'}}}%%
pie showData title 69.8% Complete
    "Completed Work (AI)" : 169
    "Remaining Work" : 73
```

**Legend** — <span style="color:#5B39F3">■</span> Completed / AI Work `#5B39F3` · <span style="color:#FFFFFF">□</span> Remaining `#FFFFFF`

| Metric | Value |
|---|---|
| **Total Hours** | **242** |
| **Completed Hours (AI + Manual)** | **169** (169 AI · 0 manual) |
| **Remaining Hours** | **73** |
| **Percent Complete** | **69.8 %** |

**Calculation (PA1, AAP-scoped work only):**
`Completion % = 169 / (169 + 73) × 100 = 169 / 242 × 100 = 69.83 % → 69.8 %`

The denominator contains only deliverables defined in the Agent Action Plan plus the standard path-to-production activities required to ship them. Nothing outside that scope is counted.

## 1.3 Key Accomplishments

- [x] **All seven specified fix elements (FS-1 … FS-7) implemented and verified in code** — teardown pointer/state hygiene, guarded allocation with state resets at both allocation sites, ATRN de-aliasing, fail-closed guards across six read consumers, the shared `tls_ungetc` guard, and BDAT reader-vector invalidation.
- [x] **SR-1 discharged with the mandatory ordered negative control** — the reproducer produces `AddressSanitizer: heap-use-after-free`, WRITE of size 1, on the unpatched tree and **zero reports** afterwards, across 5 scenarios × 2 backends × 2 spool formats plus 105 stress connections.
- [x] **Zero regressions across the full automatic range** — 898 pass / 12 fail / 155 skip of 1065 on the fix versus 894 / 17 / 155 of 1066 on the baseline, run four times in paired configurations. No test fails on the fix that passes on the baseline.
- [x] **Root cause closed structurally, not just for the reproducer** — the saved reader vector is *remapped* onto the plain readers rather than cleared, preserving the load-bearing `lwr_receive_getc == NULL` sentinel and making the plan's own highest-attention failure mode — a stray `chunking double-push/pop` debug line breaking the byte-exact comparison gate — impossible by construction rather than merely untriggered.
- [x] **A second security defect, introduced by the shared change itself, found and fixed during validation** — the reader remap let the remainder of a chunk be taken from the cleartext socket on the OpenSSL backend, so an unfinished message was accepted and delivered where the unpatched tree had refused it. Closed with a session-gone latch in shared BDAT code, leaving `tls-openssl.c` untouched.
- [x] **A third, independent defect found and fixed on the same attack surface** — `BDAT` argument parsing accepted a sign and ignored overflow, so a negative or oversized size became a 4 294 967 295-byte chunk and any stray word where `LAST` belongs silently meant "no marker", hanging the connection until the receive timeout. Now validated per RFC 3030.
- [x] **Fail-closed teardown delivered without breaking legitimate continuation** — a single `owed` predicate drives both the error latch and the EOF channel, so a session lost mid-message ends the message while one ending between messages still lets the connection carry on in clear, which Exim's own smtp transport depends on.
- [x] **Three harness reproducers with nine byte-exact reference artefacts** (`2038` mid-chunk, `2039` after a complete header line, `2040` mid-body with a byte in clear) — the AAP called for one.
- [x] **Complete audit trail** — ChangeLog entries `JH/21`–`JH/23` and a 37 KB advisory package under `doc/doc-txt/exim-security-2026-07-31.1/`, following the project's own convention for an advisory with no assigned identifier. **No CVE, CVSS score or advisory URL is fabricated anywhere.**
- [x] **Scope discipline provable** — all 21 changed paths inside the AAP allow-list; `transports/`, `auths/`, `lookups/`, `routers/`, `miscmods/`, `hintsdb/` at 0 files changed; `tls-openssl.c`, `receive.c`, `globals.*`, `store.*`, `structs.h`, `atrn.c`, `readconf.c`, `spec.xfpt`, `NewStuff`, `SECURITY.md`, `runtest`, `client.c` all byte-unchanged.
- [x] **Four build flavours compile clean** (GnuTLS, OpenSSL, GnuTLS+ASAN, OpenSSL+ASAN) with zero new warnings — only the three documented pre-existing diagnostics.
- [x] **A build-configuration defect in the verification environment found and fixed** — `HAVE_IPV6` is a build-time opt-in on Linux, so binaries were being built without it while upstream's golden references were recorded with it on; enabling it made 3 tests pass and 11 previously-skipped tests run, with nothing regressed.

## 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| No public identifier or external severity corroboration obtainable | Severity remains Blitzy's code-derived assessment (CRITICAL, est. CVSS 9.8) and is unverified. Downstream consumers cannot match it to an advisory. | Security lead + Exim maintainers | 10 h (HT-2) |
| Coordinated disclosure drafted but not executed | The advisory's own timeline marks distros-repo and public publication as *planned*. Until published, deployments stay exposed to a pre-auth remote defect. | Security lead | 10 h (HT-2) |
| 12 suite tests fail, all provably baseline-identical | SR-4 cannot be declared unconditionally green in this container. Not regressions — two verified by hand against a freshly built baseline. Caused by toolchain drift, kernel TCP-Fast-Open state, host-dependent DKIM bytes, and an upstream omission in 5705/5706. Remediation would require editing out-of-scope golden references, forbidden by §0.9.2. | QA / release engineer | 8 h (HT-3) |
| Verification toolchain drifted from the AAP reference envelope | Container has GnuTLS 3.8.9 / OpenSSL 3.5.3 / GCC 13.4.0 / PCRE2 10.46 / Perl 5.40.1 versus the AAP's 3.8.3 / 3.0.13 / 13.3.0 / 10.42 / 5.38.2. This is the direct cause of the residual log-text failures and means SR-1 should be re-confirmed on a matched host. | QA / security engineer | 4 h (HT-4) |
| Upstream maintainer review not yet performed | A ~600-line security patch across four files, plus two in-scope additions beyond the specified seven fix elements, needs maintainer sign-off against the five named review focus points before release. | Exim maintainer | 10 h (HT-1) |
| Reproducible build recipe lives outside the repository | The required `Local/Makefile` knobs exist only in ephemeral `/tmp` helper scripts. The next engineer has the advisory's Verification section but no committed recipe. | Build / DevEx engineer | 3 h (HT-9) |

## 1.5 Access Issues

| System / Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| NVD / MITRE CVE databases | Outbound HTTPS research | `web_search` returned zero results for every query including trivial controls; the tool is non-functional in this environment. No CVE record could be retrieved. | **Unresolved — worked around.** No identifier asserted; severity labelled as code-derived and unverified. | Security lead |
| Headless browser research channel | Browser automation backend | `run_chrome_task` fails at launch with `[Errno 2] No such file or directory: 'chrome-devtools-mcp'`. A six-target research brief could not execute. | **Unresolved — worked around.** Substituted the in-repository `doc/doc-txt/ChangeLog` as the primary evidence base. | Platform |
| Arbitrary URL fetch | Outbound HTTP | `web_fetch` rejects every URL with `url_not_in_prior_context`; because search returns nothing, no URL can legitimately enter prior context, so the channel is transitively unusable. | **Unresolved — worked around.** All evidence drawn from primary sources physically present in the checkout, cited with line numbers. | Platform |
| `wiki.exim.org` security pages & `security@exim.org` | Disclosure channel | The authoritative contact point and PGP keys live behind `wiki.exim.org/EximSecurity`, unreachable from this environment. Required to submit the report and request a CVE. | **Unresolved — human action required.** Tracked as HT-2. | Security lead |
| Reference-toolchain host | Build/test environment | No host matching the AAP §0.4.4.1 library envelope is available; this container has drifted forward. | **Unresolved — human action required.** Tracked as HT-3 / HT-4. | QA engineer |
| Repository, git, build toolchain, test harness, Docker, sanitizers | Local read/write and execute | No issue. Full access confirmed: 24 commits authored, five trees built from scratch, harness and ASAN daemons driven end to end this session. | **No issue** | — |

## 1.6 Recommended Next Steps

1. **[High]** Have an Exim maintainer review the patch against the five named focus points — FS-1 applied completely; FS-2/FS-3 present at *both* allocation sites (their absence fails SR-2 silently rather than the reproducer); FS-4 guards comparing `active.sock < 0` and never `== 0`; FS-6 correct under `USE_OPENSSL`; FS-7 preserving the `lwr_receive_getc == NULL` sentinel. Assess the three ChangeLog entries as three logically separate changes. **(10 h)**
2. **[High]** Submit the report through `wiki.exim.org/EximSecurity`, request a CVE from MITRE, send the drafted `oss-security.txt`, add the `doc/doc-txt/cve-YYYY-NNNNN` alias symlink once assigned, and let the maintainers set the authoritative severity. **(10 h)**
3. **[High]** Re-run the full automatic range and the ASAN negative control on a host matching the AAP reference toolchain, paired against the baseline, and confirm the 12 residual failures clear or remain provably pre-existing. **Never pass `--update`.** **(12 h combined, HT-3 + HT-4)**
4. **[Medium]** Backport to `exim-4.99+fixes` or a 4.99.x security point release following the project's one-advisory-per-point-release convention, then re-run the CHUNKING and TLS witness groups on the backported branch. **(8 h)**
5. **[Medium]** Publish to distro security teams ahead of the public release, then deploy with a release note stating the one intentional behavioural change: a peer that tears down TLS mid-chunk now receives `421 Lost incoming connection` instead of having its traffic silently read in cleartext. **(11 h combined, HT-6 + HT-7)**

---

# 2. Project Hours Breakdown

## 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---|---|
| FS-1 — GnuTLS teardown lifetime hygiene | 10 | `tls_close()`: null the session after `gnutls_deinit`, null the buffer after `store_free`, zero both water marks, latch EOF/error. Includes designing the single `owed` predicate that drives both the error latch and the feof/ferror channel choice so the two cannot disagree, plus dropping the `have_set_peerdn` latch so a later session records its own peer data. |
| FS-2 + FS-3 — Allocation-site transfer-state resets | 6 | Guarded allocation (`if (!state->xfer_buffer)`) at both sites for full OpenSSL parity, plus water-mark and flag resets, plus `ostate->session = NULL` on the ATRN inbound transplant. Mandatory for SR-2: without them a legitimate second TLS session on one TCP connection inherits the latches and EOFs immediately. |
| FS-4 — ATRN state-transplant de-aliasing | 5 | Removed the buffer/session aliasing created by the wholesale struct copy so exactly one context owns each object; `tls_shutdown_wr` additionally guarded. All guards compare `active.sock < 0`, never `== 0`, because ATRN legitimately passes `newfd == 0`. |
| FS-5 — Fail-closed guards in six read consumers | 7 | `tls_refill`→`FALSE`, `tls_getc`→`EOF`, `tls_getbuf`→`NULL`, `tls_get_cache`→early return, `tls_could_getc`→`FALSE`, `tls_read`→`-1`. Each returns the correct fail-closed value for its own contract rather than a uniform one. |
| FS-6 — Shared `tls_ungetc` released-buffer guard | 2 | Buffer-pointer check ahead of the pre-existing underflow `log_write_die`, closing the one-byte use-after-free write. Written to stay correct under both backends, where the symbol is a file-static in one case and a macro alias in the other. |
| FS-7 — BDAT reader-vector lifetime | 20 | Exported invalidation hook called from teardown, plus a settle step before every dispatch through the saved vector, plus three unconditional push/pop sites made conditional. The vector is *remapped* onto the plain readers rather than cleared, preserving the `lwr_receive_getc == NULL` sentinel — which is what makes the highest-risk failure mode impossible rather than merely untriggered. |
| Chunked-layer session-gone latch | 12 | Closes an exposure the FS-7 remap itself would otherwise have opened on the OpenSSL backend, where the chunk remainder could be taken from the cleartext socket and an unfinished message accepted and delivered. Implemented entirely in shared BDAT code; `tls-openssl.c` untouched, honouring the change-scope constraint. Also removes a latent panic route through the plain socket's ungetc underflow. |
| RFC 3030 BDAT argument validation | 6 | New parser replacing `sscanf("%u %n")` at both command sites: rejects a sign, detects overflow, and validates the end marker. Previously a negative or oversized size became a 4 294 967 295-byte chunk and any stray word where `LAST` belongs meant "no marker" — either way hanging the connection until the receive timeout. |
| Harness reproducers and reference artefacts | 14 | Three scripts (`2038` mid-chunk, `2039` after a complete header line, `2040` mid-body with a byte in clear) plus nine byte-exact munged references and three configuration symlinks. Built from existing harness primitives only; each script carries extensive rationale, including why the reply is matched in full rather than loosely (a loose `421` match would be satisfied by the very behaviour the test exists to reject). |
| ChangeLog entries JH/21 – JH/23 | 3 | Three entries in the 4.100 section: the use-after-free fix and its behavioural change, the BDAT argument validation, and the removal of two spurious diagnostics. Correctly placed and styled after the project's own security-entry convention. |
| Security advisory package | 12 | `doc/doc-txt/exim-security-2026-07-31.1/` — announcement (4.6 KB), technical report (32 KB: overview, mechanism, reachability and impact, remediation, behavioural change, verification, per-test residual-failure attribution, status) and disclosure timeline. Follows the project's own naming convention for an advisory with no assigned identifier, and states explicitly that no identifier or score is claimed. |
| SR-1 memory-safety verification | 18 | ASAN build variants, the non-setuid daemon harness they require, PoC scripts, and the **mandatory ordered negative control** — reproducer demonstrated failing on the unpatched tree first, then clean. Post-fix: zero reports across 5 scenarios × 2 backends × 2 spool formats plus 105 stress connections. |
| SR-2 / SR-4 regression verification | 24 | Four paired full-automatic-range runs (~1065 tests each, two per tree) plus every witness group on both backends, and the triage that proved each residual failure baseline-identical — including re-running the one nondeterministic test five times per build to classify it. |
| Build and verification environment enablement | 14 | Four build flavours; resolution of the release-number, root-user, Berkeley-DB and DANE build obstacles; discovery and correction of the `HAVE_IPV6` build-time opt-in defect that had been suppressing 3 tests and skipping 11; trusted-config and paniclog remediation. |
| Code-review and QA remediation cycles | 16 | Five dedicated commits addressing code-review and QA findings, plus comment-accuracy corrections and four documentation corrections made so the audit trail matches the code and the measured results. |
| **TOTAL COMPLETED** | **169** | **Matches Completed Hours in Section 1.2** |

## 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---|---|
| Upstream maintainer security review against the five named focus points | 10 | High |
| CVE request and coordinated-disclosure execution (report submission, MITRE, oss-security, CVE alias symlink, timeline updates) | 10 | High |
| Reference-toolchain re-verification of the 12 baseline-identical suite failures | 8 | High |
| Backport to `exim-4.99+fixes` / a 4.99.x security point release | 8 | Medium |
| Release packaging and OS-vendor coordination | 6 | Medium |
| SR-1 ASAN re-verification on the AAP reference toolchain envelope | 4 | High |
| Residual OpenSSL-backend teardown hardening (close_notify during refill; first post-teardown byte via the plain reader) — out of scope here per the change-scope constraint | 6 | Low |
| Production deployment plus operator notice of the intentional fail-closed change | 5 | Medium |
| Extended penetration scenarios (pipelined command after `BDAT … LAST`; sustained cycling on one connection) | 4 | Medium |
| In-repo capture of the reproducible build recipe | 3 | Medium |
| Valgrind track enablement (blocked by an out-of-scope end-of-config read) | 3 | Low |
| Optional CI regression / sanitizer gate (no pipeline exists today) | 6 | Low |
| **TOTAL REMAINING** | **73** | — |

## 2.3 Estimation Methodology and Reconciliation

Hours were derived per AAP item using the PA2 framework, with complex security-critical logic in a mature C codebase estimated at the upper end of the "complex business logic" band and verification estimated from the actual breadth executed rather than from a fixed percentage.

| Check | Expected | Actual | Status |
|---|---|---|---|
| Section 2.1 row count and sum | 15 rows | 169 h | ✅ |
| Section 2.2 row count and sum | 12 rows | 73 h | ✅ |
| Section 2.1 + Section 2.2 = Total Hours (1.2) | 242 h | 169 + 73 = 242 | ✅ |
| Remaining hours identical in 1.2, 2.2, Section 7 | 73 h | 73 / 73 / 73 | ✅ |
| Human task list total = Section 2.2 total | 73 h | 32 + 26 + 15 = 73 | ✅ |
| Completion percentage | 169 / 242 | 69.83 % → **69.8 %** | ✅ |

**Confidence levels.** *High* for every implementation and verification row in Section 2.1 — each was independently re-verified this session by reading the code, rebuilding from scratch and re-running the tests. *High* for the review, backport, packaging and deployment rows in Section 2.2, which are well-understood process activities. *Medium* for the reference-toolchain re-verification, whose duration depends on how quickly a matched host can be provisioned. *Low* for the CVE and disclosure row, which depends on third-party response times outside anyone's control; the 10 h figure covers Blitzy-side effort only, not calendar latency.

---

# 3. Test Results

All figures below originate from Blitzy's autonomous validation runs on this branch. Every row was independently re-executed during this assessment against freshly built binaries.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---|---|---|---|---|
| Full automatic range (fix, GnuTLS) | `test/runtest` (Perl harness) | 1065 selected | 898 | 12 | 100 % of selectable range | 155 skipped for absent host facilities. Run twice on this tree. |
| Full automatic range (baseline, paired) | `test/runtest` | 1066 selected | 894 | 17 | 100 % of selectable range | Control run twice. Baseline-only failures were the three new reproducers (correct negative control) plus two nondeterministic tests. **Zero regressions.** |
| Vulnerability reproducers `2038`/`2039`/`2040` | `test/runtest` + `client-gnutls` | 3 | 3 | 0 | All four unsafe dispatch paths | Correctly **fail** on the unpatched tree — a harness-level ordered negative control. Re-verified this session. |
| CHUNKING core (`0900`, `0901`, `0904`–`0906`, `0908`, `0909`) | `test/runtest` | 7 | 7 | 0 | Reception, transmission, wireformat, pipelined QUIT | `0908` covers `spool_wireformat`, discharging the no-spool-format-change requirement. |
| TLS × CHUNKING (`1114`, `1165`, `1166`) | `test/runtest` | 3 | 3 | 0 | Server reception, client transmission, RCPT-reject drop | `1114` is the direct analogue of the reproducer. All three passed standalone this session. |
| ATRN (`1148`, `0639`) | `test/runtest` | 2 | 2 | 0 | State transplant under TLS | `1148` already exercises a TLS shutdown twice; validates the `< 0` guard discipline. |
| TLS × DKIM × CHUNKING (`4531`, `4532`, `4535`, `4539`) | `test/runtest` | 4 | 4 | 0 | The historically fragile verification-feed intersection | Protects the DKIM feed the changed read path drives. |
| DKIM × CHUNKING, no TLS (`4511`, `4512`, `4515`, `4519`) | `test/runtest` | 4 | 4 | 0 | DKIM feed isolated from TLS | Re-run and confirmed this session. |
| PRDR × CHUNKING (`5590`, `5591`) | `test/runtest` | 2 | 2 | 0 | Per-recipient data response | — |
| PIPECONNECT × CHUNKING (`4053`, `4058`, `4060`, `4064`, `4068`, `4069`) | `test/runtest` | 6 | 5 | 1 | Early-pipelining variants incl. TLS and auth | `4058` is a proven flake — one failure in five runs on **both** builds (kernel TCP-Fast-Open cookie state). |
| GnuTLS category (`2000`–`2099`) | `test/runtest` | 25 | 25 | 0 | Whole affected category | Re-run this session: 25 scripts, **0 failures**. |
| OpenSSL category (`2100`–`2199`) | `test/runtest` | 23 | 22 | 1 | Dual-backend parity | Re-run this session: exit 0. `2190` is the installed OpenSSL release aborting in the mandatory-ALPN path, failing identically on both trees. |
| Basic-TLS range (`1100`–`1199`) | `test/runtest` | 36 | 34 | 2 | All TLS server/client scenarios | `1166` and `1199` mismatch on library log text; **both verified by hand to fail identically on a freshly built baseline.** |
| Memory safety — AddressSanitizer | ASAN (`libasan.so.8`) + PoC scripts | 5 scenarios × 2 backends × 2 spool formats + 105 stress connections | All clean | **0 reports** | All four unsafe dispatch paths | Pre-fix control produced `heap-use-after-free`, WRITE of size 1, at the exact predicted frames. Re-confirmed on a fresh ASAN build this session: 0 reports on 3 flows including the happy path. |
| Compilation — four flavours | GCC 13 + GNU Make | 4 builds | 4 | 0 | Whole tree per flavour | Every build exits 0 emitting only the three documented pre-existing diagnostics; zero new warnings, including none for the translation unit that textually includes the patched backend. |

**Aggregate:** 1065 tests selected in the definitive run, **898 passed, 12 failed, 155 skipped — zero regressions against the paired baseline**, and **zero AddressSanitizer reports** where the unpatched tree reports a heap use-after-free write.

**On the 12 failures.** Every one fails identically on the unpatched baseline, so none is caused by this change. Attributed causes: library log-text differences under the drifted toolchain (`1166`, `1199`, `4506`, `5820`, `5890`, `5891`, `2190`); kernel TCP-Fast-Open cookie state (`1090`, `4058`); host-name-dependent DKIM signature bytes (`4517`); a retry-database debug line this host does not emit (`0630`); and an upstream omission in `5705`/`5706`, which carry a server block but neither a saved transcript nor the directive every sibling of the same shape carries. Each would require editing an out-of-scope reference file or script for a test unrelated to this fix — expressly forbidden, and doing so would encode this container's library versions into the project's golden references.

---

# 4. Runtime Validation & UI Verification

This is a mail transfer agent with no user interface; runtime validation was performed at the SMTP protocol level against live daemons. Every result below was reproduced during this assessment.

## Daemon lifecycle
- ✅ **Operational** — Daemon starts from a standalone configuration and binds both IPv4 and IPv6 listeners.
- ✅ **Operational** — Clean shutdown via a pid-targeted signal; no orphaned children.
- ✅ **Operational** — Panic log **absent** for the whole validation session on a correctly configured environment.
- ✅ **Operational** — Queue empty after every scenario; no stuck messages.

## Normal delivery paths (functional invariance)
- ✅ **Operational** — Plain `DATA` delivery accepted and delivered with every body marker present.
- ✅ **Operational** — `BDAT`/`CHUNKING` over TLS accepted and delivered; server acknowledges `250- 74 byte chunk, total 77`, then logs acceptance with the negotiated cipher (`P=esmtps X=TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256:SECP256R1`), delivery and completion.
- ✅ **Operational** — Multi-chunk `BDAT` over TLS delivered intact.
- ✅ **Operational** — `BDAT` in clear (no TLS) delivered intact.
- ✅ **Operational** — `STARTTLS` → teardown → `STARTTLS` reuse on one TCP connection works, with the **second** session's cipher logged — proving the allocation-site resets prevent the latches leaking forward.

## Abnormal teardown paths (the vulnerability)
- ✅ **Operational** — `BDAT n LAST` with a short body then TLS shutdown, socket held open: server answers `421 Lost incoming connection`, client reaches a clean end of file, mainlog records `lost while reading message data`. **Nothing delivered.**
- ✅ **Operational** — Same flow with cleartext bytes injected after shutdown: connection reset, nothing accepted. No silent plaintext continuation.
- ✅ **Operational** — Teardown after a complete header line: refused, not accepted as a complete message.
- ✅ **Operational** — Teardown mid-body on the wireformat spool path: refused.
- ✅ **Operational** — All three abnormal flows deliver **zero** messages; 0 abnormal deliveries observed in a 45-connection OpenSSL stress run while the normal case still delivered 15 of 15.

## Memory safety under sanitizer
- ✅ **Operational** — Zero AddressSanitizer reports post-fix across every scenario, both backends, both spool formats, and 105 stress connections.
- ✅ **Operational** — Pre-fix control reproduces the defect with the exact predicted signature, confirming the reproducer genuinely exercises the vulnerable path.

## Configuration and protocol surface
- ✅ **Operational** — `chunking_advertise_hosts = *`, `tls_advertise_hosts = *`, `smtp_receive_timeout = 5m` unchanged; no new runtime option exists.
- ✅ **Operational** — EHLO advertisement set unchanged; `CHUNKING` and `STARTTLS` still offered.
- ⚠ **Partial** — Valgrind-based runtime validation unavailable: an out-of-scope end-of-config read prevents a daemon starting under valgrind. No success criterion requires it and AddressSanitizer is the decisive tool for this defect class.
- ⚠ **Partial** — Runtime validation ran on the drifted container toolchain rather than the AAP reference envelope; re-confirmation on a matched host is tracked as remaining work.

---

# 5. Compliance & Quality Review

## 5.1 Success criteria

| Requirement | Benchmark | Status | Evidence | Progress |
|---|---|---|---|---|
| **SR-1** Zero use-after-free under AddressSanitizer, negative control first | Absence of any ASAN report, not merely absence of a crash | ✅ **PASS** | Pre-fix control reports `heap-use-after-free`, WRITE of size 1, at the exact predicted frames; post-fix 0 reports across 5 scenarios × 2 backends × 2 spool formats + 105 stress connections. Re-confirmed on a fresh ASAN build. | 100 % |
| **SR-2** Normal BDAT/CHUNKING over TLS byte-identical | Every munged output surface byte-for-byte against its reference | ✅ **PASS** | All 10 named witnesses pass; zero post-fix-only failures in 1065 tests; the risky debug line occurs 0 times and is structurally impossible; happy-path delivery confirmed under sanitizer. | 100 % |
| **SR-3** No dangling references survive teardown, all dispatch paths | Structural invariant, stronger than "the reproducer passes" | ✅ **PASS** | Both pointers nulled and water marks zeroed at teardown; six consumers guarded; the shared one-byte write guarded; the saved reader vector invalidated and re-checked at every dispatch; ATRN aliasing removed. | 100 % |
| **SR-4** Delivery scenarios pass | Full automatic range plus targeted TLS categories on both backends | ⚠ **PARTIAL** | 898/1065 pass with **zero regressions** against a paired baseline; affected GnuTLS category 25/25; OpenSSL category clean. 12 failures remain, all baseline-identical and environment-attributed; remediation requires out-of-scope reference edits. | 85 % |

## 5.2 Implicit requirements

| Requirement | Status | Evidence |
|---|---|---|
| **IR-1** Fail closed; no silent plaintext downgrade | ✅ **PASS** | `421 Lost incoming connection` plus clean EOF verified at runtime on both backends; nothing delivered. The `owed` predicate preserves legitimate between-message continuation that Exim's own smtp transport relies on. |
| **IR-2** No dangling session handle | ✅ **PASS** | Session pointer nulled immediately after destruction; both remaining consumers of it guard on it. |
| **IR-3** DKIM verification feed integrity | ✅ **PASS** | Eight DKIM witnesses pass, with and without TLS; the cache-drain path is guarded on the buffer before feeding. |
| **IR-4** Escaping interior pointers accounted for | ✅ **PASS** | The buffer-returning reader is guarded; the wireformat path that consumes it was reproduced pre-fix and is clean post-fix. |
| **IR-5** Both backends build and behave identically at the boundary | ✅ **PASS** | Four clean builds; whole OpenSSL category re-run clean this session; and the session-gone latch closes what would otherwise have been a real OpenSSL behavioural regression — without touching that backend's source. |
| **IR-6** No configuration-semantics drift | ✅ **PASS** | Option values confirmed at runtime; the option-parsing module and the state-machine header are at **0 changes**; no new option. |
| **IR-7** No ABI/API, wire-format or spool-format change | ✅ **PASS** | Exactly one additive internal declaration (`+1/−0` in the shared header); the wireformat witness passes. |
| **IR-8** ATRN state transplant covered | ✅ **PASS** | Both ATRN witnesses pass; guards compare `< 0` with an explicit comment recording why `== 0` would be wrong. |

## 5.3 Constraints and quality standards

| Constraint / Standard | Status | Evidence |
|---|---|---|
| **C-1** Confine changes to BDAT body-handling and TLS transfer-buffer lifetime | ✅ **SATISFIED** | Four source files only, all inside the allow-list. The shared dispatch file is unavoidably included because the function performing one of the unsafe writes lives there. |
| **C-2** Preserve SMTP state machine and configuration semantics | ✅ **SATISFIED** | State-machine header, option-parsing module and globals at 0 changes; the only state assignments touched set the *same* enum values through a validated parser. |
| **C-3** Do not alter unrelated transports or authenticators | ✅ **SATISFIED** | `transports/`, `auths/`, `lookups/`, `routers/`, `miscmods/`, `hintsdb/` at **0 files changed** each. |
| **MINIMAL change-scope preference** | ⚠ **PARTIAL** | The seven specified elements are minimal and each mirrors an existing in-repo pattern. Two additional in-scope changes were added after validation exposed real defects on the same surface — justified and separately documented, but they do enlarge the review surface for a patch specified as minimal. Reviewers should assess three logically distinct changes, matching the three ChangeLog entries. |
| **Zero-Placeholder Policy** | ✅ **PASS** | No TODO, FIXME, XXX, stub, empty body or dummy return in any added line. Every added function is fully implemented. |
| **Documentation excellence** | ✅ **PASS** | Every guard carries a comment explaining why it exists and what breaks without it; the reader-vector hook documents why it remaps rather than clears; the reproducers explain their own arithmetic and assertion strictness. |
| **Evidence-based claims only — no fabricated identifiers** | ✅ **PASS** | The advisory states plainly that no identifier or score is claimed, that no public record was retrievable, and that identifiers found elsewhere in the tree belong to other historical defects. |
| **Audit trail alongside code** | ✅ **PASS** | Three ChangeLog entries plus a 37 KB advisory package following the project's own no-identifier-yet naming convention. |
| **Non-destructive verification** | ✅ **PASS** | Golden references never rewritten; the reference-rewriting flag never used; every harness invocation non-interactive. |
| **Commit authorship** | ✅ **PASS** | 24 of 24 commits authored and committed as `Blitzy Agent <agent@blitzy.com>`. |

## 5.4 Fixes applied during autonomous validation

| Finding | Severity | Resolution |
|---|---|---|
| The shared reader-remap let a chunk remainder be taken from the cleartext socket on the OpenSSL backend, so an unfinished message was accepted and delivered — worse than the unpatched tree, which refused it accidentally | **High** | Session-gone latch added in shared BDAT code; provably cannot fire on the GnuTLS path, so no recorded output changed. Verified: 0 abnormal deliveries in a 45-connection stress while 15/15 normal deliveries succeeded. |
| `BDAT` argument parsing accepted a sign, ignored overflow and left the end marker unexamined, hanging the connection until the receive timeout | **Medium** | Full RFC 3030 argument validation with the chunking state left unchanged on a syntax error. |
| Two chunked-layer diagnostics fired where nothing was wrong — one per header line for every CHUNKING message, one per zero-sized last chunk | **Low** | Three unconditional call sites made conditional; what either diagnostic reports is unchanged for callers that do mean it. |
| Build environment omitted a build-time IPv6 opt-in, so binaries mismatched upstream's IPv6-recorded golden references | **Medium** | Enabled and persisted; 3 tests now pass and 11 previously-skipped tests now run, nothing regressed, no repository file touched. |
| Runtime panic-log noise from an untrusted ad-hoc configuration path | **Low** | Corrected in the scratch environment only; fix re-tested during this assessment. |
| Four documentation inaccuracies where the audit trail did not match the code or the measurements | **Low** | ChangeLog entry extended, advisory's dual-backend paragraph rewritten around what the two trees actually showed, a remediation bullet added, and the verification inventory replaced with measured counts. |

---

# 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| 12 suite tests fail, all baseline-identical, caused by toolchain drift and host state | Technical | Medium | High | Re-run on a host matching the reference envelope, paired against the baseline; never rewrite golden references. Two of the twelve verified by hand this session to fail on the unpatched tree. | Open — HT-3 |
| One nondeterministic test (`4058`) fails intermittently on both builds | Technical | Low | Medium | Classified by five runs per build (one failure each way); treat as a known flake tied to kernel TCP-Fast-Open cookie state. | Accepted |
| Settle check runs once per body byte in chunked mode | Technical | Low | Low | Inlined; fast path is two loads and a compare. Record the reasoning in the review; measure only if a throughput regression is ever suspected. | Open — review note |
| Delivered scope exceeds the seven specified fix elements | Technical | Low | Medium | Both additions are requirement-traceable and separately documented as distinct ChangeLog entries; reviewers assess three logical changes rather than one. | Open — review framing |
| Severity is uncorroborated: no CVE, CVSS or advisory retrievable | Security | Medium | Certain | No identifier asserted anywhere; rating labelled as code-derived and unverified. Obtain a CVE and let the maintainers score it. | Open — HT-2 |
| Reverting the change restores a pre-authentication remote exposure | Security | Critical | Low | Any revert must be paired with restricting the chunking advertisement, which defaults to unrestricted and therefore needs deliberate action. Documented in the advisory and the rollback plan. | Mitigated by documentation |
| Residual OpenSSL teardown behaviour: close_notify written during its own refill; first post-teardown byte still taken from the plain reader | Security | Low | Low | No memory-safety consequence — that backend never frees the buffer — and the message-level exposure is closed by the shared session-gone latch. Schedule as a separate upstream change; the change-scope constraint forbids it here. | Open — HT-10 |
| Disclosure drafted but not executed; deployments stay exposed until published and patched downstream | Security | High | Certain | Execute the staged timeline: distro security teams first, public second. | Open — HT-2 |
| The intentional fail-closed change is mistaken for breakage by operators | Security | Low | Medium | Already documented in the ChangeLog entry and the advisory's behavioural-change section; add an operator release note at deployment. | Mitigated — HT-7 |
| Reproducible build recipe lives only in ephemeral helper scripts outside the repository | Operational | Medium | High | The advisory's verification section documents invocation; capture the knobs durably. | Open — HT-9 |
| No CI pipeline exists, so nothing gates a future regression of this fix | Operational | Medium | Certain | A minimal job would build both backends plus sanitizers and run the witness groups and the three reproducers. Creating a pipeline was explicitly excluded from this scope. | Open — HT-11 |
| Test harness has many environment prerequisites, each of which fails loudly but obscurely | Operational | Low | High | All eleven traps reproduced and documented with exact error strings in Section 9. | Mitigated |
| Valgrind track unavailable due to an out-of-scope end-of-config read | Operational | Low | Certain | No success criterion requires valgrind; AddressSanitizer is decisive for this defect class. | Accepted — HT-12 |
| Trusted-config list holds a checkout-absolute path and must be regenerated per checkout | Operational | Low | Medium | Correctly gitignored with an explanatory comment; regeneration documented in Section 9. | Mitigated |
| Shared-code changes affect both TLS backends | Integration | High if wrong | Medium | Already caught and closed one real cross-backend regression this way. Both backends build clean and the whole OpenSSL category re-run clean this session. | Mitigated |
| DKIM verification feed intersects the changed read path — historically fragile | Integration | High if wrong | Low | Eight DKIM witnesses pass with and without TLS. | Mitigated |
| ATRN transplant requires `< 0` rather than `== 0` because a zero descriptor is legitimate | Integration | High if wrong | Low | Code uses `< 0` with an explicit comment; both ATRN witnesses pass. | Mitigated |
| Spool wireformat interaction with chunked reception | Integration | Medium | Low | The wireformat witness passes; the wireformat variant of the defect was reproduced pre-fix and is clean post-fix. | Mitigated |
| Upstream acceptance not guaranteed; maintainers may prefer a narrower first patch | Integration | Medium | Medium | Every element mirrors an existing in-repo pattern — the sibling backend's own discipline and the project's own documented remedy for a structurally identical defect — and each logical change is separately documented. | Open — HT-1 |

---

# 7. Visual Project Status

## 7.1 Project hours

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'pie1':'#5B39F3', 'pie2':'#FFFFFF', 'pieStrokeColor':'#B23AF2', 'pieStrokeWidth':'2px', 'pieOuterStrokeColor':'#B23AF2', 'pieTitleTextSize':'16px'}}}%%
pie showData title Project Hours Breakdown - 242h Total
    "Completed Work" : 169
    "Remaining Work" : 73
```

<span style="color:#5B39F3">■</span> **Completed Work — 169 h** `#5B39F3` &nbsp;·&nbsp; <span style="color:#FFFFFF">□</span> **Remaining Work — 73 h** `#FFFFFF`

## 7.2 Remaining work by priority

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'pie1':'#5B39F3', 'pie2':'#A8FDD9', 'pie3':'#FFFFFF', 'pieStrokeColor':'#B23AF2', 'pieStrokeWidth':'2px'}}}%%
pie showData title Remaining 73h by Priority
    "High" : 32
    "Medium" : 26
    "Low" : 15
```

## 7.3 Remaining hours by category

```
Upstream maintainer security review        ██████████  10 h  [High]
CVE request & coordinated disclosure       ██████████  10 h  [High]
Reference-toolchain test re-verification   ████████     8 h  [High]
Backport to 4.99+fixes / point release     ████████     8 h  [Medium]
Release packaging & vendor coordination    ██████       6 h  [Medium]
Residual OpenSSL teardown hardening        ██████       6 h  [Low]
Optional CI regression / sanitizer gate    ██████       6 h  [Low]
Deployment + operator notice               █████        5 h  [Medium]
SR-1 ASAN re-verification (ref toolchain)  ████         4 h  [High]
Extended penetration scenarios             ████         4 h  [Medium]
In-repo build-recipe capture               ███          3 h  [Medium]
Valgrind track enablement                  ███          3 h  [Low]
                                           ─────────────────
                                           TOTAL       73 h
```

## 7.4 Requirement status

```
SR-1  Memory safety under sanitizer     ████████████████████ 100%  ✅
SR-2  Functional invariance              ████████████████████ 100%  ✅
SR-3  No dangling references             ████████████████████ 100%  ✅
SR-4  Delivery-scenario regressions      █████████████████░░░  85%  ⚠
IR-1 … IR-8  Implicit requirements       ████████████████████ 100%  ✅ (8 of 8)
C-1 … C-3    Constraints                 ████████████████████ 100%  ✅ (3 of 3)
FS-1 … FS-7  Fix elements                ████████████████████ 100%  ✅ (7 of 7, +2 extra)
```

**Integrity note.** The "Remaining Work" value of **73 h** in 7.1 is identical to the Remaining Hours in Section 1.2 and to the sum of the Hours column in Section 2.2. The priority split in 7.2 (32 + 26 + 15) and the category bars in 7.3 both total 73 h.

---

# 8. Summary & Recommendations

## 8.1 Achievements

The project is **69.8 % complete** (169 of 242 hours). The engineering is done and independently verified; what remains is almost entirely the security-process path that only humans can walk.

The vulnerability is closed at its source and closed structurally. All seven specified fix elements landed, and each was re-verified during this assessment by reading the code rather than trusting a log. Two design choices deserve emphasis because they are better than what was specified. First, the teardown latches its error flag through a single "is anything still owed to a message" predicate that also selects which end-of-file channel the connection is left with — so the two decisions cannot drift apart, a session lost mid-message ends that message, and a session ending between messages still lets the connection continue in clear, which Exim's own smtp transport depends on. Second, the saved reader vector is *remapped* onto the plain readers rather than cleared, which preserves the sentinel the push/pop bookkeeping keys on and makes the plan's own highest-risk failure mode — a stray debug line breaking the byte-exact comparison gate — impossible by construction rather than merely untriggered.

The verification is unusually strong for a memory-safety fix. The mandatory ordered negative control was genuinely established: the reproducer produces a heap use-after-free write on the unpatched tree, at the exact frames the analysis predicted, and zero sanitizer reports afterwards across five scenarios, both backends, both spool formats and 105 stress connections. The regression evidence is paired rather than absolute — four full-range runs, two per tree — which is what makes "zero regressions" a defensible claim rather than an assertion.

Two additional defects were found and fixed during validation, both on the same attack surface and both genuine. One was introduced by the fix itself: the shared reader remap let the remainder of a chunk be taken from the cleartext socket on the OpenSSL backend, so an unfinished message was accepted and delivered where the unpatched tree had refused it accidentally. Catching that is the single most valuable thing this validation did, because it is exactly the class of regression a fix-and-move-on approach ships. The other was an argument parser that turned a negative or oversized chunk size into a four-billion-byte chunk and hung the connection until the receive timeout.

Scope discipline is provable rather than asserted: four source files, all inside the allow-list; every driver tree at zero files changed; every named reference file byte-unchanged; no new runtime option, no ABI change, no wire-format change, no spool-format change.

## 8.2 Remaining gaps

Nothing in the code blocks release. The 73 remaining hours divide into two kinds of work.

The larger part, 47 hours, is the security process: maintainer review against the five named focus points, CVE request and coordinated disclosure, backport to the fixes branch, packaging for distribution security teams, and deployment with an operator notice. The advisory's own timeline stages publication as *planned*, so this is explicitly handed over rather than forgotten. None of it can be automated and none of it should be rushed.

The smaller part, 26 hours, is verification hygiene and optional follow-ups. Twelve suite tests still fail; all twelve fail identically on the unpatched baseline, and two were confirmed by hand during this assessment against a freshly built baseline binary. Their causes are the container's toolchain having drifted ahead of the reference envelope, kernel TCP-Fast-Open state, host-dependent DKIM signature bytes, and one upstream omission. Closing them means re-running on a matched host — not editing the project's golden references, which would encode this container's library versions into upstream's expectations and mask real regressions. The remaining low-priority items — hardening the OpenSSL backend's own teardown, enabling the valgrind track, adding a CI gate — all sit deliberately outside the change-scope constraint.

## 8.3 Critical path to production

1. Maintainer security review (10 h) — the gate everything else waits on.
2. Reference-toolchain re-verification of the tests and the sanitizer control (12 h) — can run in parallel with review.
3. CVE request and coordinated disclosure (10 h) — starts once review confirms the patch shape.
4. Backport and packaging (14 h).
5. Publish to distro teams, then publicly; deploy with the operator notice (5 h).

Sequential critical path ≈ 41 hours of effort, with calendar time governed by MITRE and distro response latency rather than by engineering.

## 8.4 Success metrics

| Metric | Target | Achieved | Status |
|---|---|---|---|
| AddressSanitizer reports post-fix | 0 | **0** across 5 scenarios × 2 backends × 2 spool formats + 105 connections | ✅ |
| Ordered negative control established | Fails pre-fix, passes post-fix | Confirmed, with the exact predicted signature | ✅ |
| Test regressions introduced | 0 | **0** across four paired full-range runs | ✅ |
| New compiler warnings | 0 | **0** across four build flavours | ✅ |
| Files changed outside the allow-list | 0 | **0** of 21 | ✅ |
| Driver trees modified | 0 | **0** files in six trees | ✅ |
| New runtime options introduced | 0 | **0** | ✅ |
| ABI / wire-format / spool-format changes | 0 | **0** (one additive internal declaration) | ✅ |
| Fabricated external identifiers | 0 | **0** | ✅ |
| Placeholders, stubs or TODOs added | 0 | **0** | ✅ |
| Affected-category test pass rate | 100 % | **25 / 25** | ✅ |
| Suite tests failing overall | 0 | 12, all baseline-identical | ⚠ |

## 8.5 Production readiness assessment

**Code: ready, pending maintainer review.** The remediation is complete, sanitizer-clean, regression-free against a paired baseline, scope-compliant and fully documented. It is a drop-in binary replacement with no schema change, no migration, no configuration change and no dependency change. Rollback is a single revert plus a rebuild — but any revert must be paired with restricting the chunking advertisement, because reverting restores a pre-authentication remote exposure.

**Process: not ready.** No CVE exists, the advisory has not been published, no backport has been cut, and no distro coordination has begun. Because the defect is pre-authentication and remotely reachable on a stock configuration, this sequencing matters: the patch should reach distro security teams before it reaches the public, exactly as the drafted timeline stages it.

**One behavioural change must be communicated, not hidden.** A peer that tears down TLS mid-chunk and holds the socket open now receives `421 Lost incoming connection` instead of having its subsequent traffic silently read in cleartext on the same socket. That is the security fix. It is documented in the ChangeLog entry and in the advisory, and it belongs in the release note.

**Recommendation: proceed to maintainer review immediately, and treat the disclosure timeline as the schedule-critical path.** Do not defer deployment once review completes — the vulnerability is reachable without credentials on a default build.

---

# 9. Development Guide

Every command in this section was executed successfully during this assessment. Paths assume `REPO` is the repository root.

```bash
export REPO=/tmp/blitzy/exim/blitzy-6348374b-7242-4e22-b436-0e4b9434bebe_3d01b8
cd "$REPO"
```

## 9.1 System prerequisites

Linux x86-64 (validated on Ubuntu 25.10), ~4 GB free disk, 4+ cores recommended (builds use `make -j$(nproc)`), and **root access** — the test harness makes a setuid copy of the binary.

```bash
# Verify the toolchain. Every line must print a version.
gcc-13 --version | head -1          # gcc-13 (Ubuntu 13.4.0-4ubuntu1) 13.4.0
make --version | head -1            # GNU Make 4.4.1
pkg-config --modversion gnutls      # 3.8.9
pkg-config --modversion gnutls-dane # required: DANE on GnuTLS needs the separate module
pkg-config --modversion libpcre2-8  # 10.46
openssl version                     # OpenSSL 3.5.3
perl -e 'print "perl $^V\n"'        # perl v5.40.1
ls /usr/lib/x86_64-linux-gnu/libasan.so.8   # AddressSanitizer runtime
```

> **Toolchain drift matters.** The Agent Action Plan's reference envelope was GCC 13.3.0, GnuTLS 3.8.3, OpenSSL 3.0.13, PCRE2 10.42, Perl 5.38.2. This container runs ahead of all five, which is the direct cause of the residual log-text test failures in §9.6. For release verification, match the reference envelope.

Install on a fresh Debian/Ubuntu host if needed:

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  gcc-13 make libgnutls28-dev libgnutls-dane0 libssl-dev libpcre2-dev \
  libdb-dev libgdbm-dev libsqlite3-dev perl libasan8 pkg-config
```

## 9.2 Environment setup

```bash
# 1. Two users are required. Exim refuses to build with a root internal user,
#    and the harness runs as a separate unprivileged login that must be in the
#    exim group.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin exim || true
sudo useradd --create-home --shell /bin/bash eximtest || true
sudo usermod -aG exim eximtest
id exim && id eximtest          # eximtest's groups must include exim

# 2. Kernel state the harness depends on. Without IPv6, three tests fail against
#    upstream's IPv6-recorded references and eleven more are skipped.
sudo sysctl -w net.ipv4.tcp_fastopen=3
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0
# Persist:
printf 'net.ipv4.tcp_fastopen=3\nnet.ipv6.conf.all.disable_ipv6=0\n' \
  | sudo tee /etc/sysctl.d/99-exim-testsuite.conf

# 3. Regenerate the trusted-config list. It is gitignored because it holds an
#    absolute path to the checkout it was generated in, so it must be recreated
#    per checkout.
printf '%s/test/test-config\n' "$REPO" | sudo tee "$REPO/test/trusted_configs"
sudo chown root:root "$REPO/test/trusted_configs"
sudo chmod 644 "$REPO/test/trusted_configs"
```

## 9.3 Build

Save the following as `build-exim.sh`. It derives the harness macro whitelist from `test/README` itself rather than hard-coding a list that can go stale.

```bash
#!/bin/bash
# build-exim.sh <tree> <gnutls|openssl> [asan]
set -eu
TREE="$1"; TLS="$2"; SAN="${3:-}"
: "${REPO:?set REPO to the repository root}"

WL=$(sed -n '/WHITELIST_D_MACROS should contain/,+3p' "$REPO/test/README" \
     | grep -oE '\bDIR:[A-Z0-9_:]+' | head -1)

mkdir -p "$TREE/Local"
{
  echo "BIN_DIRECTORY=/usr/exim/bin"
  echo "CONFIGURE_FILE=/usr/exim/configure"
  echo "SPOOL_DIRECTORY=/var/spool/exim"
  echo "EXIM_USER=exim"                                  # MUST NOT be root
  echo "EXIM_GROUP=exim"
  echo "CONFIGURE_OWNER=eximtest"                        # harness requirement
  echo "TRUSTED_CONFIG_LIST=$REPO/test/trusted_configs"  # harness requirement
  echo "WHITELIST_D_MACROS=$WL"                          # harness requirement
  echo "CC=gcc-13"
  if [ "$SAN" = asan ]; then
    echo "CFLAGS=-O1 -g -fsanitize=address -fno-omit-frame-pointer -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE"
    echo "LFLAGS=-fsanitize=address"
  else
    echo "CFLAGS=-O2 -g -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE"
  fi
  if [ "$TLS" = gnutls ]; then
    echo "USE_GNUTLS=yes"; echo 'USE_GNUTLS_PC=gnutls gnutls-dane'
  else
    echo "USE_OPENSSL=yes"; echo "USE_OPENSSL_PC=openssl"
  fi
  echo "SUPPORT_DANE=yes"
  echo "HAVE_IPV6=YES"                                   # build-time opt-in on Linux
  echo "USE_DB=yes"; echo "DBMLIB=-ldb"                  # else db_env_create is undefined
  echo "LOOKUP_DBM=yes"; echo "LOOKUP_LSEARCH=yes"; echo "LOOKUP_DNSDB=yes"
  echo "LOOKUP_DSEARCH=yes"; echo "LOOKUP_CDB=yes"; echo "LOOKUP_PASSWD=yes"
  echo "ROUTER_ACCEPT=yes"; echo "ROUTER_DNSLOOKUP=yes"; echo "ROUTER_IPLITERAL=yes"
  echo "ROUTER_MANUALROUTE=yes"; echo "ROUTER_QUERYPROGRAM=yes"; echo "ROUTER_REDIRECT=yes"
  echo "TRANSPORT_APPENDFILE=yes"; echo "TRANSPORT_AUTOREPLY=yes"
  echo "TRANSPORT_PIPE=yes"; echo "TRANSPORT_SMTP=yes"; echo "TRANSPORT_LMTP=yes"
  echo "SUPPORT_MAILDIR=yes"
  echo "AUTH_CRAM_MD5=yes"; echo "AUTH_PLAINTEXT=yes"; echo "AUTH_TLS=yes"
  echo "EXIM_MONITOR="
} > "$TREE/Local/Makefile"

export EXIM_RELEASE_VERSION=4.100    # MANDATORY: the checkout carries no git tags
cd "$TREE" && make -j"$(nproc)"
```

Build out of tree so the repository stays clean:

```bash
chmod +x build-exim.sh

# GnuTLS — the backend containing the defect
rm -rf /tmp/exim-gnutls && cp -a "$REPO/src" /tmp/exim-gnutls
./build-exim.sh /tmp/exim-gnutls gnutls 2>&1 | tee /tmp/build-gnutls.log
echo "exit=$?"        # expect 0

# OpenSSL — required to prove the shared change keeps the sibling backend correct
rm -rf /tmp/exim-openssl && cp -a "$REPO/src" /tmp/exim-openssl
./build-exim.sh /tmp/exim-openssl openssl 2>&1 | tee /tmp/build-openssl.log

# GnuTLS + AddressSanitizer — for the memory-safety verification
rm -rf /tmp/exim-asan && cp -a "$REPO/src" /tmp/exim-asan
./build-exim.sh /tmp/exim-asan gnutls asan 2>&1 | tee /tmp/build-asan.log
```

**Warning allow-list — treat anything else as a failure.** Exactly these three, and nothing more:

```bash
grep -E "warning:|error:" /tmp/build-gnutls.log | grep -v jobserver | sort -u
# bits/unistd.h:32:10: warning: '__read_alias' specified size ... [-Wstringop-overflow=]
# verify.c:2312:11: warning: ignoring return value of 'write' ... [-Wunused-result]
# verify.c:2315:9:  warning: ignoring return value of 'write' ... [-Wunused-result]
```

Nothing should appear for `tls.c`, `smtp_in.c` or `functions.h`. Note that the patched GnuTLS backend is *textually included* into `tls.c`, so a defect in it surfaces as a `tls.c` diagnostic.

## 9.4 Verify the build

```bash
/tmp/exim-gnutls/build-Linux-x86_64/exim -bV
```

Expected (a `non-existent configuration file` note on the first line is normal):

```
Exim version 4.100 #1 built 04-Aug-2026 09:00:40
Support for: Exim_filter Sieve_filter crypteq iconv() IPv6 GnuTLS TLS_resume
             DANE DKIM DNSSEC ESMTP_Limits ESMTP_Wellknown Event OCSP
             PIPECONNECT PRDR Queue_Ramp TCP_Fast_Open
```

**Both `IPv6` and `DKIM` must be present.** `IPv6` because without it three tests fail and eleven are skipped; `DKIM` because it activates the verification-feed paths the fix must not disturb.

```bash
ldd /tmp/exim-asan/build-Linux-x86_64/exim | grep asan   # libasan.so.8 => ...
```

## 9.5 Run the test suite

Two rules are absolute:

- **Always pass `--continue`.** Without it the harness opens `/dev/tty` and waits for a keypress, and dies outright when headless.
- **Never pass `--update`.** It rewrites the saved reference files and would mask exactly the regression a run exists to detect.

```bash
cd "$REPO/test"

# The three vulnerability reproducers.
# For the GnuTLS *server* tests, hand the GnuTLS binary to runtest and OMIT --tls.
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim \
  --continue --test 2038 --test 2039 --test 2040
# expect: three "Script completed", no "Comparison of ... failed"

# CHUNKING core and ATRN
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue \
  --test 0900 --test 0901 --test 0904 --test 0905 --test 0906 --test 0908 \
  --test 0909 --test 0639

# TLS x CHUNKING and ATRN under TLS
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue \
  --test 1114 --test 1148 --test 1165 --test 1166

# TLS x DKIM x CHUNKING — the historically fragile intersection
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue \
  --test 4531 --test 4532 --test 4535 --test 4539

# DKIM x CHUNKING without TLS, and PRDR x CHUNKING.
# NOTE: separate invocations — one run cannot span two script directories.
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue \
  --test 4511 --test 4512 --test 4515 --test 4519
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue \
  --test 5590 --test 5591

# Whole categories
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue --range 2000 2099
# expect: 25 scripts completed, 0 failures
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue --range 1100 1199
sudo -u eximtest ./runtest /tmp/exim-openssl/build-Linux-x86_64/exim --continue --range 2100 2199

# Final gate — the full automatic range (long-running)
sudo -u eximtest ./runtest /tmp/exim-gnutls/build-Linux-x86_64/exim --continue 1 8999 \
  2>&1 | tee /tmp/full-range.log
grep -c "Script completed" /tmp/full-range.log
grep -c "Comparison of" /tmp/full-range.log
```

**Always run paired against the baseline.** An absolute pass count means little; only the delta does.

```bash
rm -rf /tmp/exim-base-src && mkdir -p /tmp/exim-base-src
git -C "$REPO" archive 8c8eec613ae51b6f0bb236f6a1b9639c2cad567e src \
  | tar -x -C /tmp/exim-base-src
rm -rf /tmp/exim-base && mv /tmp/exim-base-src/src /tmp/exim-base
./build-exim.sh /tmp/exim-base gnutls
# then re-run any range against /tmp/exim-base/build-Linux-x86_64/exim and diff
# the failure sets. A test failing on BOTH is not a regression.
```

## 9.6 Expected residual failures

Twelve tests fail in this container and **all twelve fail identically on the pre-fix baseline**:

| Test(s) | Cause |
|---|---|
| `1166`, `1199`, `4506`, `5820`, `5890`, `5891`, `2190` | Library log text differs from the saved reference — the installed GnuTLS/OpenSSL are newer than the recording host's. `1166`'s diff is a single extra `TLS error on connection (recv): The TLS connection was non-properly terminated.` line. |
| `1090`, `4058` | Kernel TCP-Fast-Open cookie state. `4058` is nondeterministic — one failure in five runs on **both** builds. |
| `4517` | DKIM signature bytes depend on the signing host's name. |
| `0630` | A retry-database debug line this host does not emit. |
| `5705`, `5706` | Upstream omission: both carry a server block but neither a saved transcript nor the directive every sibling of the same shape carries. |

Do **not** "fix" these by rewriting references — that would encode this container's library versions into the project's golden expectations and mask real regressions. Re-run on a host matching the reference envelope instead.

## 9.7 Runtime validation

```bash
CONF=/tmp/exim-rt; PORT=11081
rm -rf "$CONF" && mkdir -p "$CONF"/{log,spool,mail} && chmod 777 "$CONF" "$CONF"/{log,spool,mail}

# Self-signed certificate for the test daemon
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=testhost.runtime.test" \
  -keyout "$CONF/key.pem" -out "$CONF/cert.pem" 2>/dev/null
sudo chown root:exim "$CONF/cert.pem" "$CONF/key.pem" && sudo chmod 640 "$CONF/cert.pem" "$CONF/key.pem"

cat > "$CONF/exim.conf" <<EOF
exim_path = /tmp/exim-gnutls/build-Linux-x86_64/exim
primary_hostname = testhost.runtime.test
domainlist local_domains = @ : runtime.test : localhost
spool_directory = $CONF/spool
log_file_path = $CONF/log/%slog
daemon_smtp_ports = $PORT
chunking_advertise_hosts = *
tls_advertise_hosts = *
tls_certificate = $CONF/cert.pem
tls_privatekey = $CONF/key.pem
host_lookup =
rfc1413_query_timeout = 0s
acl_smtp_rcpt = acl_check_rcpt
trusted_users = root : exim
log_selector = +smtp_connection +tls_peerdn +received_recipients
begin acl
acl_check_rcpt:
  accept  domains = +local_domains
  deny    message = relay not permitted
begin routers
localuser:
  driver = accept
  domains = +local_domains
  transport = local_delivery
begin transports
local_delivery:
  driver = appendfile
  file = $CONF/mail/inbox
  create_file = anywhere
  user = exim
  group = exim
EOF

# Avoid a "lost privilege for using -C option" panic-log entry from the
# delivery subprocess by trusting this config path.
echo "$CONF/exim.conf" | sudo tee -a "$REPO/test/trusted_configs"

# Start the daemon
/tmp/exim-gnutls/build-Linux-x86_64/exim -C "$CONF/exim.conf" -bd -oX "$PORT"
sleep 2
ss -lntp | grep ":$PORT"        # expect two listeners (IPv4 and IPv6)
```

Confirm the configuration semantics are unchanged:

```bash
/tmp/exim-gnutls/build-Linux-x86_64/exim -C "$CONF/exim.conf" \
  -bP chunking_advertise_hosts tls_advertise_hosts smtp_receive_timeout
# chunking_advertise_hosts = *
# tls_advertise_hosts = *
# smtp_receive_timeout = 5m
```

## 9.8 Example usage

**The vulnerability reproducer.** Declares a chunk, sends less than it declared, then tears TLS down while holding the socket open.

```bash
cat > /tmp/poc.script <<'EOF'
??? 220
EHLO poc.client.test
??? 250-
???*
STARTTLS
??? 220
EHLO poc.client.test
??? 250-
???*
MAIL FROM:<poc@runtime.test>
??? 250
RCPT TO:<rcpt@runtime.test>
??? 250
BDAT 85 LAST
>>> To: Susan@random.com\r\nFrom: Sam@random.com\r\n\r\nbody-start-AAAAAAAAAAAAAAAAAAAAAAAAAAA
stoptls
??? 421
???*
EOF

cd "$REPO/test" && ./bin/client-gnutls 127.0.0.1 "$PORT" < /tmp/poc.script
```

Expected — **fail closed**:

```
Shutting down TLS encryption
??? 421
<<< 421 Lost incoming connection
???*
Expected EOF read
End of script
```

```bash
grep "lost while" "$CONF/log/mainlog"
# ... SMTP connection from (poc.client.test) [127.0.0.1] lost while reading message data
ls "$CONF/mail/"        # empty: the unfinished message was NOT accepted
```

**The happy path** — a fully sent chunk over TLS must still be delivered:

```bash
cat > /tmp/normal.script <<'EOF'
??? 220
EHLO poc.client.test
??? 250-
???*
STARTTLS
??? 220
EHLO poc.client.test
??? 250-
???*
MAIL FROM:<poc@runtime.test>
??? 250
RCPT TO:<rcpt@runtime.test>
??? 250
BDAT 74 LAST
>>> To: Susan@random.com\r\nFrom: Sam@random.com\r\n\r\nnormal-bdat-body-MARKER-OK\r\n
??? 250
EOF

cd "$REPO/test" && ./bin/client-gnutls 127.0.0.1 "$PORT" < /tmp/normal.script
grep -E "<=|=>|Completed" "$CONF/log/mainlog" | tail -3
grep -c "normal-bdat-body-MARKER-OK" "$CONF/mail/inbox"   # 1
```

Expected mainlog:

```
... <= poc@runtime.test H=(poc.client.test) [127.0.0.1] P=esmtps
    X=TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256:SECP256R1 K S=349
... => rcpt <rcpt@runtime.test> R=localuser T=local_delivery
... Completed
```

**Stop the daemon.** Target only the pid you started; never use `pkill`/`killall`, which on a shared host can match unrelated processes.

```bash
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  exe=$(readlink /proc/$p/exe 2>/dev/null) || continue
  [ "$(basename "${exe%% (deleted)}")" = exim ] || continue
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -q -- "-oX $PORT" && kill "$p"
done
ls "$CONF/log/paniclog" 2>/dev/null || echo "paniclog ABSENT - correct"
```

## 9.9 Memory-safety verification (the decisive check)

The harness has no sanitizer support and makes a setuid copy of the binary, which interacts badly with AddressSanitizer, so this runs outside the harness against a **non-setuid** ASAN daemon.

```bash
CONF=/tmp/exim-asan-rt; PORT=11091
# ... build $CONF exactly as in §9.7 but with:
#     exim_path         = /tmp/exim-asan/build-Linux-x86_64/exim
#     daemon_smtp_ports = 11091
mkdir -p "$CONF/asan" && chmod 777 "$CONF/asan"

ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=$CONF/asan/asan" \
  /tmp/exim-asan/build-Linux-x86_64/exim -C "$CONF/exim.conf" -bd -oX "$PORT"
sleep 3

cd "$REPO/test"
for s in /tmp/poc.script /tmp/normal.script; do
  ./bin/client-gnutls 127.0.0.1 "$PORT" < "$s"
done

# THE PASS CRITERION
echo "ASAN reports: $(ls "$CONF"/asan/ 2>/dev/null | wc -l)"   # must be 0
```

`detect_leaks=0` is deliberate: Exim intentionally leaks at exit, so leak detection would produce noise unrelated to this defect.

**The negative control is mandatory and ordered.** Build the baseline with ASAN, run the same reproducer, and confirm it *reports* before confirming the fix is clean. A reproducer that passes both ways proves nothing.

```bash
rm -rf /tmp/exim-base-asan && cp -a /tmp/exim-base /tmp/exim-base-asan   # pre-fix source
./build-exim.sh /tmp/exim-base-asan gnutls asan
# ... run the same PoC against it; expect:
#
# ERROR: AddressSanitizer: heap-use-after-free on address 0x...
# WRITE of size 1 at 0x... thread T0
#     #0 tls_ungetc              tls.c:510
#     #1 bdat_ungetc             smtp_in.c:969
#     #2 read_message_bdat_smtp  receive.c:1016
# freed by thread T0 here:
#     #2 store_free_3            store.c:1258
#     #3 tls_close               tls-gnu.c:3996
#     #4 tls_refill              tls-gnu.c:654
#     #5 tls_getc                tls-gnu.c:4022
#     #6 bdat_getc               smtp_in.c:763
# previously allocated by thread T0 here:
#     #2 store_malloc_3          store.c:1191
#     #3 tls_server_start        tls-gnu.c:3279
```

## 9.10 Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `Cannot determine the release number` | The checkout carries no git tags. | `export EXIM_RELEASE_VERSION=4.100` |
| `*** Exim's internal user must not be root.` | `EXIM_USER=root`. | Create a non-root `exim` user; set `EXIM_USER=exim`. |
| Undefined `db_env_create` / `db_create` | Berkeley DB not selected. | `USE_DB=yes` and `DBMLIB=-ldb` |
| Undefined `dane_state_init` / `dane_raw_tlsa` / `dane_verify_crt_raw` | DANE on GnuTLS needs a separate pkg-config module. | `USE_GNUTLS_PC="gnutls gnutls-dane"` |
| `runtest` hangs, or dies with `Failed to open /dev/tty` | Interactive mode: it prompts before starting and on every mismatch. | Always pass `--continue`. |
| `exim cannot access the test suite directory` / `Couldn't open ".../test/eximdir/exim"` | `eximdir/` lost group access for the `exim` group. | `sudo chown -R eximtest:exim test/eximdir test/spool && sudo chmod -R g+rX test/eximdir` |
| `Failed to read test scripts from 'scripts/XXXX-.../*'` | One invocation cannot span two script directories. | One invocation per directory, or use `--range`. |
| `*** Version mismatch / Exim binary: 4.100 / Git: 4.99.1-…` | Benign: no 4.100 tag exists in the checkout. | Ignore. |
| paniclog: `exim user lost privilege for using -C option` | The delivery subprocess re-execs with `-C` and the config is not trusted. | Append the config's absolute path to `test/trusted_configs` (root-owned, mode 644). **Tested fix.** |
| Many unexpected failures; `exim -bV` lacks `IPv6` | `HAVE_IPV6` is a build-time opt-in on Linux, commented out by default. | Add `HAVE_IPV6=YES` and enable IPv6 via sysctl, then rebuild. |
| Reproducers `2038`–`2040` fail unexpectedly | With `--tls <lib>`, `<lib>` selects the *client*, so the other backend answers as the server. | Hand the GnuTLS binary to `runtest` and **omit `--tls`**. |
| `runtest --valgrind` cannot start a daemon | An out-of-scope end-of-config read. | Not required by any success criterion; use AddressSanitizer, which is decisive here. |
| Sanitizer reports many leaks | Exim intentionally leaks at exit. | `ASAN_OPTIONS=detect_leaks=0:...` |

---

# 10. Appendices

## Appendix A — Command Reference

| Purpose | Command |
|---|---|
| Set repository root | `export REPO=/tmp/blitzy/exim/blitzy-6348374b-7242-4e22-b436-0e4b9434bebe_3d01b8` |
| Build GnuTLS flavour | `./build-exim.sh /tmp/exim-gnutls gnutls` |
| Build OpenSSL flavour | `./build-exim.sh /tmp/exim-openssl openssl` |
| Build GnuTLS + ASAN | `./build-exim.sh /tmp/exim-asan gnutls asan` |
| Build the pre-fix baseline | `git -C "$REPO" archive 8c8eec613 src \| tar -x -C /tmp/exim-base-src` then build |
| Verify a binary | `<tree>/build-Linux-x86_64/exim -bV` |
| Check the warning allow-list | `grep -E "warning:\|error:" <log> \| grep -v jobserver \| sort -u` |
| Run the reproducers | `cd test && sudo -u eximtest ./runtest <bin> --continue --test 2038 --test 2039 --test 2040` |
| Run a category | `cd test && sudo -u eximtest ./runtest <bin> --continue --range 2000 2099` |
| Run the full gate | `cd test && sudo -u eximtest ./runtest <bin> --continue 1 8999` |
| Start a daemon | `<bin> -C <conf> -bd -oX <port>` |
| Start an ASAN daemon | `ASAN_OPTIONS="detect_leaks=0:log_path=<dir>/asan/asan" <asan-bin> -C <conf> -bd -oX <port>` |
| Drive an SMTP script | `cd test && ./bin/client-gnutls 127.0.0.1 <port> < <script>` |
| Count sanitizer reports | `ls <dir>/asan/ \| wc -l` (must be 0) |
| Show effective options | `<bin> -C <conf> -bP chunking_advertise_hosts tls_advertise_hosts smtp_receive_timeout` |
| Review the change | `git diff 8c8eec613..HEAD -- src/src/` |
| Confirm scope compliance | `git diff --name-only 8c8eec613..HEAD -- src/src/transports src/src/auths src/src/lookups src/src/routers \| wc -l` (must be 0) |
| Confirm authorship | `git log --format="%an <%ae>" 8c8eec613..HEAD \| sort -u` |

> **Never** pass `--update` to `runtest` — it rewrites golden references and masks regressions. **Never** use `pkill`/`killall` to stop a daemon on a shared host.

## Appendix B — Port Reference

| Port | Role | Notes |
|---|---|---|
| 11071 / 11081 / 11091 | Ad-hoc runtime daemon (plain, guide, ASAN) | Any free high port works; set `daemon_smtp_ports` and `-oX` to the same value. |
| 25 / 465 / 587 | Production SMTP, submissions, submission | Not used by the harness. |
| Harness-allocated | Test-suite daemons and clients | Allocated from a base port; **must be a four-digit block** — a five-digit block breaks at least one test whose configuration hard-codes a four-digit port. Override with `--portbase`. |

## Appendix C — Key File Locations

| Path | Role | Change |
|---|---|---|
| `src/src/tls-gnu.c` | GnuTLS backend: buffer/session lifetime, allocation resets, ATRN de-aliasing, consumer guards | **Modified** +339 / −14 |
| `src/src/smtp_in.c` | BDAT reader-vector lifetime, session-gone latch, argument validation | **Modified** +258 / −15 |
| `src/src/tls.c` | Shared dispatch layer; textually includes the backend; holds `tls_ungetc` | **Modified** +5 |
| `src/src/functions.h` | Shared declarations | **Modified** +1 (one additive extern) |
| `test/scripts/2000-GnuTLS/2038` | Reproducer: TLS shutdown mid-chunk | **Created** |
| `test/scripts/2000-GnuTLS/2039` | Reproducer: TLS shutdown after a complete header line | **Created** |
| `test/scripts/2000-GnuTLS/2040` | Reproducer: TLS shutdown mid-body with a byte in clear | **Created** |
| `test/{confs,log,stdout}/2038`–`2040` | Reference artefacts (configs are symlinks to an existing CHUNKING config) | **Created** (9 files) |
| `doc/doc-txt/ChangeLog` | Audit trail — entries `JH/21`, `JH/22`, `JH/23` | **Modified** +40 |
| `doc/doc-txt/exim-security-2026-07-31.1/` | Advisory package: announcement, 32 KB report, timeline | **Created** (3 files) |
| `test/.gitignore` | Excludes harness-generated files, with an explanatory comment | **Modified** +10 |
| `src/src/tls-openssl.c` | Parity reference — the model for the fix | **Unchanged** (verified) |
| `src/src/receive.c` | Direct callers of the chunked readers | **Unchanged** (verified) |
| `src/src/globals.{c,h}`, `store.{c,h}`, `structs.h`, `atrn.c`, `readconf.c` | Consulted as evidence | **Unchanged** (verified) |
| `src/src/{transports,auths,lookups,routers,miscmods,hintsdb}/` | Out of scope by constraint | **0 files changed** each (verified) |
| `test/runtest`, `test/src/client.c`, `test/README` | Harness | **Unchanged** |
| `test/trusted_configs` | Trusted-config list holding a checkout-absolute path | Gitignored; regenerate per checkout |
| `SECURITY.md` | Disclosure policy and release convention | **Unchanged** (read as evidence) |

## Appendix D — Technology Versions

| Component | Verified in this container | AAP reference envelope | Note |
|---|---|---|---|
| Exim | 4.100 (development tree) | 4.100 | No git tags; `EXIM_RELEASE_VERSION` must be exported. |
| GCC | 13.4.0 | 13.3.0 | Drift |
| GNU Make | 4.4.1 | 4.3 | Drift |
| GnuTLS (+ `gnutls-dane`) | 3.8.9 | 3.8.3 | **Drift — primary cause of residual log-text failures** |
| OpenSSL | 3.5.3 | 3.0.13 | **Drift — cause of the `2190` failure** |
| PCRE2 | 10.46 | 10.42 | Drift |
| Perl (harness) | 5.40.1 | 5.38.2 | Drift |
| Berkeley DB | 5.3.28 | 5.3.28 | Match |
| AddressSanitizer runtime | `libasan.so.8` | `libasan.so.8` | Match |
| Dependency manifests | **None exist** | None exist | Confirmed by exhaustive search; manifest-based scanners are Not Applicable. |
| CI pipeline | **None exists** | None exists | No `workflows/` directory. |

## Appendix E — Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `EXIM_RELEASE_VERSION` | `4.100` | **Mandatory for building** — the checkout has no git tags. |
| `REPO` | absolute repository root | Used by the build script and by the harness's trusted-config path. |
| `ASAN_OPTIONS` | `detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=<dir>/asan/asan` | Sanitizer configuration. `detect_leaks=0` because Exim intentionally leaks at exit; `log_path` so the report survives the fork-per-connection child. |
| `CI` | `true` (optional) | Non-interactive tooling. |
| `DEBIAN_FRONTEND` | `noninteractive` | For unattended package installation. |

Build-time settings (in `Local/Makefile`, not the environment): `EXIM_USER=exim`, `EXIM_GROUP=exim`, `CONFIGURE_OWNER=eximtest`, `TRUSTED_CONFIG_LIST`, `WHITELIST_D_MACROS`, `CC=gcc-13`, `USE_GNUTLS` / `USE_OPENSSL`, `USE_GNUTLS_PC="gnutls gnutls-dane"`, `SUPPORT_DANE=yes`, `HAVE_IPV6=YES`, `USE_DB=yes`, `DBMLIB=-ldb`, `EXIM_MONITOR=` (empty).

Runtime options deliberately **unchanged**: `chunking_advertise_hosts = *`, `tls_advertise_hosts = *`, `smtp_receive_timeout = 5m`. No new runtime option was introduced.

## Appendix F — Developer Tools Guide

| Tool | Use | Invocation |
|---|---|---|
| **AddressSanitizer** | The decisive memory-safety gate. Detects this defect because the release path is a real `free()`. | Build with `-fsanitize=address`; run the daemon non-setuid with `ASAN_OPTIONS`; pass criterion is **zero report files**. |
| **GCC warnings** | The static-analysis gate. New warnings are failures. | `make 2>&1 \| grep -E "warning:\|error:"`; allow-list is the three documented pre-existing diagnostics. |
| **`test/runtest`** | Perl regression harness; compares every munged output surface byte-for-byte. | Always `--continue`; never `--update`; run as `eximtest`; one invocation per script directory. |
| **`test/bin/client-gnutls`** | Scriptable SMTP client with TLS. Supports `>>>` (send without trailing CRLF) and `stoptls` (shut TLS down while holding the socket open) — the two primitives the reproducers need. | `./bin/client-gnutls <host> <port> < script` |
| **`exim -bV`** | Version and compiled-in feature report. | Confirm `IPv6`, `GnuTLS`/`OpenSSL`, `DANE`, `DKIM`. |
| **`exim -bP <option>`** | Print effective option values. | Confirms no configuration-semantics drift. |
| **`exim -bd -oX <port>`** | Run as a daemon on a chosen port. | Runtime validation. |
| **`git diff`/`git archive`** | Review the change; reconstruct the pre-fix tree for the paired baseline. | `git archive 8c8eec613 src \| tar -x -C <dir>` |
| **Valgrind** | Not usable here — an out-of-scope end-of-config read prevents daemon startup. | Not required by any success criterion. |
| **Manifest scanners** (`npm audit`, `pip-audit`, `Snyk`, `cargo-audit`, OWASP Dependency-Check) | **Not applicable.** No manifest exists anywhere in the tree, so a "no vulnerabilities found" result would be meaningless. | Report as Not Applicable; the compiler and sanitizer gates are the equivalent assurance. |

## Appendix G — Glossary

| Term | Meaning |
|---|---|
| **BDAT** | The SMTP command that carries a body chunk, introduced by the `CHUNKING` extension (RFC 3030). A client declares a byte count and optionally marks the chunk `LAST`. |
| **CHUNKING** | ESMTP extension replacing dot-stuffed `DATA` with length-prefixed chunks. Advertised by default in Exim. |
| **STARTTLS** | ESMTP command upgrading a plaintext SMTP connection to TLS. Advertised by default. |
| **Use-after-free (UAF)** | Accessing memory after it has been released. A UAF *write* is the more severe form: attacker-influenced bytes land in a freed allocation, a classic precursor to remote code execution. |
| **Transfer buffer** | The per-session heap buffer into which decrypted TLS records are read before the SMTP layer consumes them. The object at the centre of this defect. |
| **Reader vector** | The set of function pointers the SMTP layer dispatches through to read input. The chunked layer saves the current set and installs its own, so two levels exist — and only the top level was being reset at teardown. |
| **Sentinel** | The convention that a null saved-reader pointer means "nothing pushed". Load-bearing: the push and pop both key on it, which is why the fix remaps the vector rather than clearing it. |
| **Fail closed** | On error or teardown, deny rather than degrade. Here: report end-of-file or an explicit error instead of silently continuing to read the socket in cleartext. |
| **Negative control** | Demonstrating that a test *fails* on the unfixed code before accepting that it passing on the fixed code means anything. Mandatory and order-sensitive for this project. |
| **ATRN** | Authenticated TURN — an SMTP extension that reverses the client/server roles on an established connection, requiring TLS state to be transplanted between contexts. Notable because it legitimately uses file descriptor 0, so liveness guards must test `< 0` rather than `== 0`. |
| **`spool_wireformat`** | An Exim option storing message bodies in wire format on the spool. Interacts with `CHUNKING`, hence its own regression witness. |
| **DKIM** | DomainKeys Identified Mail. Its verification feed is driven from the changed read path, and that intersection has broken before — hence dedicated witnesses. |
| **Munged output** | Harness-normalised output (timestamps, pids, hostnames replaced) compared byte-for-byte against a saved reference. Any drift, including a stray debug line, fails the test. |
| **AAP** | Agent Action Plan — the authoritative specification of scope, constraints, fix design and verification strategy for this project. |
| **`store_free`** | Exim's allocator wrapper that calls libc `free()` directly (not a pool release), which is precisely why AddressSanitizer detects this defect. |
