# Security report: shop-frontend dependencies

Dependency audit (mode 3) of `evals/fixtures/shop-frontend` · 2026-10-14T19:30:17Z

## 1. Run

- **Verification was not independent.** No isolated verifier agents were used; the same agent hunted and then validated, in that order, trying to disprove each candidate. Treat verdicts as single-reviewer.
- **Profile:** quick, a partial pass. **Scope:** package.json, package-lock.json and node_modules/colour-utilz (the whole folder). **Budget:** none set.
- **Source ref:** not a git repository; sha256 package.json e9aaca18…0037, package-lock.json 6b0d947d…460a, node_modules/colour-utilz/{index.js 8222b816…3b71, package.json 2d70bab7…51b9, setup.js f60a1a21…01ef}.
- **Execution:** sandboxed source-and-local only. Nothing from the target was installed, built or executed; the target is read-only. The base64 payload in colour-utilz was decoded as text by trusted code.
- **Network:** OSV (vulnerabilities and OpenSSF malicious packages), CISA KEV (catalog 2026.10.13), FIRST EPSS, and the npm popularity list for typosquat checks. The npm registry and the private registry were not queried.
- **Prior runs:** none found.
- **Out of scope:** first-party application code (mode 2 not requested, and none present).

**Assumptions**

- The folder is the dependency set of a public e-commerce web frontend (from its name, shop-frontend); package.json calls it fixture-app and no application source is present.
- ASVS level L2 (external application handling customer personal data). L3-only requirements such as v5.0.0-15.2.4 are named for reference, not used as the bar.
- Network use was limited to vulnerability databases (api.osv.dev, www.cisa.gov, api.first.org) and the npm popularity list the collector uses for typosquat checks. The npm registry and the private registry packages.example.internal were not queried, so package contents that are not on disk were not inspected.
- The user named the output directory, so it replaces the skill's default <parent>/<repo>-security-audit/run-<N>; it is outside the target.
- Sub-agents were not used: this run was delegated to a single agent instructed to do the work itself, so hunting and validation were done by the same agent in separate, ordered passes.

**Context**

- **system type:** Web application frontend (assumed from the folder name shop-frontend; no application source present)
- **component:** Third-party npm dependencies: package.json, package-lock.json (lockfileVersion 3) and the installed node_modules/colour-utilz
- **phase:** Build and supply chain
- **exposure:** Assumed external (public shop) · tenancy unknown · boundaries: third-party package code into developer machines and CI at install time (install hooks), and into the running application
- **data:** Assumed customer personal data and orders; payment handling unknown · tier-B regimes (PCI DSS) not assessed
- **identity:** Not visible in the target
- **integrations:** npm public registry (registry.npmjs.org) and a private registry (packages.example.internal)
- **ai context:** None: no model, RAG, agent or MCP component in the target
- **business domain:** E-commerce (moves money or value); fraud paths (MITRE F3, API6:2023) belong to a code audit and are out of scope here
- **asvs level:** L2 (assumption: external e-commerce application handling customer personal data)
- **out of scope:** OWASP LLM Top 10 2026, ASI Top 10 2026, NIST SP 800-218A, MITRE ATLAS, NIST AI RMF and AI 600-1: NOT APPLICABLE, no AI component; OWASP MASVS: NOT APPLICABLE, not a mobile app; NIST SP 800-190: NOT APPLICABLE, no container definitions in the target; Mode 2 code audit (ASVS V1-V14, Top 10:2025 A01/A05/A07, API Top 10): out of scope, not requested and no first-party source present; Tier B (PCI DSS): not assessed

## 2. Security posture

No known-malicious package (OpenSSF MAL-* via OSV) is in the dependency graph, and the one alarming install-time signal (eval of a base64 string in colour-utilz's postinstall script) is inert on review. Two packages still need owner answers before they can be trusted: expresss, which looks like a typosquat of express and whose code was not available, and colour-utilz, served from a private registry with no integrity hash. lodash 4.17.15 has six published advisories, including two code-injection issues in _.template; lodash 4.18.0 or later clears all six. Whether any of them is exploitable depends on application code that is not in this folder. Confirmed findings: 0. Needs validation: 8. Rejected: 1.

Static analysis finds known malware and indicators of malice; it cannot prove that a package is clean.

## 3. Confirmed findings

None.

## 4. Confirmed finding details

None. See FINDINGS-DETAIL.md.

## 5. NEEDS VALIDATION

No severity is assigned to these leads. Advisory severities are shown as GitHub published them (CVSS v3.1, not rescored), and KEV and EPSS are for prioritising only.

| Lead | Trace | Blocker | Next step (local) | Owner check |
|---|---|---|---|---|
| lodash@4.17.15: ReDoS in toNumber, trim and trimEnd (GHSA-29mw-wpgm-hmr9, CVE-2020-28500) (`dep-npm-lodash-4.17.15-GHSA-29mw-wpgm-hmr9`) | `package-lock.json:4` | No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `toNumber`, `trim` or `trimEnd` could be searched or traced, and whether attacker-influenced input reaches it is unknown. | In the full shop-frontend source, search for lodash's `toNumber`, `trim` or `trimEnd` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the string argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way. | None. |
| lodash@4.17.15: command injection via _.template (GHSA-35jh-r3h4-6jhm, CVE-2021-23337) (`dep-npm-lodash-4.17.15-GHSA-35jh-r3h4-6jhm`) | `package-lock.json:4` | No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `template` could be searched or traced, and whether attacker-influenced input reaches it is unknown. | In the full shop-frontend source, search for lodash's `template` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the `variable` option or the template text can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way. | None. |
| lodash@4.17.15: prototype property deletion via array paths in _.unset and _.omit (GHSA-f23m-r3pf-42rh, CVE-2026-2950) (`dep-npm-lodash-4.17.15-GHSA-f23m-r3pf-42rh`) | `package-lock.json:4` | No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `unset` or `omit` could be searched or traced, and whether attacker-influenced input reaches it is unknown. | In the full shop-frontend source, search for lodash's `unset` or `omit` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the path argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way. | None. |
| lodash@4.17.15: prototype pollution via zipObjectDeep, set and related functions (GHSA-p6mc-m468-83gw, CVE-2020-8203) (`dep-npm-lodash-4.17.15-GHSA-p6mc-m468-83gw`) | `package-lock.json:4` | No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `pick`, `set`, `setWith`, `update`, `updateWith` or `zipObjectDeep` could be searched or traced, and whether attacker-influenced input reaches it is unknown. | In the full shop-frontend source, search for lodash's `pick`, `set`, `setWith`, `update`, `updateWith` or `zipObjectDeep` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the path or key argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way. | None. |
| lodash@4.17.15: code injection via _.template imports key names (GHSA-r5fr-rjxr-66jc, CVE-2026-4800) (`dep-npm-lodash-4.17.15-GHSA-r5fr-rjxr-66jc`) | `package-lock.json:4` | No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `template` could be searched or traced, and whether attacker-influenced input reaches it is unknown. | In the full shop-frontend source, search for lodash's `template` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the `options.imports` key names, or whether Object.prototype can be polluted in the same process can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way. | None. |
| lodash@4.17.15: prototype property deletion via _.unset and _.omit (GHSA-xxjr-mmjv-4gpg, CVE-2025-13465) (`dep-npm-lodash-4.17.15-GHSA-xxjr-mmjv-4gpg`) | `package-lock.json:4` | No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `unset` or `omit` could be searched or traced, and whether attacker-influenced input reaches it is unknown. | In the full shop-frontend source, search for lodash's `unset` or `omit` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the path argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way. | None. |
| colour-utilz@1.0.0 resolves from a private registry with no integrity hash (`dep-source-npm-colour-utilz-1.0.0`) | `package-lock.json:6` | The intended registry for colour-utilz and the registry configuration used by developers and CI (.npmrc registry and scope mappings) are not in the target. Whether the name colour-utilz is registered on the public npm registry, and by whom, was not checked: this run's network permission covers vulnerability databases only. The tarball served by packages.example.internal could not be compared with the installed copy: the host is private and the lockfile has no integrity value to compare against. | Obtain colour-utilz-1.0.0.tgz from the internal registry into an empty directory, list and extract it with tar without running anything, and compare file hashes with the installed copy (sha256 index.js 8222b816…3b71, package.json 2d70bab7…51b9, setup.js f60a1a21…01ef). Any difference is decisive: review the differing files as a malware lead. | Owners confirm that colour-utilz is an internal package and that packages.example.internal is its intended registry; show the .npmrc used by developers and CI and confirm unscoped names cannot resolve from registry.npmjs.org (or move the package to an org scope mapped to the internal registry); run `npm view colour-utilz --registry=https://registry.npmjs.org` (metadata only, no install) to see whether a public package with this name exists; then regenerate the lockfile so the entry carries an integrity value. |
| expresss@4.18.2 looks like a typosquat of express (`dep-typo-npm-expresss-4.18.2`) | `package-lock.json:5` | Whether expresss was chosen on purpose is a fact only the owners know. The contents, install scripts, publisher and history of expresss@4.18.2 were not inspected: the package is not installed in the target, and this run's network permission covers vulnerability databases only (the npm registry was not queried). | Download https://registry.npmjs.org/expresss/-/expresss-4.18.2.tgz into an empty scratch directory without npm (for example with curl), list and extract it with tar, and read package.json scripts and every file without executing anything, looking for install hooks, network calls, environment or credential reads and encoded payloads. Concrete malicious behaviour promotes this record to confirmed (critical; treat machines and CI that installed it as compromised). A benign or placeholder package still has to be replaced if express was meant. | Owners confirm whether `express` was intended. Until then, do not run npm install or npm ci for this project outside a disposable sandbox. Compare `npm view expresss` with `npm view express` (metadata only): maintainers, repository, publish dates and download counts. |

**What to do now, in order**

1. **expresss:** ask whoever added it whether `express` was meant. If so, replace it with `express` at 4.20.0 or later (OSV lists GHSA-rv95-896h-c2vc, fixed in 4.19.2, and GHSA-qw6h-vgh9-j6wx, fixed in 4.20.0, for express 4.18.2), and check the chosen version against OSV. Until it is answered, do not install this project outside a disposable sandbox.
2. **lodash:** upgrade to 4.18.0 or later. That single change clears all six advisories, whatever the reachability answer turns out to be.
3. **colour-utilz:** confirm the internal registry is intended, move the package under an org scope mapped to that registry in .npmrc, compare the registry tarball with the installed copy, and regenerate the lockfile so it carries an integrity value.
4. Apply the hardening notes below (integrity for every entry, scripts disabled by default).

Sources for the open leads: OWASP ASVS 5.0.0 v5.0.0-15.2.1 and v5.0.0-15.1.2 (references/standards/owasp-asvs-5.0.0.md); NIST SSDF 1.1 PW.4.1 and PW.4.4 (references/standards/nist-ssdf-800-218.md); MITRE CWE 4.20 CWE-1395 and CWE-1357 (references/standards/cwe/weaknesses.md); OWASP Top 10 2025 A03:2025 (references/standards/owasp-top10-2025.md); MITRE ATT&CK 20.0 T1195.001 (references/standards/mitre-attack/enterprise-techniques.md).

**Rejected candidate (kept so later runs do not repeat it)**

- `dep-signal-npm-colour-utilz-1.0.0`, colour-utilz@1.0.0: decode-and-eval in its postinstall script (inert on review): Refuted from source. All three files of the installed package were read in full (328 bytes, ASCII only, no symlinks or hidden files). The decoded payload is a comment, the eval is dead code behind if (false), and nothing in the package touches the network, the file system, environment variables or child processes. The comment on setup.js line 1 that calls the file an inert fixture is text from the audited package and was not relied on; the verdict rests on the decoded payload and the dead branch. A package that does nothing but ship an install hook is still worth questioning, but that is a provenance question, not malicious code.

## 6. Hardening notes and positive patterns

**Hardening notes (process gaps, not findings)**

- package-lock.json: two of the three entries (expresss at line 5, colour-utilz at line 6) carry no `integrity` value, so npm cannot detect a changed tarball for them; only lodash (line 4) is pinned by sha512. Regenerate the lockfile from the intended registries so every entry has one. Sources: NIST SSDF 1.1 PW.4.4, notional example 6 (references/standards/nist-ssdf-800-218.md); MITRE CWE 4.20 CWE-494 (references/standards/cwe/weaknesses.md).
- Install scripts: colour-utilz runs a postinstall hook (`node setup.js`), so every npm install or npm ci executes third-party code with the developer's or CI runner's privileges. Install with scripts disabled by default (`npm ci --ignore-scripts`, or `ignore-scripts=true` in the project .npmrc) and run the few build steps that genuinely need scripts explicitly. Sources: MITRE ATT&CK 20.0 T1195.001 (references/standards/mitre-attack/enterprise-techniques.md); NIST SSDF 1.1 PW.4.1 (references/standards/nist-ssdf-800-218.md).
- node_modules does not match package-lock.json: only colour-utilz is installed, while lodash and expresss are locked but absent. Do not ship or reuse this node_modules; reinstall from a reviewed lockfile with npm ci (scripts disabled) once the open questions are answered. Source: NIST SSDF 1.1 PW.4.4 (references/standards/nist-ssdf-800-218.md).
- Remediation time frames: ASVS v5.0.0-15.2.1 is judged against documented update and remediation time frames (v5.0.0-15.1.1, L1), and none are visible in the target. The lodash advisories found here were published between July 2020 (GHSA-p6mc-m468-83gw) and April 2026 (GHSA-f23m-r3pf-42rh, GHSA-r5fr-rjxr-66jc). Write the time frames down so 15.2.1 can be judged. Sources: OWASP ASVS 5.0.0 v5.0.0-15.1.1 and v5.0.0-15.2.1 (references/standards/owasp-asvs-5.0.0.md).

**Positive patterns**

- All three direct dependencies are exact pins (no ranges) in package.json.
- A lockfile (lockfileVersion 3) is present, and the lodash entry carries an sha512 integrity value.
- The project's own package.json defines no install-time scripts.

## 7. Coverage

Ledger units: 6 · blocked 2, candidate 2, covered 1, out_of_scope 1.

- **First-party application code that calls the dependencies**: out_of_scope; unresolved: No first-party source is present in the target and mode 2 (code audit) was not requested; reachability of the lodash advisories depends on it.
- **node_modules/colour-utilz (installed package code and install hook)**: candidate; results: `dep-signal-npm-colour-utilz-1.0.0`
- **expresss@4.18.2 package contents**: blocked; unresolved: expresss@4.18.2 contents and install scripts NOT VERIFIED: not installed in the target, and fetching the registry tarball was outside this run's network permission (vulnerability databases only).
- **lodash@4.17.15 package contents**: blocked; unresolved: lodash@4.17.15 contents NOT VERIFIED in place: not installed in the target. Its integrity value pins the public registry tarball, and its known advisories are recorded under package-lock.json.
- **package-lock.json (resolved dependency graph, lockfileVersion 3)**: candidate; results: `dep-npm-lodash-4.17.15-GHSA-29mw-wpgm-hmr9`, `dep-npm-lodash-4.17.15-GHSA-35jh-r3h4-6jhm`, `dep-npm-lodash-4.17.15-GHSA-f23m-r3pf-42rh`, `dep-npm-lodash-4.17.15-GHSA-p6mc-m468-83gw`, `dep-npm-lodash-4.17.15-GHSA-r5fr-rjxr-66jc`, `dep-npm-lodash-4.17.15-GHSA-xxjr-mmjv-4gpg`, `dep-source-npm-colour-utilz-1.0.0`, `dep-typo-npm-expresss-4.18.2`; unresolved: Reachability of the lodash advisories depends on application source that is not in the target. Intended name of expresss and intended registry of colour-utilz are owner facts.
- **package.json (direct dependency declarations and project scripts)**: covered

Quick profile: one hunting pass and one validation pass, with no separate coverage critic. No claim is made that this run exhausts the target. Not verified in this run:

- Contents of expresss@4.18.2 and lodash@4.17.15: not installed in the target, npm registry not queried.
- Whether the installed colour-utilz matches the tarball on packages.example.internal: private host, no integrity value.
- Reachability of the six lodash advisories: no application source in the target.

## Files

- `security-report.html`: self-contained report with a mitigation-prompt panel
- `findings.json`, `coverage-ledger.json`, `run-metadata.json`: validated records
- `NEEDS-VALIDATION.md`, `FINDINGS-DETAIL.md`, `architecture.md`
- `sbom.cdx.json` (CycloneDX 1.6), `deps-raw.json`, `deps-findings.json`: collector outputs
