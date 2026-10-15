# Needs validation: shop-frontend dependency audit

Leads, not confirmed vulnerabilities. They carry no severity. Each needs the fact named under *Blocker* before it can be confirmed or rejected. Generated from findings.json.

## lodash@4.17.15: ReDoS in toNumber, trim and trimEnd (GHSA-29mw-wpgm-hmr9, CVE-2020-28500)

- **Fingerprint:** `dep-npm-lodash-4.17.15-GHSA-29mw-wpgm-hmr9`
- **Package:** npm lodash@4.17.15 · fixed in 4.17.21 · advisories CVE-2020-28500, GHSA-29mw-wpgm-hmr9
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** lodash 4.17.15 is inside the affected range of GHSA-29mw-wpgm-hmr9; the effect applies only if application code calls lodash's `toNumber`, `trim` or `trimEnd` with a long string an attacker controls, which has not been established.

Regular-expression denial of service: a long, crafted string passed to `_.toNumber`, `_.trim` or `_.trimEnd` takes super-linear time and blocks the thread that runs it. Affected: lodash >= 4.0.0 and < 4.17.21; fixed in lodash 4.17.21. The project pins lodash 4.17.15 (package.json:1, package-lock.json:4), inside that range. Advisory severity as published by GitHub, not this audit's severity: MODERATE, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L; advisory CWEs CWE-1333, CWE-400. Priority only: not in the CISA KEV catalog (version 2026.10.13); EPSS 0.07. Upgrading lodash to 4.18.0 or later clears this and the other five lodash advisories.

**Source trace**

- `package-lock.json:4` (sink, lodash@4.17.15): The lockfile resolves the affected lodash version that every install receives.

**Evidence**

- `package.json:1`: Direct dependency "lodash": "4.17.15" (exact pin).
- `package-lock.json:4`: Resolved lodash 4.17.15 from registry.npmjs.org with an sha512 integrity value; OSV GHSA-29mw-wpgm-hmr9 affects lodash >= 4.0.0 and < 4.17.21, fixed in 4.17.21.

**Blocker**

- No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `toNumber`, `trim` or `trimEnd` could be searched or traced, and whether attacker-influenced input reaches it is unknown.

**How to resolve it**

- Local, bounded: In the full shop-frontend source, search for lodash's `toNumber`, `trim` or `trimEnd` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the string argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.2.1 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1395 (weakness; references/standards/cwe/weaknesses.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## lodash@4.17.15: command injection via _.template (GHSA-35jh-r3h4-6jhm, CVE-2021-23337)

- **Fingerprint:** `dep-npm-lodash-4.17.15-GHSA-35jh-r3h4-6jhm`
- **Package:** npm lodash@4.17.15 · fixed in 4.17.21 · advisories CVE-2021-23337, CVE-2026-4800, GHSA-35jh-r3h4-6jhm, GHSA-r5fr-rjxr-66jc
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** lodash 4.17.15 is inside the affected range of GHSA-35jh-r3h4-6jhm; the effect applies only if application code calls lodash's `template` with an attacker-influenced `variable` option or template text, which has not been established.

Code injection in `_.template`: a value that reaches the `variable` option is placed into source compiled by the `Function()` constructor, so whoever controls it runs code where the template is compiled. Affected: lodash < 4.17.21; fixed in lodash 4.17.21. The project pins lodash 4.17.15 (package.json:1, package-lock.json:4), inside that range. Advisory severity as published by GitHub, not this audit's severity: HIGH, CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H; advisory CWEs CWE-77, CWE-94. Priority only: not in the CISA KEV catalog (version 2026.10.13); EPSS 0.21. OSV lists GHSA-r5fr-rjxr-66jc (CVE-2026-4800, the later bypass of this fix) as an alias; it is kept as a separate record because it reaches the sink through a different option. Upgrading lodash to 4.18.0 or later clears this and the other five lodash advisories.

**Source trace**

- `package-lock.json:4` (sink, lodash@4.17.15): The lockfile resolves the affected lodash version that every install receives.

**Evidence**

- `package.json:1`: Direct dependency "lodash": "4.17.15" (exact pin).
- `package-lock.json:4`: Resolved lodash 4.17.15 from registry.npmjs.org with an sha512 integrity value; OSV GHSA-35jh-r3h4-6jhm affects lodash < 4.17.21, fixed in 4.17.21.

**Blocker**

- No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `template` could be searched or traced, and whether attacker-influenced input reaches it is unknown.

**How to resolve it**

- Local, bounded: In the full shop-frontend source, search for lodash's `template` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the `variable` option or the template text can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.2.1 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1395 (weakness; references/standards/cwe/weaknesses.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## lodash@4.17.15: prototype property deletion via array paths in _.unset and _.omit (GHSA-f23m-r3pf-42rh, CVE-2026-2950)

- **Fingerprint:** `dep-npm-lodash-4.17.15-GHSA-f23m-r3pf-42rh`
- **Package:** npm lodash@4.17.15 · fixed in 4.18.0 · advisories CVE-2025-13465, CVE-2026-2950, GHSA-f23m-r3pf-42rh, GHSA-xxjr-mmjv-4gpg
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** lodash 4.17.15 is inside the affected range of GHSA-f23m-r3pf-42rh; the effect applies only if application code calls lodash's `unset` or `omit` with an attacker-influenced path, which has not been established.

Bypass of the 4.17.23 fix for CVE-2025-13465: array-wrapped path segments passed to `_.unset` or `_.omit` still delete properties from Object.prototype, Number.prototype and String.prototype (deletion only, no overwrite). Affected: lodash < 4.18.0 (last affected 4.17.23); fixed in lodash 4.18.0. The project pins lodash 4.17.15 (package.json:1, package-lock.json:4), inside that range. Advisory severity as published by GitHub, not this audit's severity: MODERATE, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L; advisory CWEs CWE-1321. Priority only: not in the CISA KEV catalog (version 2026.10.13); EPSS 0.02. OSV lists GHSA-xxjr-mmjv-4gpg (the original CVE-2025-13465 advisory) as an alias; it is kept as a separate record because 4.17.23 fixes that one but not this bypass. Upgrading lodash to 4.18.0 or later clears this and the other five lodash advisories.

**Source trace**

- `package-lock.json:4` (sink, lodash@4.17.15): The lockfile resolves the affected lodash version that every install receives.

**Evidence**

- `package.json:1`: Direct dependency "lodash": "4.17.15" (exact pin).
- `package-lock.json:4`: Resolved lodash 4.17.15 from registry.npmjs.org with an sha512 integrity value; OSV GHSA-f23m-r3pf-42rh affects lodash < 4.18.0 (last affected 4.17.23), fixed in 4.18.0.

**Blocker**

- No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `unset` or `omit` could be searched or traced, and whether attacker-influenced input reaches it is unknown.

**How to resolve it**

- Local, bounded: In the full shop-frontend source, search for lodash's `unset` or `omit` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the path argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.2.1 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1395 (weakness; references/standards/cwe/weaknesses.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## lodash@4.17.15: prototype pollution via zipObjectDeep, set and related functions (GHSA-p6mc-m468-83gw, CVE-2020-8203)

- **Fingerprint:** `dep-npm-lodash-4.17.15-GHSA-p6mc-m468-83gw`
- **Package:** npm lodash@4.17.15 · fixed in 4.17.19 · advisories CVE-2020-8203, GHSA-p6mc-m468-83gw
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** lodash 4.17.15 is inside the affected range of GHSA-p6mc-m468-83gw; the effect applies only if application code calls lodash's `pick`, `set`, `setWith`, `update`, `updateWith` or `zipObjectDeep` with an attacker-influenced path or key, which has not been established.

Prototype pollution: `pick`, `set`, `setWith`, `update`, `updateWith` and `zipObjectDeep` accept property paths such as `__proto__`, so user-supplied paths can add or change properties on Object.prototype, leading to denial of service or, in specific circumstances, code execution. Affected: lodash >= 3.7.0 and < 4.17.19; fixed in lodash 4.17.19. The project pins lodash 4.17.15 (package.json:1, package-lock.json:4), inside that range. Advisory severity as published by GitHub, not this audit's severity: HIGH, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H; advisory CWEs CWE-1321, CWE-770. Priority only: not in the CISA KEV catalog (version 2026.10.13); EPSS 0.05. The collector also listed 4.17.20 as a fixed version; that is the lodash-es fix, so this record keeps lodash's own fix, 4.17.19. Upgrading lodash to 4.18.0 or later clears this and the other five lodash advisories.

**Source trace**

- `package-lock.json:4` (sink, lodash@4.17.15): The lockfile resolves the affected lodash version that every install receives.

**Evidence**

- `package.json:1`: Direct dependency "lodash": "4.17.15" (exact pin).
- `package-lock.json:4`: Resolved lodash 4.17.15 from registry.npmjs.org with an sha512 integrity value; OSV GHSA-p6mc-m468-83gw affects lodash >= 3.7.0 and < 4.17.19, fixed in 4.17.19.

**Blocker**

- No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `pick`, `set`, `setWith`, `update`, `updateWith` or `zipObjectDeep` could be searched or traced, and whether attacker-influenced input reaches it is unknown.

**How to resolve it**

- Local, bounded: In the full shop-frontend source, search for lodash's `pick`, `set`, `setWith`, `update`, `updateWith` or `zipObjectDeep` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the path or key argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.2.1 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1395 (weakness; references/standards/cwe/weaknesses.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## lodash@4.17.15: code injection via _.template imports key names (GHSA-r5fr-rjxr-66jc, CVE-2026-4800)

- **Fingerprint:** `dep-npm-lodash-4.17.15-GHSA-r5fr-rjxr-66jc`
- **Package:** npm lodash@4.17.15 · fixed in 4.18.0 · advisories CVE-2021-23337, CVE-2026-4800, GHSA-35jh-r3h4-6jhm, GHSA-r5fr-rjxr-66jc
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** lodash 4.17.15 is inside the affected range of GHSA-r5fr-rjxr-66jc; the effect applies only if application code calls lodash's `template` with attacker-influenced `options.imports` keys (or after Object.prototype has been polluted), which has not been established.

Code injection in `_.template`: key names in `options.imports` flow, unvalidated, into the same `Function()` constructor, and inherited keys from a polluted Object.prototype are copied in too. This is the bypass of the 4.17.21 fix for CVE-2021-23337. Affected: lodash >= 4.0.0 and < 4.18.0; fixed in lodash 4.18.0. The project pins lodash 4.17.15 (package.json:1, package-lock.json:4), inside that range. Advisory severity as published by GitHub, not this audit's severity: HIGH, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H; advisory CWEs CWE-94. Priority only: not in the CISA KEV catalog (version 2026.10.13); EPSS 0.21 (highest among its OSV aliases). OSV lists GHSA-35jh-r3h4-6jhm (CVE-2021-23337) as an alias; it is kept as a separate record because 4.17.21 fixes that one but not this bypass. Upgrading lodash to 4.18.0 or later clears this and the other five lodash advisories.

**Source trace**

- `package-lock.json:4` (sink, lodash@4.17.15): The lockfile resolves the affected lodash version that every install receives.

**Evidence**

- `package.json:1`: Direct dependency "lodash": "4.17.15" (exact pin).
- `package-lock.json:4`: Resolved lodash 4.17.15 from registry.npmjs.org with an sha512 integrity value; OSV GHSA-r5fr-rjxr-66jc affects lodash >= 4.0.0 and < 4.18.0, fixed in 4.18.0.

**Blocker**

- No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `template` could be searched or traced, and whether attacker-influenced input reaches it is unknown.

**How to resolve it**

- Local, bounded: In the full shop-frontend source, search for lodash's `template` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the `options.imports` key names, or whether Object.prototype can be polluted in the same process can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.2.1 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1395 (weakness; references/standards/cwe/weaknesses.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## lodash@4.17.15: prototype property deletion via _.unset and _.omit (GHSA-xxjr-mmjv-4gpg, CVE-2025-13465)

- **Fingerprint:** `dep-npm-lodash-4.17.15-GHSA-xxjr-mmjv-4gpg`
- **Package:** npm lodash@4.17.15 · fixed in 4.17.23 · advisories CVE-2025-13465, CVE-2026-2950, GHSA-f23m-r3pf-42rh, GHSA-xxjr-mmjv-4gpg
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** lodash 4.17.15 is inside the affected range of GHSA-xxjr-mmjv-4gpg; the effect applies only if application code calls lodash's `unset` or `omit` with an attacker-influenced path, which has not been established.

Prototype pollution by deletion: crafted paths passed to `_.unset` or `_.omit` delete methods from global prototypes. Properties can be removed, not overwritten. Affected: lodash >= 4.0.0 and < 4.17.23; fixed in lodash 4.17.23. The project pins lodash 4.17.15 (package.json:1, package-lock.json:4), inside that range. Advisory severity as published by GitHub, not this audit's severity: MODERATE, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L (GitHub also publishes CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P); advisory CWEs CWE-1321. Priority only: not in the CISA KEV catalog (version 2026.10.13); EPSS 0.02. Upgrading lodash to 4.18.0 or later clears this and the other five lodash advisories.

**Source trace**

- `package-lock.json:4` (sink, lodash@4.17.15): The lockfile resolves the affected lodash version that every install receives.

**Evidence**

- `package.json:1`: Direct dependency "lodash": "4.17.15" (exact pin).
- `package-lock.json:4`: Resolved lodash 4.17.15 from registry.npmjs.org with an sha512 integrity value; OSV GHSA-xxjr-mmjv-4gpg affects lodash >= 4.0.0 and < 4.17.23, fixed in 4.17.23.

**Blocker**

- No application source is in the target (it holds only package.json, package-lock.json and node_modules/colour-utilz), so no call path to lodash's `unset` or `omit` could be searched or traced, and whether attacker-influenced input reaches it is unknown.

**How to resolve it**

- Local, bounded: In the full shop-frontend source, search for lodash's `unset` or `omit` (as `_.<name>`, named imports from 'lodash', or 'lodash/<name>' modules). For each call, trace whether the path argument can come from a user, URL, API response or CMS content. If it can, reproduce with a dummy value against lodash 4.17.15 in a sandbox with no network and promote this record to confirmed; if no call is reachable, reject it with that reason. Upgrading to lodash >= 4.18.0 removes the question either way.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.2.1 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1395 (weakness; references/standards/cwe/weaknesses.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## colour-utilz@1.0.0 resolves from a private registry with no integrity hash

- **Fingerprint:** `dep-source-npm-colour-utilz-1.0.0`
- **Package:** npm colour-utilz@1.0.0
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** An unscoped package from a private registry, with no integrity pin, can be replaced by a same-named public package (dependency confusion) or by different content on the private host, and its install hook would then run attacker code at install time.

package-lock.json:6 resolves colour-utilz from https://packages.example.internal/colour-utilz-1.0.0.tgz, while the rest of the graph comes from registry.npmjs.org. The entry has no `integrity` value, and it does not record `hasInstallScript` although the installed copy declares a postinstall hook, so the copy in node_modules cannot be tied to the artifact the lockfile names. The name is unscoped, which is the precondition for dependency confusion: if the registry configuration lets unscoped names resolve from the public registry, a public package called colour-utilz would be picked up on the next resolution and its install hook would run on developer machines and CI. OSV has no advisory or MAL-* entry for colour-utilz. The run assumes ASVS L2; at L3 the direct requirement is v5.0.0-15.2.4.

**Source trace**

- `package-lock.json:6` (sink, colour-utilz): Resolved URL on packages.example.internal, no integrity value, no hasInstallScript.

**Evidence**

- `package.json:1`: Direct dependency "colour-utilz": "1.0.0" (unscoped name).
- `package-lock.json:6`: resolved: https://packages.example.internal/colour-utilz-1.0.0.tgz; no integrity field.
- `node_modules/colour-utilz/package.json:1`: The installed copy declares "postinstall": "node setup.js", which the lockfile entry does not record.

**Blocker**

- The intended registry for colour-utilz and the registry configuration used by developers and CI (.npmrc registry and scope mappings) are not in the target.
- Whether the name colour-utilz is registered on the public npm registry, and by whom, was not checked: this run's network permission covers vulnerability databases only.
- The tarball served by packages.example.internal could not be compared with the installed copy: the host is private and the lockfile has no integrity value to compare against.

**How to resolve it**

- Local, bounded: Obtain colour-utilz-1.0.0.tgz from the internal registry into an empty directory, list and extract it with tar without running anything, and compare file hashes with the installed copy (sha256 index.js 8222b816…3b71, package.json 2d70bab7…51b9, setup.js f60a1a21…01ef). Any difference is decisive: review the differing files as a malware lead.
- Owner-observed: Owners confirm that colour-utilz is an internal package and that packages.example.internal is its intended registry; show the .npmrc used by developers and CI and confirm unscoped names cannot resolve from registry.npmjs.org (or move the package to an org scope mapped to the internal registry); run `npm view colour-utilz --registry=https://registry.npmjs.org` (metadata only, no install) to see whether a public package with this name exists; then regenerate the lockfile so the entry carries an integrity value.

**Sources**

- OWASP ASVS 5.0.0 v5.0.0-15.1.2 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1357 (weakness; references/standards/cwe/weaknesses.md)
- MITRE ATT&CK 20.0 T1195.001 (attack-technique; references/standards/mitre-attack/enterprise-techniques.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)

## expresss@4.18.2 looks like a typosquat of express

- **Fingerprint:** `dep-typo-npm-expresss-4.18.2`
- **Package:** npm expresss@4.18.2
- **Affected boundary:** third-party code entering developer machines, CI and the application
- **Claimed root cause:** The project may depend on expresss by mistake instead of express; a typosquatted package runs its publisher's code at install time (install hooks) and at runtime with the application's privileges.

package.json declares `expresss` (three s), one character away from the widely used `express`, at version 4.18.2, the same number as a real express release, so the name is easy to mistake for express and its version looks familiar. The lockfile entry (package-lock.json:5) has no integrity value and records no dependencies of its own, whereas the real express 4.18.2 pulls in its own dependency tree (body-parser, send, serve-static and others), so expresss is not a drop-in copy of express. Its code is not present in node_modules, so its contents and install scripts were not inspected. OSV has no vulnerability or MAL-* entry for expresss on any version: there is no known-malicious match, which does not show the package is clean. If express was intended, note that OSV lists two advisories for express 4.18.2 itself (GHSA-rv95-896h-c2vc, fixed in 4.19.2, and GHSA-qw6h-vgh9-j6wx, fixed in 4.20.0).

**Source trace**

- `package-lock.json:5` (sink, expresss): Resolved package name expresss, one edit from express; no integrity value.

**Evidence**

- `package.json:1`: Direct dependency "expresss": "4.18.2".
- `package-lock.json:5`: resolved: https://registry.npmjs.org/expresss/-/expresss-4.18.2.tgz; no integrity field and no dependencies recorded.

**Blocker**

- Whether expresss was chosen on purpose is a fact only the owners know.
- The contents, install scripts, publisher and history of expresss@4.18.2 were not inspected: the package is not installed in the target, and this run's network permission covers vulnerability databases only (the npm registry was not queried).

**How to resolve it**

- Local, bounded: Download https://registry.npmjs.org/expresss/-/expresss-4.18.2.tgz into an empty scratch directory without npm (for example with curl), list and extract it with tar, and read package.json scripts and every file without executing anything, looking for install hooks, network calls, environment or credential reads and encoded payloads. Concrete malicious behaviour promotes this record to confirmed (critical; treat machines and CI that installed it as compromised). A benign or placeholder package still has to be replaced if express was meant.
- Owner-observed: Owners confirm whether `express` was intended. Until then, do not run npm install or npm ci for this project outside a disposable sandbox. Compare `npm view expresss` with `npm view express` (metadata only): maintainers, repository, publish dates and download counts.

**Sources**

- NIST SP 800-218 (SSDF) 1.1 PW.4.1 (violated-requirement; references/standards/nist-ssdf-800-218.md)
- OWASP ASVS 5.0.0 v5.0.0-15.1.2 (violated-requirement; references/standards/owasp-asvs-5.0.0.md)
- MITRE CWE 4.20 CWE-1357 (weakness; references/standards/cwe/weaknesses.md)
- MITRE ATT&CK 20.0 T1195.001 (attack-technique; references/standards/mitre-attack/enterprise-techniques.md)
- OWASP Top 10 2025 A03:2025 (risk-category; references/standards/owasp-top10-2025.md)
