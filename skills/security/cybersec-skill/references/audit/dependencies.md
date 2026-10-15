# Mode 3 — dependency audit

Audits what the project pulls in rather than what it writes: known vulnerable versions, known malicious packages, signs of malicious code, typosquats, dependency confusion, and integrity of the resolution. Run it on explicit request ("audit the dependencies", "is there anything malicious in our libraries", "SBOM", "supply chain review") or as half of a full audit.

**Limit that every report states:** static analysis finds known malware and indicators of malice; it cannot prove that a package is clean.

## Steps

1. **Run the collector** (never installs, builds or executes anything from the target):

   ```bash
   python scripts/audit_deps.py <target> --out <output-dir>          # add --offline when there is no network
   ```

   It writes `sbom.cdx.json` (CycloneDX 1.6), `deps-raw.json` (inventory, what was not verified and why, hardening notes) and `deps-findings.json` (candidate records in the findings format, `category: "dependency"`, sources included).

   | Network host | Used for | If unavailable |
   |---|---|---|
   | `api.osv.dev` | Known vulnerabilities (GHSA, PYSEC, RUSTSEC, Go…) and OpenSSF malicious packages (`MAL-*`) | Those checks are NOT VERIFIED |
   | `www.cisa.gov` | KEV: exploited in the wild | No KEV priority |
   | `api.first.org` | EPSS: exploitation probability | No EPSS priority |
   | `hugovk.github.io` → `hugovk.dev`, `raw.githubusercontent.com` | Popular PyPI / npm names for typosquatting | Typosquatting not checked for that ecosystem |

2. **Review every candidate record.** The collector proposes; the audit decides, with the evidence bar of `upstream/SECURITY-AUDIT.md`:
   - **Known-malicious match (`MAL-*`)** → `confirmed`, `critical`. Exact name and version match is the evidence. Remediation includes treating machines and CI that installed it as compromised.
   - **Known vulnerability** → `needs_validation` until reachability is shown. Trace the affected API from the advisory into the project's code. If attacker-influenced input reaches it, write a bounded local test (sandbox rules apply), then promote the record to `confirmed`: add `root_cause`, `intended_behavior`, `execution` with the observed result, `remediation` (fixed version), `severity` and `confidence`, keep the sources and add the violated requirement. If the code is unreachable, keep it as `needs_validation` with that blocker, or `rejected` with the reason. Use KEV and EPSS only to **prioritise**, never as severity.
   - **Static malware signals** (install hooks, decode-and-eval, obfuscation, credential reads, exfiltration endpoints, high-entropy blobs) → read the flagged files in full; decode payloads as text without running them; compare with the registry tarball of the same version. Confirm only with a concrete malicious behaviour in the code; otherwise `rejected` (explain the benign reason) or keep `needs_validation`.
   - **Typosquat suspects** and **non-default registry sources** → `needs_validation`: the intended name or registry is a fact only the owners know.

3. **Hardening notes** from `deps-raw.json` (no lockfile, no hashes, git/URL dependencies, the project's own install scripts) are **not findings**: they are process gaps (SSDF PS.2/PW.4, SLSA Build track). Put them in `run-metadata.json` → `hardening_notes`.

4. **Merge** the reviewed records into `findings.json`, keep it sorted by fingerprint, and run `scripts/validate_findings.py`. Record the components and manifests in the coverage ledger as units (surface = manifest, boundary = "third-party code", attack class = "supply chain").

## Usual sources for dependency records

| Record | Violated requirement | Weakness | Other |
|---|---|---|---|
| Known malicious version | SSDF `PW.4.4`, ASVS `v5.0.0-15.1.2` | `CWE-506` | `A03:2025`, ATT&CK `T1195.002` |
| Known vulnerable version | ASVS `v5.0.0-15.2.1` | `CWE-1395` | `A03:2025`; add the advisory's own CWE when reachability is confirmed |
| Malware signals | SSDF `PW.4.4` | `CWE-506` | ATT&CK `T1195.002` |
| Typosquat / dependency confusion | ASVS `v5.0.0-15.2.4` | `CWE-1357` | ATT&CK `T1195.001` |
| Unmaintained component | ASVS `v5.0.0-15.2.1` | `CWE-1104` | SSDF `PW.4.1` |

For AI models and datasets pulled as dependencies, add LLM Top 10 `LLM04:2026` (supply chain) and 800-218A `PW.4.4`; for agent tools and MCP servers, ASI `ASI04`.

## Playbooks that help

`../playbooks/index-by-domain.md` → *supply-chain-security*: SBOM analysis, dependency confusion, malicious npm packages, typosquatting, Sigstore and SLSA provenance. Use them for procedure; the standards above decide the result.
