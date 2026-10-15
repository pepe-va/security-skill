#!/usr/bin/env python3
"""Mode 3 — dependency audit: inventory, known vulnerabilities, known-malicious packages, static
malware signals, typosquatting and dependency-confusion signals, integrity notes.

Usage:
  python audit_deps.py <target-dir> --out <output-dir> [--offline] [--max-files N]

Never installs, builds or executes anything from the target: manifests, lockfiles and already
downloaded package files (node_modules/, vendor/, .venv/, site-packages/) are read as text.

Writes to <output-dir>:
  sbom.cdx.json            CycloneDX 1.6 inventory of the resolved components
  deps-raw.json            everything collected, including what could not be checked and why
  deps-findings.json       candidate records in the findings.json format (category "dependency"),
                           already carrying their sources; review them, add reachability evidence,
                           then merge them into findings.json (keep it sorted by fingerprint)

Network (skipped with --offline; anything it would have decided is then NOT VERIFIED):
  api.osv.dev        known vulnerabilities and OpenSSF malicious-package advisories (MAL-*)
  www.cisa.gov       CISA Known Exploited Vulnerabilities catalogue, to prioritise
  api.first.org      EPSS exploitation probability, to prioritise
  hugovk.github.io   most-downloaded PyPI packages, for typosquatting checks (redirects to hugovk.dev)
  raw.githubusercontent.com  most-depended-upon npm packages (wooorm/npm-high-impact), same purpose

Stdlib only (tomllib needs Python 3.11+).
"""
import argparse, datetime, hashlib, json, math, os, pathlib, re, sys, urllib.request

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

UA = "cybersec-skill-audit-deps/1.0"
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", "vendor",
             "site-packages", ".tox", ".mypy_cache"}
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "go": "Go", "cargo": "crates.io", "gem": "RubyGems", "maven": "Maven",
                 "composer": "Packagist"}
PURL_TYPE = {"npm": "npm", "pypi": "pypi", "go": "golang", "cargo": "cargo", "gem": "gem", "maven": "maven",
             "composer": "composer"}

SRC_PW44 = {"standard": "NIST SP 800-218 (SSDF)", "version": "1.1", "id": "PW.4.4",
            "file": "references/standards/nist-ssdf-800-218.md", "relation": "violated-requirement", "tier": "A"}
SRC_ASVS_1512 = {"standard": "OWASP ASVS", "version": "5.0.0", "id": "v5.0.0-15.1.2",
                 "file": "references/standards/owasp-asvs-5.0.0.md", "relation": "violated-requirement", "tier": "A"}
SRC_ASVS_1521 = {"standard": "OWASP ASVS", "version": "5.0.0", "id": "v5.0.0-15.2.1",
                 "file": "references/standards/owasp-asvs-5.0.0.md", "relation": "violated-requirement", "tier": "A"}
SRC_ASVS_1524 = {"standard": "OWASP ASVS", "version": "5.0.0", "id": "v5.0.0-15.2.4",
                 "file": "references/standards/owasp-asvs-5.0.0.md", "relation": "violated-requirement", "tier": "A"}
SRC_A03 = {"standard": "OWASP Top 10", "version": "2025", "id": "A03:2025",
           "file": "references/standards/owasp-top10-2025.md", "relation": "risk-category", "tier": "A"}


def cwe(n):
    return {"standard": "MITRE CWE", "version": "4.20", "id": f"CWE-{n}", "file": "references/standards/cwe/weaknesses.md",
            "relation": "weakness", "tier": "A"}


def attack(t):
    return {"standard": "MITRE ATT&CK", "version": "20.0", "id": t, "file": "references/standards/mitre-attack/enterprise-techniques.md",
            "relation": "attack-technique", "tier": "A"}


# ----------------------------------------------------------------------------------------------- inventory

def line_of(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def comp(eco, name, version, manifest, line, direct=None, resolved=None, integrity=None):
    return {"ecosystem": eco, "name": name, "version": version, "manifest": manifest, "line": line,
            "direct": direct, "resolved": resolved, "integrity": integrity}


def parse_package_lock(path, rel, text):
    data, out = json.loads(text), []
    for key, meta in (data.get("packages") or {}).items():
        if not key or not meta.get("version"):
            continue
        name = meta.get("name") or key.split("node_modules/")[-1]
        out.append(comp("npm", name, meta["version"], rel, line_of(text, f'"{key}"'), None, meta.get("resolved"), meta.get("integrity")))
        out[-1]["has_install_script"] = bool(meta.get("hasInstallScript"))
    if not out:  # lockfileVersion 1
        def walk(deps):
            for name, meta in (deps or {}).items():
                if meta.get("version"):
                    out.append(comp("npm", name, meta["version"], rel, line_of(text, f'"{name}"'), None, meta.get("resolved"), meta.get("integrity")))
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def parse_yarn_lock(path, rel, text):
    out = []
    for m in re.finditer(r'^"?((?:@[^@\s"/]+/)?[^@\s",]+)@[^\n]*:\n((?:[ \t]+.*\n?)+)', text, re.M):
        body = m.group(2)
        v = re.search(r'^\s+version:?\s+"?([^"\s]+)', body, re.M)
        if v:
            r = re.search(r'^\s+resolved:?\s+"?([^"\s]+)', body, re.M)
            i = re.search(r'^\s+(?:integrity|checksum):?\s+"?([^"\s]+)', body, re.M)
            out.append(comp("npm", m.group(1), v.group(1), rel, text.count("\n", 0, m.start()) + 1, None,
                            r.group(1) if r else None, i.group(1) if i else None))
    return out


def parse_pnpm_lock(path, rel, text):
    out = []
    for m in re.finditer(r"^\s{2}'?/?((?:@[^@/\s]+/)?[^@/\s:']+)@(\d[^:(\s']*)[^:]*'?:\s*$", text, re.M):
        out.append(comp("npm", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1))
    return out


def parse_requirements(path, rel, text):
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)", s)
        if m:
            out.append(comp("pypi", m.group(1).lower(), m.group(2), rel, i, True, None, "--hash" in ln or None))
    return out


def parse_toml_lock(path, rel, text, eco):
    if tomllib is None:
        return []
    data = tomllib.loads(text)
    return [comp(eco, p["name"].lower() if eco == "pypi" else p["name"], str(p["version"]), rel,
                 line_of(text, f'name = "{p["name"]}"'), None, (p.get("source") or {}).get("registry") if isinstance(p.get("source"), dict) else p.get("source"),
                 p.get("checksum") or (p.get("files") or [{}])[0].get("hash") if isinstance(p.get("files"), list) and p.get("files") else p.get("checksum"))
            for p in data.get("package", []) if p.get("name") and p.get("version")]


def parse_pipfile_lock(path, rel, text):
    data, out = json.loads(text), []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            v = (meta.get("version") or "").lstrip("=")
            if v:
                out.append(comp("pypi", name.lower(), v, rel, line_of(text, f'"{name}"'), None, None, bool(meta.get("hashes")) or None))
    return out


def parse_go_sum(path, rel, text):
    seen, out = set(), []
    for i, ln in enumerate(text.splitlines(), 1):
        p = ln.split()
        if len(p) >= 3 and not p[1].endswith("/go.mod") and (p[0], p[1]) not in seen:
            seen.add((p[0], p[1]))
            out.append(comp("go", p[0], p[1].lstrip("v"), rel, i, None, None, p[2]))
    return out


def parse_gemfile_lock(path, rel, text):
    out, in_specs = [], False
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and not ln.startswith("    "):
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)$", ln)
        if in_specs and m:
            out.append(comp("gem", m.group(1), m.group(2), rel, i))
    return out


def parse_composer_lock(path, rel, text):
    data = json.loads(text)
    return [comp("composer", p["name"], p["version"].lstrip("v"), rel, line_of(text, f'"name": "{p["name"]}"'), None,
                 (p.get("dist") or {}).get("url"), (p.get("dist") or {}).get("shasum") or None)
            for p in (data.get("packages") or []) + (data.get("packages-dev") or []) if p.get("name") and p.get("version")]


def parse_pom(path, rel, text):
    out = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        g = re.search(r"<groupId>([^<]+)</groupId>", m.group(1))
        a = re.search(r"<artifactId>([^<]+)</artifactId>", m.group(1))
        v = re.search(r"<version>([^<$]+)</version>", m.group(1))
        if g and a and v:
            out.append(comp("maven", f"{g.group(1).strip()}:{a.group(1).strip()}", v.group(1).strip(), rel,
                            text.count("\n", 0, m.start()) + 1, True))
    return out


LOCKFILES = {"package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock, "yarn.lock": parse_yarn_lock,
             "pnpm-lock.yaml": parse_pnpm_lock, "poetry.lock": lambda p, r, t: parse_toml_lock(p, r, t, "pypi"),
             "uv.lock": lambda p, r, t: parse_toml_lock(p, r, t, "pypi"), "Pipfile.lock": parse_pipfile_lock,
             "Cargo.lock": lambda p, r, t: parse_toml_lock(p, r, t, "cargo"), "go.sum": parse_go_sum,
             "Gemfile.lock": parse_gemfile_lock, "composer.lock": parse_composer_lock, "pom.xml": parse_pom}


def find_manifests(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            if f in LOCKFILES or re.fullmatch(r"requirements[\w.-]*\.txt", f) or f in ("package.json", "pyproject.toml",
                                                                                        "Pipfile", "go.mod", "Gemfile", "Cargo.toml"):
                found.append(pathlib.Path(dirpath) / f)
    return sorted(found)


def inventory(root, hardening):
    comps, manifests = [], find_manifests(root)
    dirs_with_lock = {m.parent for m in manifests if m.name in LOCKFILES and m.name != "pom.xml"}
    for m in manifests:
        rel = m.relative_to(root).as_posix()
        text = m.read_text(encoding="utf-8", errors="replace")
        try:
            if m.name in LOCKFILES:
                comps += LOCKFILES[m.name](m, rel, text)
            elif m.name.startswith("requirements"):
                comps += parse_requirements(m, rel, text)
                if "--hash" not in text:
                    hardening.append(f"{rel}: pinned requirements carry no --hash, so downloads are not integrity-checked (SSDF PS.2, SLSA).")
            elif m.name == "package.json":
                data = json.loads(text)
                deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
                for name, rng in deps.items():
                    if re.match(r"^(git|github:|https?:|file:)", str(rng)):
                        hardening.append(f"{rel}: '{name}' resolves from '{rng}', outside the registry; pin it to a commit or publish it.")
                if deps and m.parent not in dirs_with_lock:
                    hardening.append(f"{rel}: {len(deps)} dependencies with version ranges and no lockfile; builds are not reproducible.")
                for hook in ("preinstall", "install", "postinstall", "prepare"):
                    if (data.get("scripts") or {}).get(hook):
                        hardening.append(f"{rel}: the project itself runs a '{hook}' script on install: {data['scripts'][hook]!r}.")
            elif m.name in ("pyproject.toml", "Pipfile", "Gemfile", "Cargo.toml", "go.mod") and m.parent not in dirs_with_lock:
                hardening.append(f"{rel}: manifest without a lockfile next to it; resolved versions are unknown.")
        except (ValueError, KeyError, TypeError) as e:
            hardening.append(f"{rel}: could not be parsed ({type(e).__name__}); its components are not in the inventory.")
    for c in comps:
        if c["ecosystem"] == "npm" and c.get("resolved") and not re.match(r"^https://registry\.(npmjs\.org|yarnpkg\.com)/", c["resolved"]):
            c["nonstandard_source"] = True
    uniq = {}
    for c in comps:
        uniq.setdefault((c["ecosystem"], c["name"], c["version"]), c)
    return list(uniq.values()), [m.relative_to(root).as_posix() for m in manifests]


def cyclonedx(comps, target_name):
    def purl(c):
        name = c["name"]
        if c["ecosystem"] == "maven" and ":" in name:
            g, a = name.split(":", 1)
            return f"pkg:maven/{g}/{a}@{c['version']}"
        if name.startswith("@"):
            name = "%40" + name[1:]
        return f"pkg:{PURL_TYPE[c['ecosystem']]}/{name}@{c['version']}"
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                         "tools": {"components": [{"type": "application", "name": "cybersec-skill audit_deps.py"}]},
                         "component": {"type": "application", "name": target_name}},
            "components": [{"type": "library", "name": c["name"], "version": c["version"], "purl": purl(c),
                            "properties": [{"name": "cybersec-skill:manifest", "value": f"{c['manifest']}:{c['line']}"}]}
                           for c in sorted(comps, key=lambda c: (c["ecosystem"], c["name"], c["version"]))]}


# ----------------------------------------------------------------------------------------------- network

def http_json(url, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def osv(comps, notes):
    """Return {(eco,name,version): [vuln detail]}; record failures in notes."""
    results, queried = {}, [c for c in comps if c["ecosystem"] in OSV_ECOSYSTEM]
    for i in range(0, len(queried), 500):
        chunk = queried[i:i + 500]
        try:
            resp = http_json("https://api.osv.dev/v1/querybatch", {"queries": [
                {"package": {"name": c["name"], "ecosystem": OSV_ECOSYSTEM[c["ecosystem"]]}, "version": c["version"]} for c in chunk]})
        except Exception as e:
            notes.append(f"OSV query failed ({type(e).__name__}); known vulnerabilities and malicious packages are NOT VERIFIED.")
            return None
        for c, r in zip(chunk, resp.get("results", [])):
            ids = [v["id"] for v in (r.get("vulns") or [])]
            if ids:
                results[(c["ecosystem"], c["name"], c["version"])] = ids
    details = {}
    for vid in sorted({v for ids in results.values() for v in ids})[:400]:
        try:
            details[vid] = http_json(f"https://api.osv.dev/v1/vulns/{vid}")
        except Exception:
            details[vid] = {"id": vid}
    return {k: [details[v] for v in ids if v in details] for k, ids in results.items()}


def kev_set(notes):
    try:
        data = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        notes.append(f"CISA KEV unavailable ({type(e).__name__}); exploitation-in-the-wild status not checked.")
        return set()


def epss(cves, notes):
    out = {}
    cves = sorted(cves)
    for i in range(0, len(cves), 80):
        try:
            data = http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 80]))
            out.update({d["cve"]: float(d["epss"]) for d in data.get("data", [])})
        except Exception as e:
            notes.append(f"EPSS unavailable ({type(e).__name__}); exploitation probability not checked.")
            break
    return out


def popular(notes):
    names = {"pypi": set(), "npm": set()}
    try:
        data = http_json("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json")
        names["pypi"] = {r["project"].lower() for r in data.get("rows", [])[:5000]}
    except Exception as e:
        notes.append(f"PyPI popularity list unavailable ({type(e).__name__}); PyPI typosquatting not checked.")
    try:
        req = urllib.request.Request("https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            names["npm"] = set(re.findall(r"'([^']+)'", r.read().decode("utf-8", "replace"))[:5000])
    except Exception as e:
        notes.append(f"npm popularity list unavailable ({type(e).__name__}); npm typosquatting not checked.")
    return names


# ----------------------------------------------------------------------------------------------- static signals

SIGNALS = [
    ("eval-of-decoded", re.compile(r"(eval|Function)\s*\(\s*(atob|Buffer\.from|base64\.b64decode|codecs\.decode|bytes\.fromhex)", re.I)),
    ("exec-of-decoded", re.compile(r"exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex)", re.I)),
    ("obfuscator", re.compile(r"\b_0x[0-9a-f]{4,6}\b")),
    ("download-and-run", re.compile(r"(curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,200}(\|\s*(ba)?sh|-o\s+\S+\s*&&\s*(chmod|\.\/)|iex\b)", re.I)),
    ("credential-read", re.compile(r"(\.ssh/id_[a-z0-9]+|\.aws/credentials|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config)")),
    ("env-exfiltration", re.compile(r"(process\.env|os\.environ)[^\n]{0,200}(https?://|fetch\(|request\(|urlopen|requests\.post)", re.I)),
    ("discord-telegram-webhook", re.compile(r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot)", re.I)),
]


def entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def scan_file(path, max_bytes=1_000_000):
    try:
        if path.stat().st_size > max_bytes:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits = []
    for name, rx in SIGNALS:
        m = rx.search(text)
        if m:
            hits.append((name, text.count("\n", 0, m.start()) + 1, m.group(0)[:160]))
    for m in re.finditer(r"['\"]([A-Za-z0-9+/=]{400,})['\"]", text):
        if entropy(m.group(1)[:4000]) > 5.2:
            hits.append(("high-entropy-blob", text.count("\n", 0, m.start()) + 1, m.group(1)[:60] + "…"))
            break
    return hits


def installed_signals(root, max_files):
    """Look at packages already present on disk; never execute them."""
    found, scanned = [], 0
    for nm in root.rglob("node_modules"):
        if not nm.is_dir() or "node_modules" in nm.parent.parts:
            continue
        for pj in nm.glob("**/package.json"):
            if pj.parent.name == "node_modules" or scanned >= max_files:
                continue
            try:
                data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
            except ValueError:
                continue
            name, version = data.get("name"), data.get("version")
            if not name or not version:
                continue
            hooks = {h: c for h, c in (data.get("scripts") or {}).items() if h in ("preinstall", "install", "postinstall")}
            files = []
            for cmd in hooks.values():
                files += [pj.parent / f for f in re.findall(r"(?:node|sh|bash|python3?)\s+([\w./-]+\.(?:js|cjs|mjs|sh|py))", cmd)]
            main = pj.parent / (data.get("main") or "index.js")
            files.append(main)
            hits = []
            for f in files:
                if f.is_file():
                    scanned += 1
                    hits += [(f.relative_to(root).as_posix(),) + h for h in scan_file(f)]
            for hook, cmd in hooks.items():
                for sname, rx in SIGNALS:
                    if rx.search(cmd):
                        hits.append((pj.relative_to(root).as_posix(), sname, 1, f"{hook}: {cmd[:150]}"))
            if hits:
                found.append({"ecosystem": "npm", "name": name, "version": version, "hooks": hooks, "hits": hits,
                              "package_json": pj.relative_to(root).as_posix()})
    for setup in list(root.rglob("setup.py"))[:max_files]:
        if any(p in SKIP_DIRS - {"site-packages", "vendor"} for p in setup.relative_to(root).parts[:-1]) or setup.parent == root:
            continue
        hits = [(setup.relative_to(root).as_posix(),) + h for h in scan_file(setup)]
        if hits:
            found.append({"ecosystem": "pypi", "name": setup.parent.name, "version": "unknown", "hooks": {"setup.py": "runs at install"},
                          "hits": hits, "package_json": setup.relative_to(root).as_posix()})
    return found


def damerau1(a, b):
    """True if a and b differ by exactly one edit (insert, delete, substitute or adjacent swap)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    return any(b[:i] + b[i + 1:] == a for i in range(len(b)))


# ----------------------------------------------------------------------------------------------- records

def norm_name(eco, name):
    """Package names as registries compare them (PEP 503 for PyPI, case-insensitive for npm)."""
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name.lower()


def lock_hardening(root, comps, hardening):
    """Integrity hashes, install scripts and lockfile/disk drift for npm projects. Reads files only."""
    npm = [c for c in comps if c["ecosystem"] == "npm" and c["manifest"].endswith(("package-lock.json", "npm-shrinkwrap.json"))]
    no_hash = sorted(f"{c['name']}@{c['version']}" for c in npm if not c.get("integrity"))
    if no_hash:
        hardening.append(f"{len(no_hash)} lockfile entr{'y has' if len(no_hash) == 1 else 'ies have'} no integrity hash, so a "
                         f"tampered download would not be detected: {', '.join(no_hash[:10])} (SSDF PS.2, SLSA).")
    locked = {c["name"]: c for c in npm}
    for nm in root.rglob("node_modules"):
        if not nm.is_dir() or "node_modules" in nm.parent.parts:
            continue
        installed, hooks = {}, []
        for pj in list(nm.glob("*/package.json")) + list(nm.glob("@*/*/package.json")):
            try:
                data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
            except ValueError:
                continue
            if data.get("name"):
                installed[data["name"]] = data.get("version")
                h = [k for k in (data.get("scripts") or {}) if k in ("preinstall", "install", "postinstall")]
                if h:
                    hooks.append(data["name"])
                    lc = locked.get(data["name"])
                    if lc is not None and not lc.get("has_install_script"):
                        hardening.append(f"{data['name']} runs '{h[0]}' but its lockfile entry lacks hasInstallScript: the "
                                         "lockfile and the installed copy disagree; regenerate the lockfile from a clean install.")
        if hooks:
            hardening.append(f"Installed packages with install-time scripts: {', '.join(sorted(hooks))}. Install with "
                             "--ignore-scripts and allow-list the scripts you need.")
        rel = nm.relative_to(root).as_posix()
        missing = sorted(n for n in locked if n not in installed)
        extra = sorted(n for n in installed if n not in locked)
        drift = ([f"locked but not installed: {', '.join(missing[:10])}"] if missing else []) + \
                ([f"installed but not locked: {', '.join(extra[:10])}"] if extra else [])
        if locked and drift:
            hardening.append(f"{rel} does not match the lockfile ({'; '.join(drift)}); audit results describe the lockfile.")


def fp(*parts):
    return re.sub(r"[^A-Za-z0-9._:/@+-]", "-", "-".join(str(p) for p in parts)).strip("-")[:200]


def base_record(c, title, description):
    return {"fingerprint": "", "title": title, "description": description, "category": "dependency",
            "package": {"ecosystem": c["ecosystem"], "name": c["name"], "version": c["version"], "manifest": c["manifest"]}}


def evidence_of(c, text):
    return [{"file": c["manifest"], "line": max(1, int(c.get("line") or 1)), "description": text}]


def severity_of(vuln):
    for s in vuln.get("severity") or []:
        if s.get("type") == "CVSS_V4":
            return s["score"]
    return next((s["score"] for s in vuln.get("severity") or [] if s.get("score")), None)


def records(comps, vulns, kev, epss_scores, signals, typos, confusion):
    out = []
    for c in comps:
        for v in vulns.get((c["ecosystem"], c["name"], c["version"]), []):
            vid = v.get("id", "")
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            # An advisory can cover several packages (lodash and lodash-es): take the fix of this package only.
            mine = [a for a in v.get("affected", [])
                    if (a.get("package") or {}).get("ecosystem") == OSV_ECOSYSTEM.get(c["ecosystem"])
                    and norm_name(c["ecosystem"], (a.get("package") or {}).get("name", "")) == norm_name(c["ecosystem"], c["name"])]
            fixed = sorted({e["fixed"] for a in (mine or v.get("affected", [])) for r in a.get("ranges", [])
                            for e in r.get("events", []) if "fixed" in e})
            if vid.startswith("MAL-"):
                r = base_record(c, f"Known malicious package {c['name']}@{c['version']} ({vid})",
                                f"OSV advisory {vid} (OpenSSF Malicious Packages) lists {c['name']} {c['version']} as malicious. "
                                + (v.get("summary") or v.get("details", "")[:300]))
                r.update({
                    "verdict": "confirmed", "fingerprint": fp("dep", c["ecosystem"], c["name"], c["version"], vid),
                    "root_cause": f"The dependency graph resolves {c['name']}@{c['version']}, a version published with malicious code.",
                    "intended_behavior": "Only components from trusted, verified sources are resolved and installed.",
                    "trace": [{"kind": "sink", "file": c["manifest"], "line": max(1, int(c.get("line") or 1)),
                               "scope": f"{c['name']}@{c['version']}", "description": "The lockfile pins the malicious version, so every install runs its code."}],
                    "evidence": evidence_of(c, f"Resolved version {c['version']} of {c['name']}; OSV {vid}."),
                    "conditions": [{"kind": "third_party_dependency", "description": "Any install of the project (developer machine, CI) fetches and may execute the package."}],
                    "execution": {"attacker_perspective": "The publisher of the malicious package version.",
                                  "payloads": [f"{c['name']}@{c['version']} as published"],
                                  "instructions": [f"Resolve the dependency graph from {c['manifest']} (no execution needed to establish the match)."],
                                  "observed_result": f"OSV {vid} matches the exact name and version resolved by {c['manifest']}."},
                    "remediation": {"strategy": f"Remove {c['name']} (or pin a version not listed by {vid}), regenerate the lockfile, and treat every machine and CI runner that installed it as compromised: rotate the credentials they held."},
                    "severity": {"likelihood": {"score": "high", "reason": "The version is pinned and installed on every build."},
                                 "impact": {"score": "critical", "reason": "Malicious install-time or runtime code runs with the developer's or CI's privileges."},
                                 "overall_severity": "critical"},
                    "confidence": {"score": "high", "reason": "Exact name and version match an OpenSSF malicious-package advisory."},
                    "sources": [dict(SRC_PW44), dict(SRC_ASVS_1512), cwe(506), dict(SRC_A03), attack("T1195.002")],
                })
            else:
                prio = []
                if any(a in kev for a in aliases):
                    prio.append("listed in CISA KEV (exploited in the wild)")
                ep = max((epss_scores.get(a, 0.0) for a in aliases), default=0.0)
                if ep:
                    prio.append(f"EPSS {ep:.2f}")
                sev = severity_of(v)
                # OSV may list several CVEs as aliases of one advisory; the title names the advisory and its summary,
                # and every alias stays in package.advisories rather than guessing which CVE is "its own".
                summary = (v.get("summary") or "").strip().rstrip(".")
                r = base_record(c, f"{c['name']}@{c['version']}: {summary} ({vid})" if summary
                                else f"{c['name']}@{c['version']} has known vulnerability {vid}",
                                (v.get("summary") or v.get("details", "")[:400]) + (f" Advisory severity: {sev}." if sev else "")
                                + (f" Priority: {'; '.join(prio)}." if prio else ""))
                r["package"]["advisories"] = sorted({vid, *aliases})
                if fixed:
                    r["package"]["fixed_versions"] = fixed
                r.update({
                    "verdict": "needs_validation", "fingerprint": fp("dep", c["ecosystem"], c["name"], c["version"], vid),
                    "claimed_root_cause": f"{c['name']}@{c['version']} is affected by {vid}; whether the vulnerable code is reachable from this project is not yet established.",
                    "trace": [{"kind": "sink", "file": c["manifest"], "line": max(1, int(c.get("line") or 1)),
                               "scope": f"{c['name']}@{c['version']}", "description": "Resolved vulnerable version."}],
                    "evidence": evidence_of(c, f"Resolved version {c['version']}; OSV {vid}."),
                    "blockers": ["Reachability: no call path from this project's code to the vulnerable functionality has been traced yet."],
                    "validation_plan": {"local": f"Search the source for uses of the affected API of {c['name']} named in {vid}; if reached with attacker-influenced input, write a bounded local test and promote the record to confirmed."
                                        + (f" Fixed in: {', '.join(fixed[:5])}." if fixed else "")},
                    "sources": [dict(SRC_ASVS_1521), cwe(1395), dict(SRC_A03)],
                })
            out.append(r)
    for s in signals:
        c = {"ecosystem": s["ecosystem"], "name": s["name"], "version": s["version"], "manifest": s["package_json"], "line": 1}
        hit = s["hits"][0]
        r = base_record(c, f"Install-time or obfuscated code signals in {s['name']}@{s['version']}",
                        "Static signals usually seen in malicious packages: " + "; ".join(sorted({h[1] for h in s["hits"]})) + ".")
        r.update({
            "verdict": "needs_validation", "fingerprint": fp("dep-signal", s["ecosystem"], s["name"], s["version"]),
            "claimed_root_cause": "The package may run hidden code at install or import time.",
            "trace": [{"kind": "sink", "file": hit[0], "line": max(1, int(hit[2])), "scope": s["name"], "description": f"{hit[1]}: {hit[3]}"}],
            "evidence": [{"file": h[0], "line": max(1, int(h[2])), "description": f"{h[1]}: {h[3]}"} for h in s["hits"][:8]],
            "blockers": ["A static signal is not proof of malice: the code's actual behaviour has not been reviewed."],
            "validation_plan": {"local": "Read the flagged files and the install hooks in full; decode any encoded payload as text without executing it; compare the package contents with the registry's published tarball for the same version."},
            "sources": [dict(SRC_PW44), cwe(506), attack("T1195.002")],
        })
        out.append(r)
    for c, near in typos:
        r = base_record(c, f"Possible typosquat: {c['name']} looks like popular package {near}",
                        f"{c['name']} is one edit away from the widely used {near} and is not itself on the popularity list.")
        r.update({
            "verdict": "needs_validation", "fingerprint": fp("dep-typo", c["ecosystem"], c["name"], c["version"]),
            "claimed_root_cause": f"The project may depend on {c['name']} by mistake instead of {near}.",
            "trace": [{"kind": "sink", "file": c["manifest"], "line": max(1, int(c.get("line") or 1)), "scope": c["name"], "description": "Resolved package name."}],
            "evidence": evidence_of(c, f"Resolved {c['name']}@{c['version']}; nearest popular name {near}."),
            "blockers": ["Whether the name was chosen on purpose is a fact only the owners know."],
            "validation_plan": {"deployment": f"Ask the owners whether {c['name']} is intended; compare its publisher, repository and download history with {near}."},
            "sources": [dict(SRC_ASVS_1524), cwe(1357), attack("T1195.001")],
        })
        out.append(r)
    for c in confusion:
        r = base_record(c, f"Dependency resolved from a non-default registry: {c['name']}",
                        f"{c['name']}@{c['version']} resolves from {c.get('resolved')}, unlike the rest of the graph.")
        r.update({
            "verdict": "needs_validation", "fingerprint": fp("dep-source", c["ecosystem"], c["name"], c["version"]),
            "claimed_root_cause": "Mixed registries can let a public package shadow an internal one (dependency confusion), or pull code from an untrusted host.",
            "trace": [{"kind": "sink", "file": c["manifest"], "line": max(1, int(c.get("line") or 1)), "scope": c["name"], "description": "Resolved URL."}],
            "evidence": evidence_of(c, f"resolved: {c.get('resolved')}"),
            "blockers": ["The intended registry for this package and the registry configuration (.npmrc scopes) are not visible here."],
            "validation_plan": {"deployment": "Confirm the expected registry for this package and that scope-to-registry mapping prevents a public package with the same name from being chosen."},
            "sources": [dict(SRC_ASVS_1524), cwe(1357), attack("T1195.001")],
        })
        out.append(r)
    return sorted(out, key=lambda r: r["fingerprint"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("target")
    ap.add_argument("--out", required=True)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--max-files", type=int, default=3000)
    a = ap.parse_args()
    root, out = pathlib.Path(a.target).resolve(), pathlib.Path(a.out).resolve()
    if out == root or root in out.parents:
        sys.exit("the output directory must be outside the audited target")
    out.mkdir(parents=True, exist_ok=True)
    notes, hardening = [], []
    comps, manifests = inventory(root, hardening)
    if a.offline:
        notes.append("Offline run: known vulnerabilities, malicious-package advisories, KEV, EPSS and typosquatting were NOT VERIFIED.")
        vulns, kev, ep, pop = {}, set(), {}, {"pypi": set(), "npm": set()}
    else:
        vulns = osv(comps, notes)
        if vulns is None:
            vulns = {}
        cves = {x for vs in vulns.values() for v in vs for x in v.get("aliases", []) if x.startswith("CVE-")}
        kev = kev_set(notes) if cves else set()
        ep = epss(cves, notes) if cves else {}
        pop = popular(notes)
    signals = installed_signals(root, a.max_files)
    lock_hardening(root, comps, hardening)
    typos = []
    for c in comps:
        names = pop.get(c["ecosystem"]) or set()
        if names and c["name"] not in names:
            near = next((n for n in sorted(names) if damerau1(c["name"].lower(), n.lower())), None)
            if near:
                typos.append((c, near))
    confusion = [c for c in comps if c.get("nonstandard_source")]
    recs = records(comps, vulns, kev, ep, signals, typos, confusion)

    (out / "sbom.cdx.json").write_text(json.dumps(cyclonedx(comps, root.name), indent=2) + "\n", encoding="utf-8")
    (out / "deps-findings.json").write_text(json.dumps(recs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    raw = {"target": root.name, "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "manifests": manifests, "components": len(comps), "by_ecosystem": {e: sum(1 for c in comps if c["ecosystem"] == e) for e in sorted({c["ecosystem"] for c in comps})},
           "vulnerable_components": len(vulns), "malware_signals": len(signals), "typosquat_suspects": len(typos),
           "nonstandard_sources": len(confusion), "not_verified": notes, "hardening_notes": hardening,
           "limits": ["Static analysis finds known malware and indicators; it cannot prove that a package is clean."]}
    (out / "deps-raw.json").write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    print(f"components: {len(comps)} in {len(manifests)} manifest(s) · candidate records: {len(recs)} "
          f"(confirmed {sum(r['verdict'] == 'confirmed' for r in recs)}) · not verified: {len(notes)} · hardening notes: {len(hardening)}")
    for n in notes:
        print("NOT VERIFIED:", n)


if __name__ == "__main__":
    main()
