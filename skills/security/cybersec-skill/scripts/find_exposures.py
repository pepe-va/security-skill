#!/usr/bin/env python3
"""Exposure sweep for audits: environment-variable files of any name, credential stores and keys, hard-coded
secrets in any programming language, secrets left in git history, .gitignore gaps, and network exposure declared
in code or configuration (published ports, all-interface binds, open firewall rules, disabled authentication).

Reads files only. It never executes target code and never connects anywhere. git runs read-only, with the
target's risky configuration overridden (fsmonitor, hooks, pager, textconv, external diff) and no user or system
config. Secret values are never written out: every output masks them.

Usage:
  python scripts/find_exposures.py <target>                      print a summary, write nothing
  python scripts/find_exposures.py <target> --out <output-dir>   also write exposures-raw.json and exposures-findings.json
Options:
  --no-history            skip git history
  --history-commits N     commits whose added lines are scanned for secrets (default 300); file names: all commits
  --max-files N           files to scan (default 20000)

Every record in exposures-findings.json is needs_validation, with its sources: whether a value is a live
credential, or whether a published port is reachable from a lower-trust network, is a fact outside the source.

Stdlib only; Python 3.9+.
"""
import argparse, datetime, hashlib, json, math, os, pathlib, re, subprocess, sys

# ----------------------------------------------------------------------------------------------- sources

def _src(standard, version, ident, file, relation):
    return {"standard": standard, "version": version, "id": ident, "file": file, "relation": relation, "tier": "A"}

ASVS = "references/standards/owasp-asvs-5.0.0.md"
SRC_ASVS_1331 = _src("OWASP ASVS", "5.0.0", "v5.0.0-13.3.1", ASVS, "violated-requirement")
SRC_ASVS_1342 = _src("OWASP ASVS", "5.0.0", "v5.0.0-13.4.2", ASVS, "violated-requirement")
SRC_ASVS_1345 = _src("OWASP ASVS", "5.0.0", "v5.0.0-13.4.5", ASVS, "violated-requirement")
SRC_ASVS_1347 = _src("OWASP ASVS", "5.0.0", "v5.0.0-13.4.7", ASVS, "violated-requirement")
SRC_A02 = _src("OWASP Top 10", "2025", "A02:2025", "references/standards/owasp-top10-2025.md", "risk-category")
SRC_SC7 = _src("NIST SP 800-53", "Rev. 5", "SC-7", "references/standards/nist-800-53r5/sc.md", "violated-requirement")
SRC_CM7 = _src("NIST SP 800-53", "Rev. 5", "CM-7", "references/standards/nist-800-53r5/cm.md", "violated-requirement")
SRC_190 = _src("NIST SP 800-190", "September 2017", "§4.4.2", "references/standards/nist-800-190.md", "countermeasure")


def cwe(n):
    return _src("MITRE CWE", "4.20", f"CWE-{n}", "references/standards/cwe/weaknesses.md", "weakness")


def attack(t):
    return _src("MITRE ATT&CK", "20.0", t, "references/standards/mitre-attack/enterprise-techniques.md", "attack-technique")

# ----------------------------------------------------------------------------------------------- file classes

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "bower_components", "__pycache__", ".tox", ".nox", ".mypy_cache",
             ".pytest_cache", ".ruff_cache", "site-packages", ".terraform", ".gradle", ".idea", ".vscode", "vendor",
             "third_party", ".cache"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock",
             "go.sum", "Gemfile.lock", "composer.lock", "packages.lock.json"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".kts", ".scala", ".rb", ".php",
            ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift", ".m", ".lua", ".pl", ".r", ".dart", ".ex", ".exs",
            ".erl", ".clj", ".groovy", ".vue", ".svelte", ".sql", ".html", ".htm", ".css", ".scss"}
DOC_EXT = {".md", ".rst", ".adoc", ".txt", ".ipynb"}
TEMPLATE_MARKERS = ("example", "sample", "template", "dist", "default", "defaults", "tmpl", "tpl", "schema", "skeleton")
TEST_PATH = re.compile(r"(^|/)(tests?|spec|specs|__tests__|fixtures?|testdata|examples?|docs?|samples?|mocks?)/", re.I)
WEB_DIRS = re.compile(r"(^|/)(public|static|www|wwwroot|htdocs|html|web|dist|build|out|_site|site|assets)/", re.I)

ENV_NAME = re.compile(
    r"^(?:\.env(?:\..+)?|.+\.env|\.envrc|.+\.envrc|\.flaskenv|\.dev\.vars|env|environment|\.environment|envvars|\.envvars"
    r"|(?:set)?env\.(?:sh|bash|zsh|bat|cmd|ps1|list|txt|conf|cfg|vars|ini|properties)"
    r"|\.?env\.(?:ya?ml|json)|local\.settings\.json|.+\.tfvars|.+\.tfvars\.json)$", re.I)
CREDENTIAL_NAME = re.compile(
    r"^(?:\.netrc|_netrc|\.git-credentials|\.pgpass|\.my\.cnf|\.boto|\.s3cfg|\.dockercfg|credentials(?:\.json|\.ya?ml|\.xml)?"
    r"|secrets?(?:\.(?:ya?ml|json|env|txt|ini|cfg|conf|properties|toml|xml))?|\.secrets?|kubeconfig|\.htpasswd|htpasswd|master\.key|.+-adminsdk-.+\.json"
    r"|service[-_]?account.*\.json|.+[-_]sa\.json)$", re.I)
KEY_NAME = re.compile(r"^(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|.+\.(?:pem|key|p8|p12|pfx|jks|keystore|bks|kdbx|ppk|asc|ovpn))$", re.I)
KEY_BINARY_EXT = (".p12", ".pfx", ".jks", ".keystore", ".bks", ".kdbx")
STATE_NAME = re.compile(r"^(?:terraform\.tfstate(?:\.backup)?|.+\.tfstate)$", re.I)
# Credential files that live in a well-known directory: .aws/credentials, .docker/config.json, .kube/config.
DIR_CREDENTIALS = {(".aws", "credentials"), (".aws", "config"), (".docker", "config.json"), (".kube", "config"),
                   (".ssh", "config"), (".gnupg", "secring.gpg")}

ENV_LINE = re.compile(r"^\s*(?:export\s+|set\s+|setx\s+|\$env:)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$")
ENV_LINE_UPPER = re.compile(r"^[A-Z_][A-Z0-9_]*$")

# ----------------------------------------------------------------------------------------------- secret patterns

PROVIDER = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+")),
    ("Discord webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b"
                                  r"|\bsk-proj-[A-Za-z0-9_-]{60,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("Azure storage account key", re.compile(r"AccountKey=[A-Za-z0-9+/]{86}==")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
]
URL_CREDS = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|ftps?|sftp|smtps?"
                       r"|ldaps?|https?)://([^\s:/@'\"<>]+):([^\s@/'\"<>]{3,})@[\w.-]+")
# Secret-like key names in many languages, so a config in Spanish or German is caught as well as one in English.
SECRET_WORDS = (r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key|private[_.-]?key"
                r"|client[_.-]?secret|auth[_.-]?(?:key|token)|credential|conn(?:ection)?[_.-]?str(?:ing)?|dsn|signing[_.-]?key"
                r"|contrase(?:ñ|n)a|clave|secreto|credencial|mot[_.-]?de[_.-]?passe|motdepasse|passwort|kennwort|geheim"
                r"|senha|segredo|chave|wachtwoord|haslo|hasło|losenord|lösenord|salasana|sifre|şifre|пароль|密码|密碼"
                r"|パスワード|비밀번호|كلمة_?المرور")
ASSIGN = re.compile(r"(?P<key>[\w.\-]*(?:" + SECRET_WORDS + r")[\w.\-]*)[\"']?\s*(?::=|=>|=|:)\s*(?P<q>[\"'`]?)"
                    r"(?P<val>[^\s\"'`,;)}\]#]{6,})(?P=q)", re.I)
XML_ASSIGN = re.compile(r"<(?P<key>[\w.:-]*(?:" + SECRET_WORDS + r")[\w.:-]*)>(?P<val>[^<\s]{6,})</", re.I)
DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+(?P<key>[\w.\-]*(?:" + SECRET_WORDS + r")[\w.\-]*)(?:\s+|=)(?P<val>\S{6,})", re.I)
JSON_ASSIGN = re.compile(r'"(?P<key>[^"\n]*(?:' + SECRET_WORDS + r')[^"\n]*)"\s*:\s*"(?P<val>[^"\s]{6,})"', re.I)
# Cheap substring checks run before the regular expressions: most lines contain none of these.
PROVIDER_HINT = re.compile(r"AKIA|ASIA|ABIA|ACCA|A3T|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|hooks\.slack|webhooks/|_live_"
                           r"|AIza|sk-|hf_|npm_|pypi-|SG\.|SK[0-9a-f]{8}|:AA|AccountKey=|eyJ|PRIVATE KEY")
WORD_HINTS = ("pass", "pwd", "secret", "token", "key", "credential", "conn", "dsn", "contrase", "clave", "credencial",
              "kennwort", "geheim", "senha", "segredo", "chave", "wachtwoord", "haslo", "hasło", "losenord", "lösenord",
              "salasana", "sifre", "şifre", "пароль", "密码", "密碼", "パスワード", "비밀번호", "كلمة")
# In-line markers other scanners honour; a line carrying one is skipped (gitleaks, detect-secrets, bandit, this tool).
ALLOW_MARK = re.compile(r"gitleaks:allow|pragma:\s*allowlist\s+secret|#\s*nosec\b|exposures:\s*ignore", re.I)
PLACEHOLDER = re.compile(r"^(?:\$\{?|\$\(|%\(|%[A-Z_]+%|\{\{|<|\[|\*{3,}|x{4,}|\.{3}|_+$|0{4,}|1234|changeme|change[_-]?me"
                         r"|example|sample|dummy|fake|test|testing|placeholder|your[_-]|my[_-]?(?:pass|secret|token|key)"
                         r"|password|passwd|secret|token|none|null|nil|undefined|true|false|todo|tbd|fixme|replace|redacted"
                         r"|xxx|foo|bar|baz|admin$|root$|default$|string$|required$|optional$|env\(|process\.|os\.|getenv"
                         r"|config\.|settings\.|self\.|this\.|request\.|params|args\.|ENV\[|System\.getenv)", re.I)
HASHED = re.compile(r"^(?:\$2[abxy]?\$|\$argon2|\$pbkdf2|\$scrypt|\$6\$|\$5\$|\$1\$|sha256:|pbkdf2_sha256\$)")
KNOWN_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAI44QH8DHBEXAMPLE"}

# ----------------------------------------------------------------------------------------------- exposure patterns

SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 1521: "Oracle", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker API (no TLS)", 2376: "Docker API", 2379: "etcd", 3000: "Grafana / dev server", 3306: "MySQL",
    3389: "RDP", 4040: "Spark UI", 5000: "dev server / registry", 5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API", 7474: "Neo4j", 8086: "InfluxDB",
    8500: "Consul", 8888: "Jupyter", 8983: "Solr", 9000: "MinIO / PHP-FPM", 9042: "Cassandra", 9090: "Prometheus",
    9092: "Kafka", 9100: "node_exporter", 9200: "Elasticsearch", 9300: "Elasticsearch transport", 10250: "kubelet",
    11211: "Memcached", 15672: "RabbitMQ management", 27017: "MongoDB", 50070: "Hadoop NameNode", 61616: "ActiveMQ",
}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
# The service a configuration file belongs to, when its listener carries no port.
FILE_SERVICE = [(re.compile(r"redis", re.I), "Redis"), (re.compile(r"mongo", re.I), "MongoDB"),
                (re.compile(r"elasticsearch|opensearch", re.I), "Elasticsearch"), (re.compile(r"postgres", re.I), "PostgreSQL"),
                (re.compile(r"my(?:sqld?)?\.cnf|mariadb", re.I), "MySQL"), (re.compile(r"memcache", re.I), "Memcached"),
                (re.compile(r"rabbit", re.I), "RabbitMQ"), (re.compile(r"jupyter", re.I), "Jupyter"),
                (re.compile(r"daemon\.json|docker", re.I), "Docker daemon")]
COMPOSE_NAME = re.compile(r"^(?:docker-)?compose[\w.-]*\.ya?ml$", re.I)
CODE_BIND = re.compile(r"(?i)\b(?:host|bind|bindip|bind_ip|listen|address|addr|server\.address|hostname|network\.host|interface)"
                       r"\w*[\"']?\s*(?:=|:|,|\(|\s)\s*[\"']?(?:0\.0\.0\.0|::|\[::\]|\*)(?:[\"':]|\s|$)")
CLI_BIND = re.compile(r"(?i)--(?:host|bind|listen|address|ip)[ =][\"']?(?:0\.0\.0\.0|::)\b")
GO_ALL = re.compile(r"\b(?:ListenAndServe(?:TLS)?|net\.Listen)\(\s*(?:\"tcp[46]?\",\s*)?\":\d+\"")
DEBUG_ON = re.compile(r"(?i)(?:\bdebug\s*[=:]\s*(?:true|1|on)\b|\.run\([^)]*debug\s*=\s*True|--reload\b|\bFLASK_DEBUG\s*=\s*1"
                      r"|\bDEBUG\s*=\s*True\b|use_debugger\s*=\s*True)")
AUTH_OFF = [
    ("Redis protected mode off", re.compile(r"^\s*protected-mode\s+no\b", re.I | re.M)),  # exposures: ignore
    ("Docker API on TCP without TLS", re.compile(r"tcp://(?:0\.0\.0\.0|\*)?:2375\b")),  # exposures: ignore
    ("Elasticsearch security disabled", re.compile(r"xpack\.security\.enabled\s*[:=]\s*[\"']?false", re.I)),  # exposures: ignore
    ("MongoDB authorization disabled", re.compile(r"authorization\s*:\s*[\"']?disabled", re.I)),  # exposures: ignore
    ("Jupyter without token", re.compile(r"(?:NotebookApp|ServerApp|IdentityProvider)\.token\s*=\s*(?:''|\"\")")),  # exposures: ignore
    ("kubelet anonymous auth", re.compile(r"--anonymous-auth=true|anonymous:\s*\n\s*enabled:\s*true")),  # exposures: ignore
    ("Directory listing enabled", re.compile(r"^\s*(?:autoindex\s+on\s*;|Options\b[^\n]*?(?<!-)\bIndexes\b)", re.I | re.M)),  # exposures: ignore
]

# ----------------------------------------------------------------------------------------------- helpers


def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def mask(value, provider=False):
    v = value.strip()
    if v.startswith("-----BEGIN"):
        return "-----BEGIN … PRIVATE KEY----- (redacted)"
    keep = 4 if provider and len(v) > 12 else 2 if len(v) > 8 else 1
    return v[:keep] + "…" + f" ({len(v)} chars)"


def vhash(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def fp(*parts):
    return re.sub(r"[^A-Za-z0-9._:/@+-]", "-", "-".join(str(p) for p in parts)).strip("-")[:200]


def looks_real(value, key=""):
    v = value.strip().strip("\"'`")
    if len(v) < 6 or v in KNOWN_EXAMPLES or "example" in v.lower():
        return False
    if PLACEHOLDER.match(v) or HASHED.match(v) or re.fullmatch(r"(.)\1+", v):
        return False
    if re.match(r"^(?:/|\./|\.\./|~/|[A-Za-z]:\\|https?://(?![^/\s]*@)|arn:)", v):
        return False
    if re.fullmatch(r"[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+", v):
        return False       # a lower-case resource path such as prod/db/credentials
    if re.fullmatch(r"[A-Za-z_][\w.]*\(.*\)?", v) or re.fullmatch(r"[a-z]+(?:[._-][a-z]+)*", v):
        return False       # a function call, a dotted name or lowercase words: code or prose, not a literal secret
    return entropy(v) >= 3.0 or (re.search(r"pass|pwd|contrase|clave|senha|passwort|mot", key, re.I) and len(v) >= 8
                                  and re.search(r"\d", v) and re.search(r"[A-Za-z]", v))


def is_text(path):
    try:
        with open(path, "rb") as fh:
            return b"\0" not in fh.read(8192)
    except OSError:
        return False


def read_text(path, limit):
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return None

# ----------------------------------------------------------------------------------------------- git (read-only)

GIT_SAFE_CONFIG = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
                   "-c", "diff.external=", "-c", "core.sshCommand=false", "-c", "protocol.allow=never",
                   "-c", "core.untrackedCache=false"]


def git(root, *args, timeout=120, stdin=None, ok=(0,)):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"}
    try:
        r = subprocess.run(["git", "--no-pager"] + GIT_SAFE_CONFIG + ["-C", str(root)] + list(args),
                           input=stdin, capture_output=True, env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, type(e).__name__
    if r.returncode not in ok:
        return None, r.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["git failed"]
    return r.stdout.decode("utf-8", "replace"), None

# ----------------------------------------------------------------------------------------------- scanners


def classify_name(rel):
    parts = rel.split("/")
    name = parts[-1]
    low = name.lower()
    if len(parts) >= 2 and (parts[-2], name) in DIR_CREDENTIALS:
        return "credential-store"
    if ENV_NAME.match(name):
        stem = low.lstrip(".")
        if any(re.search(r"(^|[._-])" + m + r"($|[._-])", stem) for m in TEMPLATE_MARKERS):
            return "env-template"
        return "env-file"
    if STATE_NAME.match(name):
        return "infra-state"
    if KEY_NAME.match(name) and not low.endswith(".pub"):
        return "key-material"
    if CREDENTIAL_NAME.match(name):
        return "credential-store"
    return None


def env_by_content(rel, text):
    """A dotenv-style file whatever its name: mostly KEY=VALUE lines with upper-case keys."""
    ext = pathlib.PurePath(rel).suffix.lower()
    if ext in CODE_EXT or ext in DOC_EXT - {".txt"}:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", ";", "//", "REM ", "rem "))]
    if len(lines) < 3:
        return False
    keys = [m.group(1) for m in (ENV_LINE.match(ln) for ln in lines) if m]
    upper = [k for k in keys if ENV_LINE_UPPER.match(k)]
    return len(keys) >= 3 and len(keys) / len(lines) >= 0.6 and len(upper) / len(keys) >= 0.6


def env_keys(text):
    out = []
    for ln in text.splitlines():
        m = ENV_LINE.match(ln)
        if m and not ln.lstrip().startswith("#"):
            out.append((m.group(1), m.group(2).strip().strip("\"'")))
    return out


def scan_secrets(rel, text, config_like):
    hits, seen = [], set()
    ext = pathlib.PurePath(rel).suffix.lower()
    generic = (JSON_ASSIGN,) if ext in (".json", ".ipynb") else () if ext in (".html", ".htm", ".svg") \
        else (ASSIGN, XML_ASSIGN, DOCKER_ENV)
    for no, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000 or ALLOW_MARK.search(line):
            continue
        low = line.lower()
        provider = PROVIDER_HINT.search(line) is not None
        words = any(w in low for w in WORD_HINTS)
        url = "://" in line and "@" in line
        if not (provider or words or url):
            continue
        for kind, rx in (PROVIDER if provider else ()):
            for m in rx.finditer(line):
                val = m.group(0)
                if val in KNOWN_EXAMPLES or "EXAMPLE" in val.upper():
                    continue
                if kind == "JSON Web Token" and TEST_PATH.search(rel):
                    continue
                key = (no, vhash(val))
                if key not in seen:
                    seen.add(key)
                    hits.append({"file": rel, "line": no, "kind": kind, "key": "", "masked": mask(val, provider=True),
                                 "hash": vhash(val), "confidence": "medium" if kind == "JSON Web Token" else "high"})
        for m in (URL_CREDS.finditer(line) if url else ()):
            pw = m.group(2)
            if looks_real(pw, "password") and (no, vhash(pw)) not in seen:
                seen.add((no, vhash(pw)))
                hits.append({"file": rel, "line": no, "kind": "Credentials in a connection URL", "key": m.group(1),
                             "masked": mask(pw), "hash": vhash(pw), "confidence": "high"})
        for rx in (generic if words else ()):
            for m in rx.finditer(line):
                val, key = m.group("val"), m.group("key")
                quoted = rx is not ASSIGN or bool(m.group("q"))
                if not (quoted or config_like) or not looks_real(val, key) or (no, vhash(val)) in seen:
                    continue
                if any(h["line"] == no and h["confidence"] == "high" for h in hits):
                    continue
                seen.add((no, vhash(val)))
                hits.append({"file": rel, "line": no, "kind": "Secret-like assignment", "key": key, "masked": mask(val),
                             "hash": vhash(val), "confidence": "medium"})
    if ext == ".json" and "service_account" in text and "PRIVATE KEY" in text:
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and obj.get("type") == "service_account" and "PRIVATE KEY" in str(obj.get("private_key")):
            hits.append({"file": rel, "line": 1, "kind": "Google service-account key file", "key": "private_key",
                         "masked": "(redacted)", "hash": vhash(rel), "confidence": "high"})
    return hits


def compose_ports(rel, text):
    out, lines = [], text.splitlines()
    service, svc_indent, in_services = None, None, False
    i = 0
    while i < len(lines):
        ln = lines[i]
        stripped = ln.strip()
        indent = len(ln) - len(ln.lstrip())
        if re.match(r"^services\s*:", ln):
            in_services, svc_indent = True, None
        elif in_services and stripped and not stripped.startswith("#") and indent > 0 and stripped.endswith(":") \
                and (svc_indent is None or indent == svc_indent):
            svc_indent, service = indent, stripped[:-1].strip("\"'")
        elif in_services and indent == 0 and stripped and not stripped.startswith("#"):
            in_services = False
        if re.match(r"^\s*network_mode\s*:\s*[\"']?host", ln):
            out.append({"file": rel, "line": i + 1, "kind": "compose-host-network", "service": service,
                        "detail": "network_mode: host shares every container port with the host"})
        m = re.match(r"^(\s*)ports\s*:\s*$", ln)
        if m:
            base = len(m.group(1))
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > base):
                item = lines[j].strip()
                if item.startswith("- "):
                    spec = item[2:].strip().strip("\"'")
                    long_form = {}
                    if spec.startswith(("target:", "published:", "host_ip:")):
                        k = j
                        while k < len(lines) and lines[k].strip() and (k == j or not lines[k].strip().startswith("- ")):
                            kv = re.match(r"^-?\s*(target|published|host_ip|protocol)\s*:\s*[\"']?([^\"'\s]+)", lines[k].strip())
                            if kv:
                                long_form[kv.group(1)] = kv.group(2)
                            k += 1
                        host_ip, published, target = long_form.get("host_ip", ""), long_form.get("published", ""), long_form.get("target", "")
                    else:
                        spec = spec.split("/")[0]
                        if spec.startswith("["):
                            host_ip, _, rest = spec[1:].partition("]:")
                            host_ip = "[" + host_ip + "]"
                            published, _, target = rest.partition(":")
                        else:
                            bits = spec.split(":")
                            host_ip, published, target = (bits + ["", "", ""])[:3] if len(bits) == 3 else \
                                ("", bits[0], bits[1]) if len(bits) == 2 else ("", "", bits[0])
                    if host_ip not in LOOPBACK:
                        port = re.match(r"\d+", target or published or "")
                        port = int(port.group(0)) if port else None
                        out.append({"file": rel, "line": j + 1, "kind": "compose-published-port", "service": service,
                                    "port": port, "published": published or "(random)", "host_ip": host_ip or "all interfaces",
                                    "sensitive": SENSITIVE_PORTS.get(port)})
                j += 1
            i = j
            continue
        i += 1
    return out


def k8s_exposure(rel, text):
    out = []
    offset = 0
    for doc in re.split(r"(?m)^---\s*$", text):
        kind = re.search(r"(?m)^kind\s*:\s*(\w+)", doc)
        for m in re.finditer(r"(?m)^\s*type\s*:\s*[\"']?(LoadBalancer|NodePort)\b", doc):
            if kind is None or kind.group(1) == "Service":
                line = offset + doc[:m.start()].count("\n") + 1
                ranges = "loadBalancerSourceRanges" in doc
                ports = [int(p) for p in re.findall(r"(?m)^\s*-?\s*(?:port|targetPort)\s*:\s*(\d+)", doc)]
                sens = next((SENSITIVE_PORTS[p] for p in ports if p in SENSITIVE_PORTS), None)
                out.append({"file": rel, "line": line, "kind": f"k8s-{m.group(1)}", "ports": ports, "sensitive": sens,
                            "detail": "source ranges restricted" if ranges else "no loadBalancerSourceRanges"})
        for m in re.finditer(r"(?m)^\s*(hostNetwork\s*:\s*true|hostPort\s*:\s*(\d+)|externalIPs\s*:)", doc):
            line = offset + doc[:m.start()].count("\n") + 1
            port = int(m.group(2)) if m.group(2) else None
            out.append({"file": rel, "line": line, "kind": "k8s-host-exposure", "port": port,
                        "sensitive": SENSITIVE_PORTS.get(port), "detail": m.group(1).strip()})
        offset += doc.count("\n") + 1
    return out


def terraform_exposure(rel, text):
    out, stack = [], []
    lines = text.splitlines()
    open_cidr = re.compile(r"(?:cidr_blocks|ipv6_cidr_blocks|source_ranges|cidr_ipv4|cidr_ipv6|source_address_prefix(?:es)?)"
                           r"\s*=\s*[\[\"]?[^\n]*(?:\"0\.0\.0\.0/0\"|\"::/0\"|\"\*\"|\"Internet\"|\"Any\")", re.I)
    for no, ln in enumerate(lines, 1):
        code = ln.split("#")[0]
        for m in re.finditer(r"(?:([A-Za-z_][\w-]*)\s*(?:\"[^\"]*\"\s*)*)?\{|\}", code):
            if m.group(0) == "}":
                if stack:
                    stack.pop()
            else:
                label = re.match(r"(?:resource|dynamic|data|module)\s+\"([\w-]+)\"", code[m.start():])
                stack.append((label.group(1) if label else (m.group(1) or "{"), no))
        if open_cidr.search(code):
            names = [s[0] for s in stack]
            if any("egress" in n for n in names):
                continue
            start = stack[0][1] if stack else no
            block = "\n".join(lines[start - 1:min(len(lines), start + 60)])
            if re.search(r"(?:direction\s*=\s*\"(?:EGRESS|Outbound)\"|\btype\s*=\s*\"egress\")", block, re.I):
                continue
            ports = sorted({int(p) for p in re.findall(r"(?:from_port|to_port|port|destination_port_range|ports)\s*=\s*\[?\"?(\d+)", block)})
            sens = next((SENSITIVE_PORTS[p] for p in ports if p in SENSITIVE_PORTS), None)
            out.append({"file": rel, "line": no, "kind": "terraform-open-ingress", "resource": names[0] if names else "",
                        "ports": ports, "sensitive": sens, "detail": "ingress open to the whole Internet"})
        if re.search(r"\bpublicly_accessible\s*=\s*true", code):
            out.append({"file": rel, "line": no, "kind": "terraform-public-database", "sensitive": "database",
                        "detail": "publicly_accessible = true"})
    return out


def code_exposure(rel, text):
    out = []
    debug = bool(DEBUG_ON.search(text))
    for no, ln in enumerate(text.splitlines(), 1):
        if len(ln) > 2000 or ALLOW_MARK.search(ln):
            continue
        if ("0.0.0.0" in ln or "::" in ln or "*" in ln or "Listen" in ln) and \
                (CODE_BIND.search(ln) or CLI_BIND.search(ln) or GO_ALL.search(ln)):
            out.append({"file": rel, "line": no, "kind": "debug-bind-all" if debug else "bind-all-interfaces",
                        "detail": "debug mode in the same file" if debug else "listens on every interface"})
        m = re.match(r"^\s*EXPOSE\s+(.+)$", ln)
        if m and pathlib.PurePath(rel).name.lower().startswith(("dockerfile", "containerfile")):
            for p in re.findall(r"\d+", m.group(1)):
                out.append({"file": rel, "line": no, "kind": "dockerfile-expose", "port": int(p),
                            "sensitive": SENSITIVE_PORTS.get(int(p)), "detail": "image declares the port"})
        if re.match(r"^\s*bind\s+0\.0\.0\.0\b", ln):
            svc = next((name for rx, name in FILE_SERVICE if rx.search(pathlib.PurePath(rel).name)), None)
            out.append({"file": rel, "line": no, "kind": "service-bind-all", "sensitive": svc, "detail": ln.strip()[:80]})
    lines = text.splitlines()
    for label, rx in AUTH_OFF:
        for m in rx.finditer(text):
            no = text[:m.start()].count("\n") + 1
            if not ALLOW_MARK.search(lines[no - 1] if no <= len(lines) else ""):
                out.append({"file": rel, "line": no, "kind": "auth-disabled", "detail": label})
    return out

# ----------------------------------------------------------------------------------------------- sweep


def walk(root, max_files):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not (pathlib.Path(dirpath, d, "pyvenv.cfg")).exists())
        for f in sorted(filenames):
            p = pathlib.Path(dirpath, f)
            if p.is_symlink() or not p.is_file():
                continue
            files.append(p)
            if len(files) >= max_files:
                return files, True
    return files, False


def sweep(root, args):
    notes, hardening, scope = [], [], []
    files, truncated = walk(root, args.max_files)
    if truncated:
        notes.append(f"Stopped after {args.max_files} files (--max-files); the rest of the tree was not scanned.")
    is_repo = (root / ".git").exists()
    tracked = None
    if is_repo:
        out, err = git(root, "ls-files", "-z")
        if out is None:
            notes.append(f"git ls-files failed ({err}); tracked status is NOT VERIFIED.")
        else:
            tracked = set(x for x in out.split("\0") if x)
    else:
        notes.append("Not a git repository: whether files are committed is unknown; every sensitive file present is reported.")

    sensitive, secrets, exposure = [], [], []
    for p in files:
        rel = p.relative_to(root).as_posix()
        kind = classify_name(rel)
        text = read_text(p, 2_000_000) if is_text(p) else None
        if kind is None and text is not None and env_by_content(rel, text):
            kind = "env-file"
        if kind:
            entry = {"path": rel, "kind": kind, "tracked": (rel in tracked) if tracked is not None else None,
                     "web_served_dir": bool(WEB_DIRS.search("/" + rel)), "test_path": bool(TEST_PATH.search("/" + rel))}
            if text is not None and kind in ("env-file", "env-template"):
                keys = env_keys(text)
                entry["keys"] = [k for k, _ in keys][:60]
                entry["real_looking_values"] = sum(1 for k, v in keys if re.search(SECRET_WORDS, k, re.I) and looks_real(v, k))
            if kind == "key-material":
                if p.name.lower().endswith(KEY_BINARY_EXT):
                    entry["detail"] = "binary key store"
                elif text is not None and "PRIVATE KEY" not in text:
                    continue       # a certificate or a public key: not secret
            sensitive.append(entry)
        if text is None or p.name in LOCKFILES or p.suffix == ".map":
            continue
        ext = p.suffix.lower()
        config_like = ext not in CODE_EXT or kind is not None
        found = scan_secrets(rel, text, config_like)
        for h in found:
            h["tracked"] = (rel in tracked) if tracked is not None else None
            h["test_or_doc_path"] = bool(TEST_PATH.search("/" + rel)) or ext in DOC_EXT
        secrets += found
        low = p.name.lower()
        if ext in DOC_EXT:
            continue
        if COMPOSE_NAME.match(low) or (ext in (".yml", ".yaml") and re.search(r"(?m)^services\s*:", text)
                                       and re.search(r"(?m)^\s+(?:image|build)\s*:", text)):
            exposure += compose_ports(rel, text)
        if ext in (".yml", ".yaml", ".json") and re.search(r"(?m)^\s*kind\s*:\s*\w+", text):
            exposure += k8s_exposure(rel, text)
        elif ext in (".yml", ".yaml") and re.search(r"(?m)^\s*type\s*:\s*[\"']?(LoadBalancer|NodePort)", text):
            exposure += k8s_exposure(rel, text)
        if ext in (".tf", ".hcl") or low.endswith(".tf.json"):
            exposure += terraform_exposure(rel, text)
        exposure += code_exposure(rel, text)

    history = []
    if is_repo and not args.no_history and tracked is not None:
        current = {h["hash"] for h in secrets}
        out, err = git(root, "log", "--all", "--diff-filter=A", "--no-renames", "--name-only", "--format=%x01%H %cs",
                       "-n", "50000", timeout=300)
        if out is None:
            notes.append(f"git history (file names) failed ({err}); NOT VERIFIED.")
        else:
            commit = date = ""
            for ln in out.splitlines():
                if ln.startswith("\x01"):
                    commit, date = (ln[1:].split(" ") + [""])[:2]
                elif ln.strip():
                    kind = classify_name(ln.strip())
                    unambiguous = kind != "key-material" or re.search(
                        r"(^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|\.(?:p12|pfx|jks|keystore|kdbx|ppk)$", ln.strip(), re.I)
                    if kind and kind != "env-template" and unambiguous and ln.strip() not in tracked \
                            and not TEST_PATH.search("/" + ln.strip()):
                        history.append({"path": ln.strip(), "kind": kind, "commit": commit[:12], "date": date,
                                        "what": "file added in history, no longer tracked"})
        out, err = git(root, "log", "--all", "-p", "--no-textconv", "--no-ext-diff", "--no-color", "--unified=0",
                       "-n", str(args.history_commits), "--format=%x01%H %cs", timeout=600)
        if out is None:
            notes.append(f"git history (content) failed ({err}); secrets removed from the tree were NOT VERIFIED.")
        else:
            commit = date = path = ""
            for ln in out.splitlines():
                if ln.startswith("\x01"):
                    commit, date = (ln[1:].split(" ") + [""])[:2]
                elif ln.startswith("+++ b/"):
                    path = ln[6:]
                elif ln.startswith("+") and not ln.startswith("+++") and len(ln) < 4000:
                    for kind, rx in PROVIDER:
                        for m in rx.finditer(ln):
                            v = m.group(0)
                            if v in KNOWN_EXAMPLES or "EXAMPLE" in v.upper() or vhash(v) in current:
                                continue
                            history.append({"path": path, "kind": kind, "commit": commit[:12], "date": date,
                                            "masked": mask(v), "hash": vhash(v), "what": "secret only in history"})
                            current.add(vhash(v))
        scope.append(f"git history: file names in every commit; added lines in the last {args.history_commits} commits.")

    gaps = []
    if is_repo:
        probes = [".env", ".env.local", ".env.production", "config/.env", "secrets.env", "prod.env", ".envrc",
                  ".dev.vars", "local.settings.json", "id_rsa", "server.key", "key.pem", "terraform.tfstate",
                  "prod.tfvars", "credentials.json"]
        probes += [e["path"] for e in sensitive if e["kind"] != "env-template" and not e["test_path"]]
        # check-ignore exits 1 when nothing is ignored; 128 is a real error.
        out, err = git(root, "check-ignore", "--no-index", "-z", "--stdin", timeout=60,
                       stdin="\0".join(probes).encode(), ok=(0, 1))
        if out is None:
            notes.append(f"git check-ignore failed ({err}); .gitignore gaps NOT VERIFIED.")
        ignored = set(x for x in (out or "").split("\0") if x)
        gaps = sorted(set(p for p in probes if p not in ignored)) if out is not None else []
        if gaps:
            hardening.append("Not covered by .gitignore: " + ", ".join(gaps[:20])
                             + ". Add patterns such as .env, .env.*, !.env.example, *.pem, *.key, *.tfstate, *.tfvars.")
    with_hits = {h["file"] for h in secrets}
    for e in sensitive:
        if e["kind"] == "env-file" and e.get("tracked") and not e.get("real_looking_values") and e["path"] not in with_hits:
            hardening.append(f"{e['path']} is committed but holds no secret-looking values: rename it to "
                             f"{e['path']}.example and ignore the real one.")
    in_docs = [h for h in secrets if h["test_or_doc_path"] and h["confidence"] == "high"]
    if in_docs:
        hardening.append(f"{len(in_docs)} provider-format value(s) in documentation or tests (for example "
                         f"{in_docs[0]['file']}:{in_docs[0]['line']}); usually examples, but check them in exposures-raw.json.")
    binds = [x for x in exposure if x["kind"] in ("bind-all-interfaces", "dockerfile-expose") and not x.get("sensitive")]
    if binds:
        hardening.append(f"{len(binds)} listener(s) on every interface or exposed image port(s); normal inside a "
                         "container, but confirm what publishes them (exposures-raw.json → exposure).")
    return {"is_repo": is_repo, "tracked_files": len(tracked) if tracked is not None else None, "files_scanned": len(files),
            "sensitive_files": sensitive, "secrets": secrets, "history": history, "gitignore_gaps": gaps,
            "exposure": exposure, "hardening_notes": hardening, "not_verified": notes, "scope": scope}

# ----------------------------------------------------------------------------------------------- findings


def record(fprint, title, description, root_cause, trace, evidence, blockers, plan, sources):
    return {"verdict": "needs_validation", "fingerprint": fp("exp", fprint), "title": title, "description": description,
            "claimed_root_cause": root_cause, "trace": trace, "evidence": evidence, "blockers": blockers,
            "validation_plan": plan, "sources": sources, "category": "code"}


def findings(raw):
    recs = []
    committed = lambda x: x.get("tracked") is not False      # tracked, or unknown outside git
    by_file = {}
    for s in raw["secrets"]:
        if committed(s) and not s["test_or_doc_path"]:
            by_file.setdefault(s["file"], []).append(s)
    for e in raw["sensitive_files"]:
        if e["kind"] == "env-template" or not committed(e):
            continue
        hits = by_file.pop(e["path"], [])
        if e["test_path"]:
            continue       # test keys and fixture env files: kept in exposures-raw.json, not leads
        if e["kind"] == "env-file" and not hits and not e.get("real_looking_values") and not e["web_served_dir"]:
            continue       # a committed env file without secret-looking values is a hardening note, not a lead
        where = "committed to the repository" if e.get("tracked") else "present in the tree (no git metadata)"
        served = e["web_served_dir"]
        sources = [dict(SRC_ASVS_1331), cwe(538 if served else 540), dict(SRC_A02),
                   attack("T1552.004" if e["kind"] == "key-material" else "T1552.001")]
        if served:
            sources.insert(1, dict(SRC_ASVS_1347))
        detail = (f" It holds {len(hits)} secret-looking value(s): " + "; ".join(f"{h['kind']} {h['key']} {h['masked']}".strip()
                                                                           for h in hits[:5]) + "." if hits else "")
        if e.get("keys"):
            detail += f" Variables: {', '.join(e['keys'][:15])}."
        recs.append(record(
            f"file-{e['path']}", f"{e['kind'].replace('-', ' ').capitalize()} {where}: {e['path']}",
            f"{e['path']} ({e['kind']}) is {where}" + (", inside a directory that is usually served to the web" if served else "")
            + "." + detail + " Values are masked in this report.",
            f"A {e['kind'].replace('-', ' ')} is distributed with the source instead of being injected at deploy time from a secret store.",
            [{"kind": "sink", "file": e["path"], "line": 1, "scope": e["path"], "description": f"{e['kind']} {where}"}],
            [{"file": e["path"], "line": h["line"], "description": f"{h['kind']} {h['key']} {h['masked']}".strip()}
             for h in hits[:10]] or [{"file": e["path"], "line": 1, "description": f"{e['kind']} {where}"}],
            ["Whether the values are live credentials, and who can read this repository or the served directory, "
             "are facts outside the source."],
            {"local": "Check each value against the secret store or with its owner, without using it; if live, rotate it "
                      "(deleting the file does not remove it from git history) and replace the file with an ignored "
                      "local one plus a committed .example.",
             "deployment": "If the directory is served, request the file from the deployed site only with the owner's "
                           "authorisation." if served else "Confirm who can read the repository."},
            sources))
    for path, hits in sorted(by_file.items()):
        recs.append(record(
            f"secret-{path}-{hits[0]['line']}", f"Hard-coded secret-looking value(s) in {path}",
            f"{len(hits)} value(s) in {path}: " + "; ".join(f"line {h['line']}: {h['kind']} {h['key']} {h['masked']}".strip()
                                                            for h in hits[:8]) + ". Values are masked in this report.",
            "A credential is written in the source instead of being read from a secret store at runtime.",
            [{"kind": "sink", "file": path, "line": hits[0]["line"], "scope": path, "description": hits[0]["kind"]}],
            [{"file": path, "line": h["line"], "description": f"{h['kind']} {h['key']} {h['masked']}".strip()} for h in hits[:10]],
            ["Whether each value is a live credential (not a test value or a public identifier) is a fact outside the source."],
            {"local": "Trace where the value is used and ask its owner whether it is live, without using it; if live, rotate "
                      "it and move it to the secret store."},
            [dict(SRC_ASVS_1331), cwe(798), dict(SRC_A02), attack("T1552.001")]))
    hist = {}
    for h in raw["history"]:
        hist.setdefault(h["path"], []).append(h)
    for path, items in sorted(hist.items()):
        recs.append(record(
            f"history-{path}-{items[0]['commit']}", f"Secret material left in git history: {path}",
            f"{path} " + "; ".join(f"{i['what']} ({i['kind']}{' ' + i['masked'] if i.get('masked') else ''}, "
                                   f"commit {i['commit']}, {i['date']})" for i in items[:5])
            + ". Anyone with a clone can read it.",
            "Removing a file or a value from the working tree leaves it in every earlier commit.",
            [{"kind": "sink", "file": path, "line": 1, "scope": f"commit {items[0]['commit']}", "description": items[0]["what"]}],
            [{"file": path, "line": 1, "description": f"{i['kind']} in commit {i['commit']}"} for i in items[:10]],
            ["Whether the value was a live credential, and whether it was rotated, are facts outside the source."],
            {"local": "Treat the value as exposed: confirm with its owner that it was rotated. Rewriting history does not "
                      "help once the repository has been cloned or published."},
            [dict(SRC_ASVS_1331), cwe(540), attack("T1552.001")]))
    for x in raw["exposure"]:
        sens = x.get("sensitive")
        k = x["kind"]
        if TEST_PATH.search("/" + x["file"]):
            continue
        web_only = set(x.get("ports") or [x.get("port")] if (x.get("ports") or x.get("port")) else []) <= {80, 443} \
            and bool(x.get("ports") or x.get("port"))
        if k in ("bind-all-interfaces", "dockerfile-expose"):
            continue
        if k == "compose-published-port" and not sens:
            continue
        if k == "k8s-host-exposure" and x.get("port") and not sens:
            continue
        if k in ("k8s-LoadBalancer", "k8s-NodePort") and not sens:
            continue       # a public web entry point is normal; only sensitive ports become leads
        if k == "terraform-open-ingress" and not sens and web_only:
            continue
        if k == "auth-disabled":
            title, cause = f"Authentication or protection disabled: {x['detail']}", f"{x['detail']} in the configuration."
            sources = [dict(SRC_CM7), cwe(306), dict(SRC_A02), attack("T1133")]
        elif k == "debug-bind-all":
            title, cause = f"Debug server listening on every interface in {x['file']}", \
                "Debug mode and an all-interface listener are enabled together."
            sources = [dict(SRC_ASVS_1342), cwe(489), cwe(1327), attack("T1190")]
        else:
            what = sens or "a service"
            title = f"{what} exposed beyond the host: {x['file']}"
            cause = f"The configuration publishes {what} to every network interface or to the Internet ({k}: {x.get('detail', '')})."
            sources = [dict(SRC_SC7), cwe(1327), dict(SRC_190), attack("T1133")]
            if sens and re.search(r"Prometheus|exporter|Kibana|Grafana|management|UI", str(sens)):
                sources.insert(1, dict(SRC_ASVS_1345))
        desc = (f"{x['file']}:{x['line']} — {k}" + (f", service {x['service']}" if x.get("service") else "")
                + (f", port {x.get('port') or x.get('ports')}" if (x.get("port") or x.get("ports")) else "")
                + (f", host {x['host_ip']}" if x.get("host_ip") else "") + (f": {x['detail']}" if x.get("detail") else "") + ".")
        recs.append(record(
            f"net-{x['file']}-{x['line']}-{k}", title, desc, cause,
            [{"kind": "sink", "file": x["file"], "line": x["line"], "scope": x.get("service") or x.get("resource") or x["file"],
              "description": k}],
            [{"file": x["file"], "line": x["line"], "description": desc}],
            ["Which networks can reach this listener in the deployed environment (firewalls, security groups, ingress) "
             "is a fact outside the source."],
            {"local": "Read the deployment's network configuration for this service; publish it on 127.0.0.1 or an internal "
                      "network, or restrict its source ranges, unless it is meant to be public.",
             "deployment": "Confirm reachability with the owner's network diagrams or an authorised scan; never probe "
                           "systems you are not authorised to test."},
            sources))
    return sorted(recs, key=lambda r: r["fingerprint"])

# ----------------------------------------------------------------------------------------------- main


def summary(raw, recs):
    lines = [f"files scanned: {raw['files_scanned']} · git repository: {'yes' if raw['is_repo'] else 'no'}",
             f"sensitive files: {len(raw['sensitive_files'])} · secret-looking values: {len(raw['secrets'])} · "
             f"in history only: {len(raw['history'])} · exposure items: {len(raw['exposure'])} · leads: {len(recs)}"]
    for r in recs[:25]:
        lines.append(f"  - {r['title']}")
    for n in raw["hardening_notes"]:
        lines.append(f"  hardening: {n}")
    for n in raw["not_verified"]:
        lines.append(f"  NOT VERIFIED: {n}")
    for n in raw["scope"]:
        lines.append(f"  scope: {n}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("target")
    ap.add_argument("--out")
    ap.add_argument("--no-history", action="store_true")
    ap.add_argument("--history-commits", type=int, default=300)
    ap.add_argument("--max-files", type=int, default=20000)
    args = ap.parse_args()
    root = pathlib.Path(args.target).resolve()
    if not root.is_dir():
        sys.exit(f"{root} is not a directory")
    out = pathlib.Path(args.out).resolve() if args.out else None
    if out and (out == root or root in out.parents):
        sys.exit("the output directory must be outside the audited target")
    raw = sweep(root, args)
    recs = findings(raw)
    raw.update({"target": root.name,
                "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "limits": ["Pattern matching finds known formats and secret-like assignments; it cannot prove a tree "
                           "clean, and a value in an unusual format can be missed.",
                           "Static configuration says what is published, not what a firewall in front of it allows."]})
    for s in raw["secrets"] + raw["history"]:
        s.pop("hash", None)
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / "exposures-raw.json").write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (out / "exposures-findings.json").write_text(json.dumps(recs, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(summary(raw, recs))


if __name__ == "__main__":
    main()
