"""Tests for scripts/find_exposures.py.

A temporary repository mixes what must be found (environment-variable files under any name, keys, secrets in
English and Spanish key names, a secret only in git history, published database ports, an open SSH rule, a debug
server on every interface, Redis without protected mode) with what must not (templates, AWS documentation
example keys, environment lookups, certificates, web ports, loopback ports, `Options -Indexes`, test fixtures).
Run: python -m unittest discover tests
"""
import json, pathlib, shutil, subprocess, sys, tempfile, unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = REPO / "skills" / "security" / "cybersec-skill" / "scripts"
SCRIPT = TOOLS / "find_exposures.py"
VALIDATOR = TOOLS / "validate_findings.py"

SECRETS = {   # value -> must never appear unmasked in any output
    "S3cr3tP4ssw0rd": ".env.production",
    "sk_live_" + "A" * 24: ".env.production",
    "Zq8vR2mX9kL4pW7nT3yB6cJ1": "deploy/prod.env",
    "Hj8sK2lP9qW4eR7tY1uI3oP5": "conf/runtime_vars",
    "ghp_" + "a1B2c3D4e5" * 4: "app/public/.env",
    "Verano2024!Seguro": "conf/ajustes.yaml",
    "Xk9mP2qL8vN4rT6wZ1yB": "conf/ajustes.yaml",
    "glpat-" + "x7Y8z9" * 4: "old.env (history)",
}

FILES = {
    ".env.production": "DB_HOST=db\nDB_PASSWORD=S3cr3tP4ssw0rd\nSTRIPE_KEY=sk_live_" + "A" * 24 + "\n",
    "deploy/prod.env": "API_TOKEN=Zq8vR2mX9kL4pW7nT3yB6cJ1\nREGION=eu-west-1\nLOG_LEVEL=info\nPORT=8080\n",
    "conf/runtime_vars": "export APP_SECRET=Hj8sK2lP9qW4eR7tY1uI3oP5\nexport MODE=prod\nexport WORKERS=4\n",
    "app/public/.env": "GITHUB=ghp_" + "a1B2c3D4e5" * 4 + "\n",
    "conf/ajustes.yaml": 'contraseña = "Verano2024!Seguro"\nclave_api: "Xk9mP2qL8vN4rT6wZ1yB"\n',
    "deploy/server.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n",
    "docker-compose.yml": ('services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n'
                           '  web:\n    image: nginx\n    ports:\n      - "80:80"\n'
                           '  cache:\n    image: redis\n    ports:\n      - "127.0.0.1:6379:6379"\n'),
    "deploy/k8s/es.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: es\nspec:\n  type: LoadBalancer\n  ports:\n    - port: 9200\n",
    "infra/main.tf": ('resource "aws_security_group" "ssh" {\n  tags = { Name = "x" }\n  ingress {\n    from_port = 22\n'
                      '    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n  egress {\n    from_port = 0\n    to_port = 0\n'
                      '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_security_group" "web" {\n  ingress {\n'
                      '    from_port = 443\n    to_port = 443\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'),
    "app/server.py": 'from flask import Flask\napp = Flask(__name__)\nif __name__ == "__main__":\n    app.run(host="0.0.0.0", debug=True)\n',
    "conf/redis.conf": "bind 0.0.0.0\nprotected-mode no\n",
    # must not become leads
    ".env.example": "DB_PASSWORD=changeme\nAPI_KEY=${API_KEY}\nSECRET=<your-secret>\n",
    "app/settings.py": 'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\naws_key = "AKIAIOSFODNN7EXAMPLE"\npassword = getpass()\n',
    "deploy/ca.pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    "conf/site.conf": "Options -Indexes\n",
    "tests/fixtures/test.env": "TEST_TOKEN=Abc123Def456Ghi789Jkl0\nA=1\nB=2\n",
    "README.md": 'Run locally with `app.run(host="0.0.0.0", debug=True)` and DB_PASSWORD=Example123456.\n',
    ".gitignore": ".env.example\n",
}

EXPECTED_LEADS = [
    ".env.production", "app/public/.env", "conf/runtime_vars", "deploy/prod.env", "deploy/server.key", "old.env",
    "app/server.py", "conf/redis.conf", "deploy/k8s/es.yaml", "docker-compose.yml", "infra/main.tf", "conf/ajustes.yaml",
]
NOT_LEADS = [".env.example", "app/settings.py", "deploy/ca.pem", "conf/site.conf", "tests/fixtures/test.env", "README.md"]


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True, capture_output=True)


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class FindExposures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.target, cls.out = cls.tmp / "target", cls.tmp / "out"
        for rel, text in FILES.items():
            p = cls.target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        git(cls.target, "init", "-q")
        git(cls.target, "add", "-A")
        git(cls.target, "commit", "-qm", "init")
        (cls.target / "old.env").write_text("OLD_TOKEN=glpat-" + "x7Y8z9" * 4 + "\n", encoding="utf-8")
        git(cls.target, "add", "old.env")
        git(cls.target, "commit", "-qm", "add")
        git(cls.target, "rm", "-q", "old.env")
        git(cls.target, "commit", "-qm", "rm")
        cls.proc = subprocess.run([sys.executable, "-I", str(SCRIPT), str(cls.target), "--out", str(cls.out)],
                                 capture_output=True, text=True, timeout=120)
        cls.leads = json.loads((cls.out / "exposures-findings.json").read_text())
        cls.raw = json.loads((cls.out / "exposures-raw.json").read_text())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def lead_files(self):
        return {t["file"] for r in self.leads for t in r["trace"]}

    def test_runs(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)

    def test_expected_leads(self):
        self.assertEqual(sorted(set(EXPECTED_LEADS) - self.lead_files()), [])

    def test_no_false_leads(self):
        self.assertEqual(sorted(self.lead_files() & set(NOT_LEADS)), [])

    def test_env_files_found_by_name_and_by_content(self):
        kinds = {e["path"]: e["kind"] for e in self.raw["sensitive_files"]}
        self.assertEqual(kinds.get("conf/runtime_vars"), "env-file")      # no env-like name: found by its content
        self.assertEqual(kinds.get("deploy/prod.env"), "env-file")
        self.assertEqual(kinds.get(".env.example"), "env-template")

    def test_secrets_never_written_unmasked(self):
        blob = "\n".join(p.read_text() for p in self.out.iterdir()) + self.proc.stdout
        for value, where in SECRETS.items():
            self.assertNotIn(value, blob, f"secret from {where} leaked")

    def test_findings_pass_the_validator(self):
        r = subprocess.run([sys.executable, "-I", str(VALIDATOR), str(self.out / "exposures-findings.json")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_every_lead_needs_validation_with_sources(self):
        for r in self.leads:
            self.assertEqual(r["verdict"], "needs_validation")
            self.assertTrue(any(s["relation"] == "weakness" for s in r["sources"]), r["title"])

    def test_gitignore_gap_reported(self):
        self.assertIn(".env", self.raw["gitignore_gaps"])
        self.assertNotIn(".env.example", self.raw["gitignore_gaps"])

    def test_output_must_be_outside_target(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.target), "--out", str(self.target / "o")],
                           capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)

    def test_no_out_writes_nothing(self):
        before = sorted(p.name for p in self.tmp.iterdir())
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(self.target), "--no-history"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), before)


if __name__ == "__main__":
    unittest.main()
