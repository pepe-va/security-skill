# Exposure sweep — environment files, secrets and network exposure

A deterministic first pass for mode 2 (and, without `--out`, a quick check in consultation): it finds what the *Obvious things* hunter of `upstream/ATTACK-CLASSES.md` looks for, in every file and every programming language, so the agent spends its reading on triage instead of on searching.

## Run

```bash
python scripts/find_exposures.py <target>                      # summary only, no files (consultation)
python scripts/find_exposures.py <target> --out <output-dir>   # writes exposures-raw.json and exposures-findings.json
```

It reads files only: no target code runs and nothing is contacted. When the target is a git repository it runs `git ls-files`, `git check-ignore` and `git log` with the repository's risky settings overridden (fsmonitor, hooks, pager, textconv, external diff) and without user or system configuration. Options: `--no-history`, `--history-commits N` (default 300), `--max-files N`.

**Secret values never leave the machine in clear**: every output shows a masked prefix and the length (`S3… (14 chars)`), never the value. Do not paste values into the report either.

## What it finds

| Area | Detected | Never a lead |
|---|---|---|
| Environment-variable files | By name: `.env`, `.env.*`, `*.env`, `.envrc`, `.flaskenv`, `.dev.vars`, `env.list`, `setenv.sh`, `env.yaml`, `local.settings.json`, `*.tfvars`. By content, whatever the name: mostly `KEY=VALUE` / `export KEY=…` lines with upper-case keys | Templates (`.env.example`, `.sample`, `.template`, `.dist`…) unless they hold real-looking values |
| Credential stores and keys | `.netrc`, `.git-credentials`, `.pgpass`, `.aws/credentials`, `.docker/config.json`, kubeconfig, `secrets.yml`, service-account JSON, `master.key`, private keys (`id_rsa`, `*.pem`/`*.key` with `PRIVATE KEY`), key stores (`.p12`, `.pfx`, `.jks`, `.kdbx`, `.ppk`), `*.tfstate` | Certificates and public keys; key material under test or fixture paths |
| Secrets in any file | Provider formats (AWS, GitHub, GitLab, Slack, Stripe live, Google, OpenAI, Anthropic, Hugging Face, npm, PyPI, SendGrid, Twilio, Telegram, Azure storage, private keys, credentials in connection URLs) and secret-like assignments in any language and in many human languages (`password`, `contraseña`, `clave`, `senha`, `Passwort`, `mot de passe`, `пароль`…) with a literal, non-placeholder value | `os.environ[...]`, `process.env`, `${VAR}`, `changeme`, `<your-key>`, AWS documentation keys, hashes (`$2b$…`), paths, ARNs |
| Git | Sensitive files ever committed and no longer tracked; provider-format secrets added in the last N commits and gone from the tree; `.gitignore` gaps for the usual secret files | |
| Network exposure (static) | docker-compose ports published on every interface, `network_mode: host`; Kubernetes `LoadBalancer`/`NodePort`, `hostNetwork`, `hostPort`; Terraform ingress open to `0.0.0.0/0` / `::/0` / `*`, `publicly_accessible = true`; debug servers on `0.0.0.0`; `bind 0.0.0.0` in service configs; disabled protection (Redis `protected-mode no`, Docker API on `:2375`, Elasticsearch security off, MongoDB authorization disabled, Jupyter without token, kubelet anonymous auth, directory listing) | Ports 80/443 open to the Internet; ports published on `127.0.0.1`; plain listeners on `0.0.0.0` (normal inside a container: listed in `exposures-raw.json` and summarised as a hardening note) |

## Triage

Every record in `exposures-findings.json` is `needs_validation` with its sources. Copy the ones that survive triage into `findings.json`:

- **Committed env file or secret** → stays `needs_validation` unless the source itself proves the value is live (for example the same value authenticates in a test that runs against a real service). Never test a credential to find out. The remediation is **rotate first**, then move the value to the secret store and ignore the file: deleting it does not remove it from git history.
- **Secret only in history** → same; treat it as exposed if the repository was ever cloned or published.
- **Env file in a web-served directory** (`public/`, `static/`, `www/`, `dist/`…) → high priority: if that directory is the web root, the file is downloadable. Confirm from the server or build configuration in the repository.
- **Published port or open ingress** → `needs_validation` until the deployment's network configuration shows who can reach it. A repository-controlled public route to an unauthenticated admin, debug or data service can be `confirmed` (`upstream/CLOUD-AND-DEPLOYMENT.md` → *Unexpected service or management-plane reachability*).
- **Debug server on every interface** → the Werkzeug, Django and similar debuggers run code for whoever reaches them: confirm whether this entry point runs outside development.

Rejected leads (test values, documentation, public identifiers) go to `findings.json` as `rejected` with the reason, so the next run does not repeat them. `.gitignore` gaps and plain listeners are hardening notes (`run-metadata.json` → `hardening_notes`).

## Sources it attaches

| Lead | Requirement | Weakness | Other |
|---|---|---|---|
| Committed env file, credential store, key | ASVS `v5.0.0-13.3.1` | `CWE-540` | `A02:2025`, ATT&CK `T1552.001` / `T1552.004` |
| Same, in a web-served directory | ASVS `v5.0.0-13.3.1`, `v5.0.0-13.4.7` | `CWE-538` | |
| Hard-coded secret | ASVS `v5.0.0-13.3.1` | `CWE-798` | `A02:2025`, ATT&CK `T1552.001` |
| Secret in git history | ASVS `v5.0.0-13.3.1` | `CWE-540` | ATT&CK `T1552.001` |
| Service exposed beyond the host | 800-53 `SC-7` (monitoring: ASVS `v5.0.0-13.4.5`) | `CWE-1327` | `800-190 §4.4.2`, ATT&CK `T1133` |
| Debug server on every interface | ASVS `v5.0.0-13.4.2` | `CWE-489`, `CWE-1327` | ATT&CK `T1190` |
| Protection disabled | 800-53 `CM-7` | `CWE-306` | `A02:2025`, ATT&CK `T1133` |

Controls: SC-SEC-01 (secrets) and SC-NET-01 (network exposure) in `../sc-controls-catalog.md`.

## Limits

Pattern matching finds known formats and secret-like assignments; it cannot prove a tree clean, and a secret in an unusual format or under a neutral variable name can be missed. Static configuration says what is published, not what a firewall in front of it allows. Live port scanning is out of scope: run it yourself only on systems you are authorised to test, and paste the result into a consultation to have it classified.
