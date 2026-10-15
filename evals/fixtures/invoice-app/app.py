"""Small invoicing service (demo). Run: python app.py  — serves on 127.0.0.1:8080."""
import json
import sqlite3
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from auth import current_user, login

DB = "invoices.db"


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def respond(start, status, body):
    start(status, [("Content-Type", "application/json")])
    return [json.dumps(body).encode()]


def app(environ, start):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/login" and method == "POST":
        size = int(environ.get("CONTENT_LENGTH") or 0)
        form = parse_qs(environ["wsgi.input"].read(size).decode())
        token = login(form.get("user", [""])[0], form.get("password", [""])[0])
        if not token:
            return respond(start, "401 Unauthorized", {"error": "invalid credentials"})
        return respond(start, "200 OK", {"token": token})

    user = current_user(environ.get("HTTP_AUTHORIZATION", ""))
    if user is None:
        return respond(start, "401 Unauthorized", {"error": "login required"})

    if path.startswith("/invoices/"):
        invoice_id = path.rsplit("/", 1)[-1]
        row = db().execute("SELECT id, owner_id, customer, amount, iban FROM invoices WHERE id = ?",
                           (invoice_id,)).fetchone()
        if row is None:
            return respond(start, "404 Not Found", {"error": "not found"})
        return respond(start, "200 OK", dict(row))

    if path == "/invoices":
        rows = db().execute("SELECT id, customer, amount FROM invoices WHERE owner_id = ?", (user["id"],)).fetchall()
        return respond(start, "200 OK", [dict(r) for r in rows])

    if path == "/search":
        q = parse_qs(environ.get("QUERY_STRING", "")).get("q", [""])[0]
        sql = (f"SELECT id, customer, amount FROM invoices "
               f"WHERE owner_id = {user['id']} AND customer LIKE '%{q}%'")
        rows = db().execute(sql).fetchall()
        return respond(start, "200 OK", [dict(r) for r in rows])

    return respond(start, "404 Not Found", {"error": "no route"})


if __name__ == "__main__":
    make_server("127.0.0.1", 8080, app).serve_forever()
