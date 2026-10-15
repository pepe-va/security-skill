"""Login and session tokens for the invoicing service."""
import hashlib
import hmac
import secrets
import sqlite3

DB = "invoices.db"
SESSIONS = {}  # token -> user id (in memory)


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 600_000)


def login(username, password):
    con = sqlite3.connect(DB)
    row = con.execute("SELECT id, salt, pw_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not hmac.compare_digest(_hash(password, row[1]), row[2]):
        return None
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = row[0]
    return token


def current_user(header):
    if not header.startswith("Bearer "):
        return None
    uid = SESSIONS.get(header[7:])
    return {"id": uid} if uid is not None else None
