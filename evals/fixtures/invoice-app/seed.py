"""Create invoices.db with two demo users and their invoices (dummy data only)."""
import hashlib
import os
import sqlite3

con = sqlite3.connect("invoices.db")
con.executescript("""
DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS invoices;
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt BLOB, pw_hash BLOB);
CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER, customer TEXT, amount REAL, iban TEXT);
""")
for uid, name in ((1, "alice"), (2, "bob")):
    salt = os.urandom(16)
    con.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                (uid, name, salt, hashlib.pbkdf2_hmac("sha512", b"demo-password", salt, 600_000)))
con.executemany("INSERT INTO invoices VALUES (?, ?, ?, ?, ?)", [
    (1, 1, "Acme Ltd", 1200.0, "DE00 0000 0000 0000 0000 01"),
    (2, 2, "Globex", 830.5, "DE00 0000 0000 0000 0000 02"),
])
con.commit()
