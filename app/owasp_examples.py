"""
OWASP Top 10 practice: vulnerable vs fixed code side by side.
Run the self-test at the bottom:  python owasp_examples.py
(Uses only the standard library.)
"""

import hashlib
import hmac
import os
import sqlite3
import subprocess

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (id INTEGER, name TEXT, secret TEXT)")
db.execute("INSERT INTO users VALUES (1, 'alice', 's3cr3t-a'), (2, 'bob', 's3cr3t-b')")


# ---------- A03 Injection (SQL) ----------
def get_user_vulnerable(name):
    # Attacker input:  x' OR '1'='1   -> returns every row
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


def get_user_fixed(name):
    # Parameterised query: input is data, never code
    return db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()


# ---------- A01 Broken Access Control (IDOR) ----------
def read_secret_vulnerable(requested_id, current_user_id):
    # Trusts the ID from the request; any user can read any record
    return db.execute("SELECT secret FROM users WHERE id = ?", (requested_id,)).fetchone()


def read_secret_fixed(requested_id, current_user_id):
    # Server-side authorisation check
    if requested_id != current_user_id:
        raise PermissionError("forbidden")
    return db.execute("SELECT secret FROM users WHERE id = ?", (requested_id,)).fetchone()


# ---------- A03 Injection (OS command) ----------
def ping_vulnerable(host):
    # host = "8.8.8.8; cat /etc/passwd"  -> shell injection
    return subprocess.run(f"ping -c1 {host}", shell=True, capture_output=True, text=True)


def ping_fixed(host):
    # No shell, argument list, plus input validation
    if not host.replace(".", "").isdigit():
        raise ValueError("invalid host")
    return subprocess.run(["ping", "-c1", host], capture_output=True, text=True)


# ---------- A02 Cryptographic Failures ----------
def hash_password_vulnerable(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # fast, unsalted, broken


def hash_password_fixed(pw):
    salt = os.urandom(16)
    digest = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + ":" + digest.hex()


def verify_password(pw, stored):
    salt_hex, digest_hex = stored.split(":")
    candidate = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate.hex(), digest_hex)  # constant-time compare


# ---------- Self-test ----------
if __name__ == "__main__":
    print("SQLi vulnerable :", get_user_vulnerable("x' OR '1'='1"))
    print("SQLi fixed      :", get_user_fixed("x' OR '1'='1"))
    print("IDOR vulnerable :", read_secret_vulnerable(2, current_user_id=1))
    try:
        read_secret_fixed(2, current_user_id=1)
    except PermissionError:
        print("IDOR fixed      : blocked (PermissionError)")
    print("MD5             :", hash_password_vulnerable("password"))
    stored = hash_password_fixed("password")
    print("scrypt verifies :", verify_password("password", stored))
