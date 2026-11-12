"""TaskTrack - small task-list API with token login (rescued version).

Standard library only. Run:  python app.py   (set TASKTRACK_SECRET first)
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from wsgiref.simple_server import make_server

TOKEN_TTL = 3600  # seconds
MAX_TITLE = 200
MAX_BODY = 10_000          # bytes
MAX_FAILURES = 5           # failed logins allowed per name...
LOCK_SECONDS = 300         # ...within this window


class HTTPError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return salt.hex() + "$" + digest.hex()


def check_password(password, stored):
    salt_hex, digest_hex = stored.split("$")
    candidate = hash_password(password, bytes.fromhex(salt_hex)).split("$")[1]
    return hmac.compare_digest(candidate, digest_hex)


def make_token(secret, user, now=None):
    expires = int(now if now is not None else time.time()) + TOKEN_TTL
    payload = f"{user}|{expires}"
    sig = hmac.new(secret.encode(), payload.encode(), "sha256").hexdigest()
    return f"{payload}|{sig}"


def read_token(secret, token, now=None):
    try:
        user, expires, sig = token.rsplit("|", 2)
        payload = f"{user}|{expires}"
        good = hmac.new(secret.encode(), payload.encode(), "sha256").hexdigest()
        if hmac.compare_digest(sig, good) and int(expires) > (now if now is not None else time.time()):
            return user
    except (ValueError, AttributeError):
        pass
    return None


def create_app(secret=None, db_path=":memory:"):
    secret = secret or os.environ.get("TASKTRACK_SECRET")
    if not secret:
        raise RuntimeError("Set the TASKTRACK_SECRET environment variable.")
    failures = {}  # name -> list of failure timestamps
    db = sqlite3.connect(db_path, check_same_thread=False)
    db.execute("CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, owner TEXT NOT NULL,"
               " title TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0)")

    def body_of(environ):
        try:
            size = int(environ.get("CONTENT_LENGTH") or 0)
            if size > MAX_BODY:
                raise HTTPError("413 Payload Too Large", "Request body is too large")
            if size < 0:
                raise ValueError("negative length")
            data = json.loads(environ["wsgi.input"].read(size) or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise HTTPError("400 Bad Request", "Invalid JSON body")
        if not isinstance(data, dict):
            raise HTTPError("400 Bad Request", "JSON object expected")
        return data

    def need_str(data, key):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            raise HTTPError("400 Bad Request", f"'{key}' is required")
        return value.strip()

    def current_user(environ):
        header = environ.get("HTTP_AUTHORIZATION", "")
        user = read_token(secret, header[7:]) if header.startswith("Bearer ") else None
        if not user:
            raise HTTPError("401 Unauthorized", "Login required")
        return user

    def route(environ):
        path, method = environ["PATH_INFO"], environ["REQUEST_METHOD"]
        if path == "/register" and method == "POST":
            data = body_of(environ)
            name, password = need_str(data, "name"), need_str(data, "password")
            if len(password) < 8:
                raise HTTPError("400 Bad Request", "Password must have at least 8 characters")
            try:
                db.execute("INSERT INTO users VALUES (?, ?)", (name, hash_password(password)))
                db.commit()
            except sqlite3.IntegrityError:
                raise HTTPError("409 Conflict", "User already exists")
            return "201 Created", {"ok": True}
        if path == "/login" and method == "POST":
            data = body_of(environ)
            name, password = need_str(data, "name"), need_str(data, "password")
            now = time.time()
            recent = [t for t in failures.get(name, []) if now - t < LOCK_SECONDS]
            if len(recent) >= MAX_FAILURES:
                raise HTTPError("429 Too Many Requests", "Too many failed logins, try again later")
            row = db.execute("SELECT password FROM users WHERE name=?", (name,)).fetchone()
            if not row or not check_password(password, row[0]):
                failures[name] = recent + [now]
                raise HTTPError("401 Unauthorized", "Wrong name or password")
            return "200 OK", {"token": make_token(secret, name)}

        user = current_user(environ)
        if path == "/tasks" and method == "GET":
            rows = db.execute("SELECT id, title, done FROM tasks WHERE owner=? ORDER BY id", (user,)).fetchall()
            return "200 OK", [{"id": r[0], "title": r[1], "done": bool(r[2])} for r in rows]
        if path == "/tasks" and method == "POST":
            title = need_str(body_of(environ), "title")
            if len(title) > MAX_TITLE:
                raise HTTPError("400 Bad Request", f"Title is longer than {MAX_TITLE} characters")
            cur = db.execute("INSERT INTO tasks (owner, title) VALUES (?, ?)", (user, title))
            db.commit()
            return "201 Created", {"id": cur.lastrowid}
        if path.startswith("/tasks/") and method in ("POST", "DELETE"):
            tail = path.split("/")[-1]
            if not tail.isdigit():
                raise HTTPError("400 Bad Request", "Task id must be a number")
            task_id = int(tail)
            if method == "POST":
                cur = db.execute("UPDATE tasks SET done=1 WHERE id=? AND owner=?", (task_id, user))
            else:
                cur = db.execute("DELETE FROM tasks WHERE id=? AND owner=?", (task_id, user))
            db.commit()
            if cur.rowcount == 0:
                raise HTTPError("404 Not Found", "Task not found")
            return "200 OK", {"ok": True}
        raise HTTPError("404 Not Found", "Unknown route")

    def app(environ, start_response):
        try:
            status, data = route(environ)
        except HTTPError as err:
            status, data = err.status, {"error": err.message}
        body = json.dumps(data).encode()
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    return app


if __name__ == "__main__":
    print("TaskTrack on http://localhost:8000")
    make_server("127.0.0.1", 8000, create_app(db_path="tasks.db")).serve_forever()
