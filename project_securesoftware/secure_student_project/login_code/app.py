"""
Secure login demonstration for the Online Secure Student Information System.
Focus: input validation, password hashing, rate limiting, secure sessions,
and SQL injection prevention through parameterized queries.
"""

import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "students.db"

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,30}$")
MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 10 * 60
failed_attempts = {}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # keep True in production with HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def valid_username(username: str) -> bool:
    return bool(username and USERNAME_RE.fullmatch(username))


def is_locked(client_key: str) -> bool:
    record = failed_attempts.get(client_key)
    if not record:
        return False
    attempts, last_time = record
    if attempts >= MAX_FAILED_ATTEMPTS and time.time() - last_time < LOCK_SECONDS:
        return True
    if time.time() - last_time >= LOCK_SECONDS:
        failed_attempts.pop(client_key, None)
    return False


def record_failed_attempt(client_key: str):
    attempts, _ = failed_attempts.get(client_key, (0, 0))
    failed_attempts[client_key] = (attempts + 1, time.time())


def reset_failed_attempts(client_key: str):
    failed_attempts.pop(client_key, None)


def authenticate_user(username: str, password: str):
    """Return user info if credentials are correct; otherwise return None."""
    if not valid_username(username) or not password:
        return None

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user and check_password_hash(user["password_hash"], password):
        return {"id": user["id"], "username": user["username"], "role": user["role"]}
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    client_key = request.remote_addr or "unknown-client"

    if request.method == "POST":
        if is_locked(client_key):
            error = "Too many failed attempts. Please try again later."
            return render_template("login.html", error=error)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(username, password)
        if user:
            reset_failed_attempts(client_key)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        record_failed_attempt(client_key)
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return f"Welcome {session['username']}! Role: {session['role']}"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def init_demo_database():
    """Creates a small demo database with one student and one instructor."""
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student', 'instructor', 'admin'))
            )
            """
        )
        conn.execute("DELETE FROM users")
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("student1", generate_password_hash("Student@123"), "student"),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("instructor1", generate_password_hash("Instructor@123"), "instructor"),
        )
        conn.commit()


if __name__ == "__main__":
    init_demo_database()
    app.run(debug=False)
