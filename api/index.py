from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2.pool
import psycopg2
import bcrypt
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app, origins=["https://www.figma.com", "https://figma.com"], supports_credentials=True)

# ─── Config ───
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
DATABASE_URL = os.environ.get("DATABASE_URL")

# ─── Database Pool ───
conn_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=10,
    dsn=DATABASE_URL,
    sslmode="require"
)

def get_db():
    return conn_pool.getconn()

def release_db(conn):
    conn_pool.putconn(conn)

# ─── Auto-create tables on startup ───
def init_db():
    """Create tables if they don't exist."""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                figma_file_key VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        cur.close()
        print("[init_db] Tables created successfully (or already exist).")
    except Exception as e:
        print(f"[init_db] Error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            release_db(conn)

# Run init on startup
init_db()

# ─── Auth Middleware ───
def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        try:
            payload = jwt.decode(token.split(" ")[1], JWT_SECRET, algorithms=["HS256"])
            request.user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# ─── Routes ───

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "User exists"}), 409

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
            (email, hashed)
        )
        user_id = cur.fetchone()[0]
        conn.commit()

        token = jwt.encode(
            {"user_id": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)},
            JWT_SECRET,
            algorithm="HS256"
        )
        return jsonify({"token": token, "user_id": user_id})
    finally:
        release_db(conn)

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        if not row or not bcrypt.checkpw(password.encode(), row[1].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        token = jwt.encode(
            {"user_id": row[0], "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)},
            JWT_SECRET,
            algorithm="HS256"
        )
        return jsonify({"token": token, "user_id": row[0]})
    finally:
        release_db(conn)

@app.route("/api/tasks", methods=["GET"])
@token_required
def get_tasks():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, title, description, figma_file_key, created_at FROM tasks WHERE user_id = %s ORDER BY created_at DESC",
            (request.user_id,)
        )
        rows = cur.fetchall()
        return jsonify([{
            "id": r[0], "title": r[1], "description": r[2],
            "figma_file_key": r[3], "created_at": r[4].isoformat()
        } for r in rows])
    finally:
        release_db(conn)

@app.route("/api/tasks", methods=["POST"])
@token_required
def create_task():
    data = request.get_json()
    title = data.get("title")
    description = data.get("description", "")
    figma_file_key = data.get("figma_file_key")

    if not title:
        return jsonify({"error": "Title required"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tasks (user_id, title, description, figma_file_key) VALUES (%s, %s, %s, %s) RETURNING id, created_at",
            (request.user_id, title, description, figma_file_key)
        )
        row = cur.fetchone()
        conn.commit()
        return jsonify({
            "id": row[0], "title": title, "description": description,
            "figma_file_key": figma_file_key, "created_at": row[1].isoformat()
        }), 201
    finally:
        release_db(conn)

@app.route("/api/tasks/<int:task_id>", methods=["DELETE"])
@token_required
def delete_task(task_id):
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM tasks WHERE id = %s AND user_id = %s", (task_id, request.user_id))
        conn.commit()
        return jsonify({"success": True})
    finally:
        release_db(conn)

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# Vercel serverless handler
def handler(request, **kwargs):
    return app(request.environ, lambda s, h: None)
