import os
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import bcrypt
import jwt
from dotenv import load_dotenv

# ----------------------------
# Config
# ----------------------------
load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))

db = SQLAlchemy(app)

# ----------------------------
# Model
# ----------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)

    def to_safe_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "created_at": self.created_at.isoformat(),
        }

# ----------------------------
# Utilities
# ----------------------------
def hash_password(plain: str) -> bytes:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt())

def verify_password(plain: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed)
    except Exception:
        return False

def make_jwt(user_id: int, token_type: str = "access") -> str:
    now = datetime.now(timezone.utc)
    exp = now + (timedelta(minutes=ACCESS_TOKEN_MINUTES) if token_type == "access"
                 else timedelta(days=REFRESH_TOKEN_DAYS))
    payload = {
        "sub": user_id,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def require_auth(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth.split(" ", 1)[1].strip()
        payload = decode_jwt(token)
        if not payload or payload.get("type") != "access":
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user_id = payload["sub"]
        return fn(*args, **kwargs)
    return wrapper

# ----------------------------
# Routes
# ----------------------------
@app.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not (name and email and password):
        return jsonify({"error": "name, email, password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email already registered"}), 409

    user = User(name=name, email=email, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "registered", "user": user.to_safe_dict()}), 201

@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not verify_password(password, user.password_hash):
        return jsonify({"error": "invalid credentials"}), 401

    access = make_jwt(user.id, "access")
    refresh = make_jwt(user.id, "refresh")
    return jsonify({"access_token": access, "refresh_token": refresh, "user": user.to_safe_dict()})

@app.post("/auth/refresh")
def refresh():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token") or ""
    payload = decode_jwt(refresh_token)
    if not payload or payload.get("type") != "refresh":
        return jsonify({"error": "invalid or expired refresh token"}), 401
    new_access = make_jwt(payload["sub"], "access")
    return jsonify({"access_token": new_access})

@app.get("/me")
@require_auth
def me():
    user = db.session.get(User, request.user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"user": user.to_safe_dict()})

# ----------------------------
# CLI helper to init DB table
# ----------------------------
@app.cli.command("init-db")
def init_db():
    """Create tables if they don't exist."""
    db.create_all()
    print("✅ Database tables created.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
