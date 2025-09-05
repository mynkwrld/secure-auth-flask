# === Secure Authentication System: one-shot setup & run ===

# 1. Clone repo (or make empty folder if already created manually)
git clone https://github.com/<your-username>/secure-auth-flask.git || mkdir secure-auth-flask
cd secure-auth-flask

# 2. Create virtual environment + activate
python -m venv .venv
source .venv/bin/activate

# 3. Create required files (requirements.txt, .env, app.py, README.md)
cat > requirements.txt <<'REQ'
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
PyJWT==2.8.0
python-dotenv==1.0.1
bcrypt==4.1.3
REQ

cat > .env <<'ENV'
FLASK_ENV=development
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
# Leave DATABASE_URL empty for SQLite (default)
# DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/secure_auth_db
ACCESS_TOKEN_MINUTES=15
REFRESH_TOKEN_DAYS=7
ENV

cat > app.py <<'APP'
<-- paste the full app.py content I gave earlier here -->
APP

cat > README.md <<'MD'
<-- paste the final README.md content I gave earlier here -->
MD

# 4. Install deps
pip install -r requirements.txt

# 5. Initialize DB
flask --app app.py init-db

# 6. Run the server (available at http://127.0.0.1:5000)
flask --app app.py run
