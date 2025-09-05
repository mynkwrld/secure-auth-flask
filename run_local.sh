#!/usr/bin/env bash
# Small helper to create venv, install, init db and run
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# if no .env exists, copy example and auto-generate SECRET_KEY
[ -f .env ] || (cp .env.example .env && python - <<PY
from pathlib import Path, isfile
import os, secrets
p=Path('.env')
s = open('.env').read()
if 'SECRET_KEY' in s and 'replace-with' in s:
    s = s.replace('replace-with-a-strong-random-string', secrets.token_hex(32))
open('.env','w').write(s)
print('Created .env with SECRET_KEY')
PY
)
# init DB and run
export FLASK_APP=app.py
flask --app app.py init-db
flask --app app.py run
