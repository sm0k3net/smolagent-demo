#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .[dev]
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env (edit it to add real keys)"
fi
echo "Setup complete. Run: source .venv/bin/activate && uvicorn app.main:app --reload"
