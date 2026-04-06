#!/usr/bin/env bash
# Local / cron entrypoint: correlation rules + Fusion workflows + NGSIEM lookups + NGSIEM parsers.
# CrowdStrike does not provide a supported "export everything to disk" backup product for
# these artifacts as of this writing; this script runs the community automation that calls
# the Falcon APIs instead. See README.md for API permissions and responsibility.
#
# Usage: ./run-crowdstrike-backup.sh
# Cron example: 0 2 * * * /path/to/crowdstrike-backup/run-crowdstrike-backup.sh >> /path/to/crowdstrike-backup/logs/cron.log 2>&1
#
# Requires: chmod +x run-crowdstrike-backup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p backups logs

if [[ -d ".venv" ]]; then
  VENV_DIR=".venv"
elif [[ -d "venv" ]]; then
  VENV_DIR="venv"
else
  VENV_DIR="venv"
  echo "Creating virtual environment at ${VENV_DIR}..."
  python3 -m venv "$VENV_DIR"
fi

PY="${VENV_DIR}/bin/python"
PIP="${VENV_DIR}/bin/pip"
if [[ ! -x "$PY" ]] || [[ ! -x "$PIP" ]]; then
  echo "error: expected Python and pip under ${VENV_DIR}/bin" >&2
  exit 1
fi

if [[ -f "requirements.txt" ]]; then
  echo "Syncing Python dependencies..."
  "$PIP" install --quiet --upgrade pip
  "$PIP" install --quiet -r requirements.txt
else
  echo "warning: requirements.txt missing; skipping pip install" >&2
fi

# Full backup without the heavy Fusion activities/triggers/executions catalog JSON
exec "$PY" cli.py all --no-fusion-catalog
