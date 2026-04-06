.PHONY: help install install-dev test clean backup backup-all setup status validate audit lint-security

# Resolve interpreter: project venv first so tests import falconpy/rich.
PY ?= $(shell if test -x .venv/bin/python; then echo .venv/bin/python; elif test -x venv/bin/python; then echo venv/bin/python; else echo python3; fi)

help:
	@echo "CrowdStrike backup (API-driven)"
	@echo ""
	@echo "  install     pip install -r requirements.txt"
	@echo "  install-dev pip install -r requirements-dev.txt (audit + bandit)"
	@echo "  test        py_compile + compileall + tests/ (uses $(PY))"
	@echo "  audit       pip-audit -r requirements.txt (needs install-dev)"
	@echo "  lint-security  bandit on cli.py tools utils (needs install-dev)"
	@echo "  clean       remove __pycache__, *.pyc"
	@echo "  backup      python cli.py backup"
	@echo "  backup-all  python cli.py all --no-fusion-catalog"
	@echo "  setup       python cli.py setup"
	@echo "  status      python cli.py status"
	@echo "  validate    python cli.py validate-searches"
	@echo ""
	@echo "Shell entrypoint (venv + deps + backup-all): ./run-crowdstrike-backup.sh"

install:
	$(PY) -m pip install -r requirements.txt

install-dev:
	$(PY) -m pip install -r requirements-dev.txt

audit:
	$(PY) -m pip_audit -r requirements.txt

lint-security:
	$(PY) -m bandit -r cli.py tools utils -q -ll

test:
	$(PY) -m py_compile cli.py
ifneq ($(wildcard config.py),)
	$(PY) -m py_compile config.py
endif
	$(PY) -m compileall -q -f tools utils
	$(PY) -m unittest discover -s tests -p 'test_*.py' -q

clean:
	rm -rf __pycache__ */__pycache__ */*/__pycache__ .pytest_cache
	find . -path ./.venv -prune -o -path ./venv -prune -o -name '*.pyc' -delete

backup:
	$(PY) cli.py backup

backup-all:
	$(PY) cli.py all --no-fusion-catalog

setup:
	$(PY) cli.py setup

status:
	$(PY) cli.py status

validate:
	$(PY) cli.py validate-searches
