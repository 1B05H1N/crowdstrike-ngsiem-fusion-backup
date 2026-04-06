# CrowdStrike NGSIEM / Fusion backup (unofficial)

**Export NGSIEM correlation rules, Falcon Fusion SOAR workflow definitions, NGSIEM lookups, and custom parser definitions to dated folders on disk** using the public Falcon APIs (via [FalconPy](https://github.com/CrowdStrike/falconpy)). Optional zip + manifest publish to a mounted share.

**Repository:** [github.com/1B05H1N/crowdstrike-ngsiem-fusion-backup](https://github.com/1B05H1N/crowdstrike-ngsiem-fusion-backup). This tree ships **without** a `.git` directory (no prior history). To publish: create the empty repo on GitHub, then locally run `git init -b main`, `git add -A`, `git commit -m "Initial commit"`, `git remote add origin …`, and `git push -u origin main`.

This is the **grown-up successor** to the author's earlier public project [**crowdstrike-ngsiem-correlation-rules-backup**](https://github.com/1B05H1N/crowdstrike-ngsiem-correlation-rules-backup) (correlation rules only). [Background and lineage](#background-and-lineage) explains scope and why this tool exists alongside CrowdStrike's own product improvements.

### No affiliation, endorsement, or implied use

This project is **not** affiliated with, endorsed by, sponsored by, or supported by **CrowdStrike, Inc.** or **CrowdStrike affiliates**. It is **independent community software**.

Nothing here should be read as CrowdStrike (or any CrowdStrike affiliate) **using**, **recommending**, **approving**, or **being responsible for** this tool. The author **does not** represent or imply that CrowdStrike, any CrowdStrike affiliate, **any employer or organization the author works with or is affiliated with**, or any other third party **uses**, **vets**, or **stands behind** this repository. Any use is **your** decision alone.

CrowdStrike product names are used **descriptively** (to explain what APIs the code calls), not to suggest official status.

---

## Contents

- [Background and lineage](#background-and-lineage)
- [Quick start](#quick-start)
- [Validating API searches](#validating-api-searches)
- [Optional listening](#optional-listening)
- [No affiliation, endorsement, or implied use](#no-affiliation-endorsement-or-implied-use)
- [What you get](#what-you-get)
- [Author and expectations](#author-and-expectations)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Where data is written](#where-data-is-written)
- [API permissions](#api-permissions)
- [Security and hardening](#security-and-hardening)
- [Commands](#commands)
- [Configuration](#configuration)
- [Docker](#docker)
- [Publishing / Git](#publishing--git)
- [License](#license)

## Background and lineage

- **Earlier project:** [1B05H1N/crowdstrike-ngsiem-correlation-rules-backup](https://github.com/1B05H1N/crowdstrike-ngsiem-correlation-rules-backup) on GitHub (correlation rules only). This repo is the **expanded** line: workflows, optional Fusion catalog reads, NGSIEM lookups and parsers, optional zip publish, fingerprints, and `validate-searches`.
- **CrowdStrike and "official" backup / audit:** The Falcon platform continues to improve. The author does not speak for CrowdStrike. In practice, a single first-party **backup**, **bulk export**, or **audit** workflow that matched this **offline / DR / change-review** need across **rules, workflows, lookups, and parsers** was still worth automating via API here. Use vendor features when they fit; use this when you need **files on disk under your controls**.
- **Not a product critique:** Nothing here implies CrowdStrike should have shipped a specific feature by a specific date. It is independent tooling for operators who want exports they can hash, diff, and archive themselves.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp env.example .env
# Edit .env: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_CLOUDREGION

python cli.py status
./run-crowdstrike-backup.sh
```

`run-crowdstrike-backup.sh` creates or reuses `.venv` or `venv`, installs `requirements.txt`, then runs `cli.py all --no-fusion-catalog`. First time: `chmod +x run-crowdstrike-backup.sh`.

For a dry credential check without writing backups: `python cli.py backup --dry-run`.

## Validating API searches

Before a long `all` or `workflows` run, `python cli.py validate-searches` calls the same **list / search** endpoints the backup uses, with **small limits** (usually one row), so you can confirm:

- Your **Correlation Rules** FQL (`BACKUP_FILTER` / `--backup-filter`) is accepted by `query_rules`.
- **Workflows** `search_definitions` and optional Fusion `search_*` calls succeed.
- **NGSIEM** `list_lookup_files` works for each lookup domain and `list_parsers` works for your `NGSIEM_PARSER_TYPES` passes.

Exit code **0** only if every **enabled** probe returns HTTP 200. Use `--no-fusion-catalog`, `--no-ngsiem-lookups`, or `--no-ngsiem-parsers` to match flags you use on `workflows` / `all`. Use `-v` to print full error text for failed rows.

## Optional listening

You may run backups in **monastic silence** or with a playlist that makes your SIEM admin question their career path. This project **does not** ship audio, require a soundtrack, or judge your taste.

It is **completely up to you** if you want something in the spirit of **"Back That Thang Up"** (1999) by rapper **Juvenile** featuring **Mannie Fresh** and **Lil Wayne**, produced by **Mannie Fresh**, released **June 11, 1999**, as the second single from Juvenile's **1998** album **400 Degreez** (use the **radio edit** if your environment prefers its bleeps to its themes). No study has shown this improves `query_rules` latency. Use only sources and licenses that apply to you.

## What you get

| Area | Mechanism (high level) |
|------|-------------------------|
| Correlation rules | Falcon **Correlation Rules** API: list rule IDs (with optional FQL filter), fetch each rule JSON |
| Workflow definitions | Falcon **Workflows** API: paginated definitions, per-workflow export (YAML/JSON) |
| Fusion catalog (optional) | Additional Workflows API reads (activities, triggers, executions) into `fusion_catalog/` |
| NGSIEM lookups | **NGSIEM** API: list and download lookup files by domain (often **large, sensitive** tables; see [Security and hardening](#security-and-hardening)) |
| NGSIEM parsers | **NGSIEM** API: `ListParsers` / `GetParser` for `parsers-repository` |

CrowdStrike may ship or change native export, backup, or content-management features at any time. **Treat this tool as a community complement, not a statement about what CrowdStrike officially offers.** For authoritative capability and licensing questions, use [CrowdStrike documentation](https://www.crowdstrike.com/resources/?type=documentation) and your support or account contacts.

## Author and expectations

**Author: Ibrahim Al-Shinnawi** ([@1B05H1N](https://github.com/1B05H1N) on GitHub). I built this because I needed reliable **offline copies** of rules, workflows, and related NGSIEM artifacts for operational and DR-style workflows. I am sharing it in case it helps others facing the same kind of gap.

**Please set expectations:**

- **Unofficial:** This is personal / community automation. It is not a CrowdStrike product; CrowdStrike and its affiliates do not endorse or support it. It is **not** presented as used or blessed by CrowdStrike, any affiliate, or any organization the author is affiliated with (see [above](#no-affiliation-endorsement-or-implied-use)).
- **No maintainer support:** I am **not** able to offer help running, debugging, or recovering from use of this repo (email, DMs, “quick questions,” incident assistance, or custom API guidance beyond what is documented here). Fork it, adapt it, and rely on your own team or CrowdStrike for product support.
- **Your risk:** You are responsible for credentials, API scopes, storage, compliance, and any impact on your tenant (rate limits, misconfiguration, data handling). **Read `LICENSE` and `NOTICE.md`:** software is **as-is**, with **no warranty** and **limitation of liability** to the extent the law allows. If you are not comfortable with that, please do not use it.

Thanks for reading this section; it keeps everyone aligned.

## How it works

1. **Configuration:** `cli.py` calls `load_dotenv()` so a local `.env` can populate the environment before Click parses options. Flags can still override env vars (for example `FALCON_CLIENT_ID` on `--client-id`).

2. **Credential check:** `utils.validators.validate_api_credentials` builds a short-lived `falconpy.CorrelationRules` client for the **same cloud** you pass as `FALCON_CLOUDREGION` / `--cloud-region` and calls **`get_rules_combined(limit=1)`** so validation matches the tenant you will query.

3. **Backups:** Steps in `tools/` use FalconPy service classes (`CorrelationRules`, `Workflows`, `NGSIEM`) with OAuth2 client id and secret. Outputs go under `<output_dir>/<YYYY-MM-DD>/` (date from `datetime.now().strftime("%Y-%m-%d")` at the start of each major step, so one run usually shares one date folder).

4. **`cli.py all`:** Runs correlation rules backup, then workflow backup. **Only if the workflow step succeeds**, it runs optional Fusion catalog, NGSIEM lookups, and NGSIEM parsers unless you pass `--no-fusion-catalog`, `--no-ngsiem-lookups`, or `--no-ngsiem-parsers`.

   **Lookups vs parsers:** Lookups use list/download APIs (including the `parsers-repository` *domain* for lookup files). Parser **entities** are backed up separately via `ListParsers` / `GetParser` into `ngsiem_parsers/`. By default the parser step requests **`parser_type=custom`** (parsers you authored). Use `NGSIEM_PARSER_TYPES` or `--ngsiem-parser-types` for `ootb`, `all`, or `custom,ootb`. FalconPy **1.6.1+** is required so `parser_type` is forwarded on `ListParsers`. The list response uses **PascalCase** fields **`ID`** and **`Name`** per the API; the backup normalizes those when collecting ids.

5. **Remote publish:** If `BACKUP_REMOTE_DIR` or `OUTPUT_SHARE` points to a directory **and** `BACKUP_REMOTE_PUBLISH` is `1` / `true` / `yes`, `tools.backup_remote_publish.publish_compressed_backup` hashes files under the chosen date folder, diffs against the last manifest, writes a zip and audit JSON, and updates `previous_file_manifest.json`. If the mount vars are set but `BACKUP_REMOTE_PUBLISH` is off, nothing is copied (avoids accidental export). The tool performs **no HTTP upload**; it only writes to paths you control. **If you used `OUTPUT_SHARE` without this flag before, add `BACKUP_REMOTE_PUBLISH=1` to keep copying zips.** See [Remote layout](#remote-layout-optional).

6. **Skip if unchanged:** With `--skip-if-unchanged` or `BACKUP_SKIP_IF_UNCHANGED=1`, `tools.backup_fingerprints.py` compares lightweight API fingerprints to `<output_dir>/.backup_fingerprints.json` from the last **successful** run that used this flag (scope depends on command). If nothing relevant changed, the CLI exits without a full download or remote publish. **Correlation rules** are fingerprinted by **rule ID set only** (in-place edits without ID changes may still look “unchanged”; run a full backup periodically). **Workflows** use definition metadata (`last_modified_timestamp`, `version`). Lookups and parsers use list-based fingerprints; optional Fusion catalog uses light API totals when the catalog step is enabled.

7. **Logging:** `utils.logger.setup_logger` configures the **root** logger (stdout plus optional file) so `tools.*` INFO/ERROR lines and the CLI logger share the same output. Default file path: `logs/correlation_rules_backup_YYYYMMDD_HHMMSS.log` (`get_log_filename`). Each line includes the logger module name. Rich still drives interactive progress in the terminal.

8. **Privacy in the CLI:** `status` and `backup --dry-run` avoid printing raw non-default `BACKUP_FILTER` FQL (only `*` is shown literally). In `status`, client id is masked like the secret when set.

## Repository layout

| Path | Role |
|------|------|
| `cli.py` | Click entry: `backup`, `workflows`, `all`, `validate-searches`, `status`, `setup`; optional `publish_compressed_backup` |
| `requirements.txt` | Pinned Python dependencies |
| `requirements-dev.txt` | Optional: `pip-audit`, `bandit` for `make audit` / `make lint-security` |
| `.github/dependabot.yml` | Weekly pip dependency update PRs (GitHub) |
| `env.example` | Template for `.env` (copy to `.env`) |
| `run-crowdstrike-backup.sh` | Venv + `pip install` + `cli.py all --no-fusion-catalog` |
| `Makefile` | `make test`, `make backup`, optional `make audit` / `make lint-security` |
| `tests/test_smoke.py` | Offline unit tests |
| `docker-compose.yml`, `Dockerfile` | Container runs |
| `LICENSE` | Custom non-commercial terms, warranty disclaimer, liability cap |
| `NOTICE.md` | Short plain-language disclaimer |
| `tools/correlation_rules_backup.py` | Rules list + fetch + `_backup_summary.json` |
| `tools/workflows_backup.py` | Workflow definitions export + summaries |
| `tools/fusion_workflows_catalog_backup.py` | Fusion catalog JSON |
| `tools/ngsiem_lookups_backup.py` | Lookup list + download |
| `tools/ngsiem_parsers_backup.py` | Parser list + `GetParser` JSON |
| `tools/backup_remote_publish.py` | Zip + manifest diff + audits |
| `tools/backup_fingerprints.py` | Fingerprints for `--skip-if-unchanged` |
| `tools/validate_backup_searches.py` | Live probes for backup list/search APIs |
| `utils/validators.py` | Credentials, paths, filename sanitize |
| `utils/logger.py` | Logging helpers |

## Where data is written

### Local (when a backup step runs)

Paths are relative to the working directory unless `--output-dir` is absolute.

| Location | Contents |
|----------|----------|
| `<output_dir>/<YYYY-MM-DD>/*.json` | One JSON per correlation rule |
| `<output_dir>/<YYYY-MM-DD>/_backup_summary.json` | Rule backup metadata |
| `<output_dir>/<YYYY-MM-DD>/workflows/` | Definitions snapshot, exports, per-workflow files |
| `<output_dir>/<YYYY-MM-DD>/fusion_catalog/` | Catalog JSON + summary |
| `<output_dir>/<YYYY-MM-DD>/ngsiem_lookups/` | Lookups by domain + summary |
| `<output_dir>/<YYYY-MM-DD>/ngsiem_parsers/` | Parser JSON + summary |
| `logs/correlation_rules_backup_*.log` | Log file for the run |
| `<output_dir>/.backup_fingerprints.json` | Fingerprint state when using skip-if-unchanged |

Default `<output_dir>` is `backups`.

### Remote layout (optional)

| Path | Purpose |
|------|---------|
| `<BACKUP_REMOTE_SUBDIR>/archives/crowdstrike_backup_<UTC>.zip` | Zip of the date folder + audit readme |
| `<BACKUP_REMOTE_SUBDIR>/audits/audit_<UTC>.json` | Audit metadata |
| `<BACKUP_REMOTE_SUBDIR>/previous_file_manifest.json` | Path → SHA-256 for diffing the next publish |

`BACKUP_REMOTE_SUBDIR` defaults to `crowdstrike-backup`. Pruning uses `BACKUP_REMOTE_MAX_ARCHIVES`.

## API permissions

Use a **dedicated** API client with **read-only** scopes that match what you run:

| You run | FalconPy area | Purpose |
|---------|---------------|---------|
| `backup` / rules in `all` | Correlation Rules | Query and read rules |
| `workflows` / `all` (definitions) | Workflows | Search and export definitions |
| `all` without `--no-fusion-catalog` | Workflows | Catalog-style reads |
| NGSIEM lookups | NGSIEM | List and download lookups |
| NGSIEM parsers | NGSIEM | List and get parsers |

Scope **names** in the console vary. If you see **403**, add the narrowest read scope for that call. Protect secrets and backup directories like production data.

## Security and hardening

- **Privileged and sensitive data:** Everything this tool writes (rules, workflow exports, Fusion catalog JSON, **NGSIEM lookup files**, parser JSON, logs, zips) is a **copy of your tenant’s configuration and related content**. It may be **privileged**, **confidential**, include **personal or organizational identifiers**, or fall under **regulatory** rules in your environment. The author **cannot** classify your data for you. Treat outputs like **production secrets**: least privilege, encryption at rest where required, and no sharing unless policy allows. **Lookups** deserve extra scrutiny; they are commonly used for enrichment and can hold **dense tabular data** you would not want exposed.
- **Network egress:** Outbound calls are **only to CrowdStrike** (OAuth and Falcon APIs via FalconPy). There is **no** telemetry, analytics, or third-party URL in this repo. Optional zip publish is **writes to a local or mounted directory** (`BACKUP_REMOTE_DIR` / `OUTPUT_SHARE`), not an HTTP upload.
- **Tenant data and fingerprints:** `backups/`, `logs/`, `.backup_fingerprints.json`, and published zips can contain **sensitive Falcon tenant content**. They are listed in `.gitignore`; do not commit them or paste them into tickets, chats, or public repos. Optional remote publish copies **only** to your configured mount when `BACKUP_REMOTE_PUBLISH` is enabled. Before `git push`, run `git status` / `git ls-files` and confirm `.env`, backup folders, and logs are not tracked.
- **Dependencies:** `requirements.txt` uses **pinned** versions for reproducible installs. [Dependabot](.github/dependabot.yml) can open weekly PRs when this repo is on GitHub. Optional: `pip install -r requirements-dev.txt` then `make audit` (CVE check) and `make lint-security` (Bandit).
- **Secrets:** Prefer a `.env` file or secret manager over `--client-secret` on the command line (process lists can expose argv). Restrict who can read `backups/`, `logs/`, and remote publish mounts.
- **`--output-dir`:** Use a **dedicated** writable directory (for example `backups/`). The tool creates a short-lived `.test_write` file there to verify writability before a run.
- **Docker:** The image runs as a **non-root** `app` user (see `Dockerfile`).

## Commands

| Command | Typical outputs under `<output_dir>/<date>/` |
|---------|-----------------------------------------------|
| `cli.py backup` | Rule JSON + `_backup_summary.json` (+ publish if configured) |
| `cli.py workflows` | `workflows/` (+ optional fusion / lookups / parsers) + publish |
| `cli.py all` | Rules + workflows + optional extras + publish |
| `cli.py status` | None (env check only) |
| `cli.py validate-searches` | None (API probe table to stdout; exit 1 if any check fails) |
| `cli.py setup` | Writes `.env` interactively |

`--no-fusion-catalog`, `--no-ngsiem-lookups`, `--no-ngsiem-parsers` apply to `workflows`, `all`, and `validate-searches`. `--skip-if-unchanged` (or `BACKUP_SKIP_IF_UNCHANGED`) applies to `backup`, `workflows`, and `all`; a skipped run does not publish remotely.

## Configuration

See `env.example`. Common variables:

- `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_CLOUDREGION`
- `BACKUP_FILTER` (FQL for rules on `backup` / `all`)
- `BACKUP_REMOTE_PUBLISH` (enable zip copy to share), `BACKUP_REMOTE_DIR` or `OUTPUT_SHARE`, `BACKUP_REMOTE_SUBDIR`, `BACKUP_REMOTE_MAX_ARCHIVES`
- `FUSION_EXECUTIONS_MAX` (optional cap for execution pagination in the catalog step)
- `BACKUP_SKIP_IF_UNCHANGED` (`1`, `true`, or `yes` enables skip-if-unchanged behavior)

## Docker

```bash
docker compose --profile backup run --rm backup
```

Mounts `./backups`, `./correlation_rules_backups`, `./logs`, and `./.env` (read-only where compose sets `:ro`) as defined in `docker-compose.yml`. Profiles: `backup`, `setup`, `status`.

## Publishing / Git

- Do not commit `.env`, `backups/`, `logs/`, or virtualenvs (see `.gitignore`).
- This tree is the **public** export: it omits optional `config.py` / `setup.py` that may exist in a private development copy; runtime behavior is the same.
- When you fork or republish, keep the **no affiliation / no endorsement** language visible (see [No affiliation, endorsement, or implied use](#no-affiliation-endorsement-or-implied-use)). Attribution: Ibrahim Al-Shinnawi ([@1B05H1N](https://github.com/1B05H1N)). Legal terms: `LICENSE` and `NOTICE.md`.

## License

Custom **non-commercial** license: attribution required, no commercial use without permission, no warranties, limitation of liability. See `LICENSE` and `NOTICE.md`.
