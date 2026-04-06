#!/usr/bin/env python3
"""
Compress one dated local backup directory and publish to an optional **mounted share**.

There is **no HTTP or cloud upload** in this module: it only writes under a local or
mounted filesystem path you configure.

When ``BACKUP_REMOTE_DIR`` or ``OUTPUT_SHARE`` is unset, ``publish_compressed_backup``
returns ``None`` and does nothing.

When a remote root **is** set, publishing still does **nothing** unless you also set
``BACKUP_REMOTE_PUBLISH`` to ``1``, ``true``, or ``yes``. That opt-in avoids copying
tenant backup data to a share by mistake (for example from a stray ``OUTPUT_SHARE`` in
the environment).

Inputs
------
- ``output_dir``: same root the CLI uses (e.g. ``backups``).
- ``date_stamp``: must be ``YYYY-MM-DD``; the publisher reads only
  ``Path(output_dir) / date_stamp /`` (resolved, symlink-safe when hashing/zipping).

Algorithm
---------
1. Walk that directory, SHA-256 every file, build ``relative_path -> hex digest``.
2. Load ``previous_file_manifest.json`` from the remote product folder (if present);
   compute added / removed / modified paths vs the new manifest.
3. Build an audit dict (counts, truncated path lists, ``run_context`` from caller).
4. Write ``AUDIT_README.md`` and ``audit_<run_id>.json`` **into** the zip; add every
   backup file with archive names equal to relative paths (no ``..``).
5. Atomically replace ``crowdstrike_backup_<UTC>.zip`` under ``archives/``, write the
   sidecar ``audits/audit_<UTC>.json``, then atomically replace
   ``previous_file_manifest.json`` with the new full manifest.
6. Delete oldest zips in ``archives/`` beyond ``BACKUP_REMOTE_MAX_ARCHIVES``.

Remote layout (under ``Path(BACKUP_REMOTE_DIR) / BACKUP_REMOTE_SUBDIR``)
------------------------------------------------------------------------
- ``archives/crowdstrike_backup_<YYYYMMDD_HHMMSS>.zip``
- ``audits/audit_<YYYYMMDD_HHMMSS>.json``
- ``previous_file_manifest.json`` (state for the next diff)

Env
---
- ``BACKUP_REMOTE_DIR`` or ``OUTPUT_SHARE`` -- mount point (required to publish)
- ``BACKUP_REMOTE_PUBLISH`` -- must be ``1``, ``true``, or ``yes`` to write zips when a
  remote root is set (default: off)
- ``BACKUP_REMOTE_SUBDIR`` (default ``crowdstrike-backup``) -- folder under the mount;
  must not contain ``..``
- ``BACKUP_REMOTE_MAX_ARCHIVES`` (default ``30``) -- retain newest N zips
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

console = Console()

MANIFEST_STATE_NAME = "previous_file_manifest.json"


def _validate_date_stamp(ds: str) -> bool:
    if not isinstance(ds, str) or len(ds) != 10:
        return False
    try:
        datetime.strptime(ds, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _rel_path_safe(rel: str) -> bool:
    if not rel or rel.startswith(("/", "\\")):
        return False
    return ".." not in Path(rel).as_posix().split("/")


def _safe_remote_subdir() -> str:
    raw = os.environ.get("BACKUP_REMOTE_SUBDIR", "crowdstrike-backup")
    norm = raw.strip().replace("\\", "/").strip("/")
    if not norm:
        return "crowdstrike-backup"
    if any(p == ".." for p in norm.split("/")):
        console.print(
            "[yellow]BACKUP_REMOTE_SUBDIR must not contain '..'; using crowdstrike-backup[/yellow]"
        )
        return "crowdstrike-backup"
    return norm


def _remote_root() -> Optional[str]:
    path = os.environ.get("BACKUP_REMOTE_DIR") or os.environ.get("OUTPUT_SHARE")
    if not path or not str(path).strip():
        return None
    return str(path).strip()


def _remote_publish_explicitly_enabled() -> bool:
    v = os.environ.get("BACKUP_REMOTE_PUBLISH", "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _sanitize_run_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Drop or redact context keys that could carry secrets if misused by a caller."""
    sensitive_substrings = (
        "secret",
        "password",
        "token",
        "authorization",
        "api_key",
        "apikey",
        "client_secret",
        "credential",
    )
    sensitive_key_exact = frozenset(
        {
            "client_id",
            "falcon_client_id",
            "id_token",
            "refresh_token",
        }
    )
    out: Dict[str, Any] = {}
    for k, v in ctx.items():
        if not isinstance(k, str):
            continue
        kl = k.lower()
        if kl in sensitive_key_exact or any(s in kl for s in sensitive_substrings):
            out[k] = "[redacted]"
            continue
        if isinstance(v, dict):
            out[k] = _sanitize_run_context(v)
        elif isinstance(v, list):
            out[k] = [
                _sanitize_run_context(x) if isinstance(x, dict) else x for x in v
            ]
        else:
            out[k] = v
    return out


def _max_archives() -> int:
    try:
        return max(1, int(os.environ.get("BACKUP_REMOTE_MAX_ARCHIVES", "30")))
    except ValueError:
        return 30


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_manifest(backup_root: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not backup_root.is_dir():
        return out
    try:
        root_resolved = backup_root.resolve()
    except OSError:
        return out
    for p in sorted(backup_root.rglob("*")):
        if not p.is_file():
            continue
        try:
            p.resolve().relative_to(root_resolved)
        except (ValueError, OSError):
            continue
        rel = p.relative_to(backup_root).as_posix()
        if not _rel_path_safe(rel):
            continue
        out[rel] = _file_sha256(p)
    return out


def _diff_manifests(
    old_m: Dict[str, str], new_m: Dict[str, str]
) -> Tuple[List[str], List[str], List[Dict[str, str]]]:
    old_keys = set(old_m)
    new_keys = set(new_m)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    modified: List[Dict[str, str]] = []
    for k in sorted(old_keys & new_keys):
        if old_m[k] != new_m[k]:
            modified.append(
                {
                    "path": k,
                    "previous_sha256": old_m[k],
                    "current_sha256": new_m[k],
                }
            )
    return added, removed, modified


def _trim_archives(archives_dir: Path, keep: int) -> None:
    zips = sorted(
        [p for p in archives_dir.glob("crowdstrike_backup_*.zip") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in zips[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def publish_compressed_backup(
    output_dir: str,
    date_stamp: str,
    context: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Zip ``Path(output_dir) / date_stamp /`` and publish under the configured remote root.

    Returns ``None`` if no remote env var is set. Otherwise returns a dict with
    ``zip_path``, ``audit_path``, ``manifest_state``, ``run_id``, ``file_count``,
    or a ``skipped`` dict with ``reason`` if the mount is missing, read-only, or
    ``date_stamp`` is invalid. See module docstring for remote directory layout.
    """
    remote = _remote_root()
    if not remote:
        return None

    if not _remote_publish_explicitly_enabled():
        console.print(
            "[dim]Remote backup: OUTPUT_SHARE / BACKUP_REMOTE_DIR is set but "
            "BACKUP_REMOTE_PUBLISH is not enabled; not copying zips.[/dim]"
        )
        return {
            "skipped": True,
            "reason": "remote_publish_disabled",
            "path": str(Path(remote).expanduser()),
        }

    if not _validate_date_stamp(date_stamp):
        console.print(
            f"[yellow]Remote backup skipped: invalid date_stamp (expected YYYY-MM-DD): {date_stamp!r}[/yellow]"
        )
        return {"skipped": True, "reason": "invalid_date_stamp", "path": date_stamp}

    remote_path = Path(remote).expanduser()
    if not remote_path.is_dir():
        console.print(
            f"[yellow]Remote backup skipped: not a directory or not mounted: {remote_path}[/yellow]"
        )
        return {"skipped": True, "reason": "remote_path_not_available", "path": str(remote_path)}

    if not os.access(remote_path, os.W_OK):
        console.print(f"[yellow]Remote backup skipped: not writable: {remote_path}[/yellow]")
        return {"skipped": True, "reason": "remote_path_not_writable", "path": str(remote_path)}

    local_root = (Path(output_dir) / date_stamp).resolve()
    if not local_root.is_dir():
        console.print(f"[yellow]Remote backup skipped: no local tree {local_root}[/yellow]")
        return {"skipped": True, "reason": "local_backup_missing", "path": str(local_root)}

    sub = _safe_remote_subdir()
    try:
        remote_resolved = remote_path.resolve()
        product = (remote_path / sub).resolve()
        product.relative_to(remote_resolved)
    except ValueError:
        console.print("[yellow]Remote backup skipped: product directory escapes the mount path[/yellow]")
        return {"skipped": True, "reason": "product_path_escape", "path": str(remote_path / sub)}
    except OSError as e:
        console.print(f"[yellow]Remote backup skipped: cannot resolve paths: {e}[/yellow]")
        return {"skipped": True, "reason": "path_resolution_error", "path": str(e)}

    archives = product / "archives"
    audits = product / "audits"
    state_path = product / MANIFEST_STATE_NAME
    archives.mkdir(parents=True, exist_ok=True)
    audits.mkdir(parents=True, exist_ok=True)

    new_manifest = _build_manifest(local_root)
    old_manifest: Dict[str, str] = {}
    if state_path.is_file():
        try:
            raw = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k, v in raw.items():
                    if isinstance(k, str) and isinstance(v, str) and _rel_path_safe(k):
                        old_manifest[k] = v
        except (json.JSONDecodeError, OSError):
            old_manifest = {}

    added, removed, modified = _diff_manifests(old_manifest, new_manifest)
    old_keys = set(old_manifest)
    new_keys = set(new_manifest)
    unchanged = len(old_keys & new_keys) - len(modified) if old_manifest else 0

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_name = f"crowdstrike_backup_{run_id}.zip"
    zip_path = archives / zip_name

    ctx = _sanitize_run_context(dict(context or {}))
    cap = 2000

    def _cap(lst: List[Any]) -> Tuple[List[Any], Optional[int]]:
        if len(lst) <= cap:
            return lst, None
        return lst[:cap], len(lst)

    added_store, added_total = _cap(added)
    removed_store, removed_total = _cap(removed)
    modified_store, modified_total = _cap(modified)

    audit: Dict[str, Any] = {
        "run_id": run_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "date_stamp": date_stamp,
        "local_source": str(local_root.resolve()),
        "remote_product_dir": str(product.resolve()),
        "zip_archive": str(zip_path.resolve()),
        "file_counts": {
            "total_in_backup": len(new_manifest),
            "added_vs_previous_run": len(added),
            "removed_vs_previous_run": len(removed),
            "modified_vs_previous_run": len(modified),
            "unchanged_vs_previous_run": max(0, unchanged),
        },
        "run_context": ctx,
        "changes": {
            "added_paths": added_store,
            "removed_paths": removed_store,
            "modified": modified_store,
        },
    }
    if added_total is not None:
        audit["changes"]["added_paths_total"] = added_total
        audit["changes"]["added_paths_truncated"] = True
    if removed_total is not None:
        audit["changes"]["removed_paths_total"] = removed_total
        audit["changes"]["removed_paths_truncated"] = True
    if modified_total is not None:
        audit["changes"]["modified_total"] = modified_total
        audit["changes"]["modified_truncated"] = True

    if not old_manifest:
        audit["note"] = (
            "No prior manifest on remote; all files treated as new for this diff. "
            "Next run will show true deltas."
        )

    audit_path = audits / f"audit_{run_id}.json"

    def _readme_scalar(val: Any) -> str:
        t = str(val).replace("`", "'").replace("\r", " ").replace("\n", " ")
        return t if len(t) <= 8000 else t[:8000] + "...(truncated)"

    readme_lines = [
        "# CrowdStrike backup bundle",
        "",
        f"- **Run ID:** `{run_id}`",
        f"- **Backup date folder:** `{date_stamp}`",
        f"- **UTC generated:** {audit['generated_at_utc']}",
        "",
        "## Contents",
        "",
        "This zip contains the full tree under the dated backup directory:",
        "- Correlation rules JSON and `_backup_summary.json`",
        "- `workflows/` (Fusion exports, snapshots, summaries)",
        "- `ngsiem_lookups/` when that step ran",
        "- `ngsiem_parsers/` when NGSIEM parser backup ran",
        "- `fusion_catalog/` when enabled",
        "",
        "## Change summary (vs previous published run)",
        "",
        f"- Files in this backup: **{len(new_manifest)}**",
        f"- Added paths: **{len(added)}**",
        f"- Removed paths: **{len(removed)}**",
        f"- Modified paths (content hash changed): **{len(modified)}**",
        f"- Unchanged paths: **{max(0, unchanged)}**",
        "",
        "Full machine-readable audit JSON is published beside this archive under",
        f"`{sub}/audits/{audit_path.name}` on the share.",
        "",
        "## Run context",
        "",
    ]
    for k, v in sorted(ctx.items()):
        readme_lines.append(f"- **{k}:** {_readme_scalar(v)}")
    readme_lines.append("")
    if modified[:50]:
        readme_lines.extend(["## Sample modified paths (up to 50)", ""])
        for m in modified[:50]:
            readme_lines.append(f"- `{_readme_scalar(m.get('path', ''))}`")
        readme_lines.append("")

    readme_text = "\n".join(readme_lines)
    audit_json = json.dumps(audit, indent=2, default=str)
    manifest_json = json.dumps(new_manifest, indent=2)
    root_lr = local_root.resolve()

    fd, tmp_zip = tempfile.mkstemp(suffix=".zip", dir=str(archives))
    os.close(fd)
    tmp_zip_path = Path(tmp_zip)
    try:
        with zipfile.ZipFile(tmp_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AUDIT_README.md", readme_text)
            zf.writestr(f"audit_{run_id}.json", audit_json)
            for rel, _h in sorted(new_manifest.items()):
                if not _rel_path_safe(rel):
                    continue
                src = (local_root / rel).resolve()
                try:
                    src.relative_to(root_lr)
                except ValueError:
                    continue
                zf.write(src, arcname=rel)
        os.replace(tmp_zip_path, zip_path)
    except Exception:
        tmp_zip_path.unlink(missing_ok=True)
        raise

    audit_path.write_text(audit_json, encoding="utf-8")

    fd_s, tmp_state = tempfile.mkstemp(suffix=".json", dir=str(product))
    os.close(fd_s)
    tmp_state_path = Path(tmp_state)
    try:
        tmp_state_path.write_text(manifest_json, encoding="utf-8")
        os.replace(tmp_state_path, state_path)
    except Exception:
        tmp_state_path.unlink(missing_ok=True)
        raise
    _trim_archives(archives, _max_archives())

    console.print(f"[green]Remote archive: {zip_path}[/green]")
    console.print(f"[dim]Audit: {audit_path}[/dim]")
    return {
        "zip_path": str(zip_path),
        "audit_path": str(audit_path),
        "manifest_state": str(state_path),
        "run_id": run_id,
        "file_count": len(new_manifest),
    }
