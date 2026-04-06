#!/usr/bin/env python3
"""
Lightweight API fingerprints to skip full backups when nothing material changed.

Fingerprints are stored in ``<output_dir>/.backup_fingerprints.json``. Compare runs a
cheap preflight (list IDs / counts, workflow metadata, NGSIEM list names) before
downloading full rule bodies, exports, or lookup bytes.

Limits
------
- **Correlation rules**: Hash of the ordered set of rule IDs from ``query_rules`` only.
  In-place edits that do not add/remove/rename IDs are **not** detected; run without
  ``--skip-if-unchanged`` periodically for a full refresh.
- **Workflows**: Hash includes ``id``, ``last_modified_timestamp``, and ``version`` from
  ``search_definitions`` so definition edits are usually detected.
- **NGSIEM lookups**: Hash of sorted file names per domain (list API only; no file bodies).
- **NGSIEM parsers**: Hash of sorted parser IDs for the configured ``parser_type`` scope (default
  ``custom`` only; see ``NGSIEM_PARSER_TYPES`` / ``--ngsiem-parser-types``).
- **Fusion catalog (light)**: When catalog is enabled, stores reported totals from the
  first page meta of activities / triggers / executions searches (best-effort).

Author: Ibrahim Al-Shinnawi
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from falconpy import CorrelationRules, NGSIEM, Workflows

from tools.ngsiem_lookups_backup import SEARCH_DOMAINS, _list_all_lookups
from tools.ngsiem_parsers_backup import _list_all_parsers, resolve_parser_type_passes

logger = logging.getLogger(__name__)

STATE_FILENAME = ".backup_fingerprints.json"
FORMAT_VERSION = 1


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _paginate_correlation_rule_ids(
    falcon: CorrelationRules, backup_filter: str, limit: int = 500
) -> List[str]:
    ids: List[str] = []
    offset = 0
    while True:
        response = falcon.query_rules(filter=backup_filter, limit=limit, offset=offset)
        if response.get("status_code") != 200:
            raise RuntimeError(
                f"query_rules failed: {response.get('body', {}).get('errors', response)}"
            )
        batch = response.get("body", {}).get("resources") or []
        for x in batch:
            ids.append(str(x) if not isinstance(x, dict) else str(x.get("id", x)))
        if len(batch) < limit:
            break
        offset += len(batch)
    return ids


def fingerprint_correlation_rules(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    backup_filter: str,
) -> Dict[str, Any]:
    falcon = CorrelationRules(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    ids = _paginate_correlation_rule_ids(falcon, backup_filter)
    ids_sorted = sorted(ids)
    payload = "\n".join(ids_sorted)
    return {
        "count": len(ids_sorted),
        "ids_sha256": _sha256_text(payload),
    }


def _workflow_lines(resources: List[dict]) -> str:
    rows = []
    for w in sorted(resources, key=lambda x: str(x.get("id", ""))):
        wid = str(w.get("id", ""))
        lm = str(w.get("last_modified_timestamp", ""))
        ver = str(w.get("version", ""))
        rows.append(f"{wid}\t{lm}\t{ver}")
    return "\n".join(rows)


def fingerprint_workflows(
    client_id: str,
    client_secret: str,
    cloud_region: str,
) -> Dict[str, Any]:
    falcon = Workflows(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    all_resources: List[dict] = []
    limit = 500
    offset = 0
    total: Optional[int] = None
    while True:
        response = falcon.search_definitions(limit=limit, offset=offset)
        if response.get("status_code") != 200:
            raise RuntimeError(
                f"search_definitions failed: {response.get('body', {}).get('errors', response)}"
            )
        body = response.get("body") or {}
        batch = body.get("resources") or []
        meta = body.get("meta") or {}
        for item in batch:
            if isinstance(item, dict):
                all_resources.append(item)
        pag = meta.get("pagination") or {}
        if total is None and pag.get("total") is not None:
            total = int(pag["total"])
        if not batch:
            break
        offset += len(batch)
        if total is not None and offset >= total:
            break
        if len(batch) < limit:
            break
    text = _workflow_lines(all_resources)
    return {
        "count": len(all_resources),
        "reported_total": total,
        "meta_sha256": _sha256_text(text),
    }


def fingerprint_ngsiem_lookups(
    client_id: str,
    client_secret: str,
    cloud_region: str,
) -> Dict[str, Any]:
    ngsiem = NGSIEM(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    domains: Dict[str, Any] = {}
    for domain in SEARCH_DOMAINS:
        try:
            names, _metas = _list_all_lookups(ngsiem, domain)
            names_sorted = sorted(names)
            domains[domain] = {
                "count": len(names_sorted),
                "names_sha256": _sha256_text("\n".join(names_sorted)),
            }
        except Exception as e:
            logger.warning("fingerprint lookups domain=%s: %s", domain, e)
            domains[domain] = {"error": str(e)}
    return {"domains": domains}


def fingerprint_ngsiem_parsers(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    repository: str = "parsers-repository",
    parser_types_cli: Optional[str] = None,
) -> Dict[str, Any]:
    passes = resolve_parser_type_passes(parser_types_cli)
    passes_for_blob = [None if p is None else p for p in passes]
    ngsiem = NGSIEM(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    try:
        entries, _metas = _list_all_parsers(
            ngsiem, repository, parser_type_passes=passes
        )
        ids_sorted = sorted(str(pid) for pid, _n in entries)
        return {
            "count": len(ids_sorted),
            "repository": repository,
            "parser_type_passes": passes_for_blob,
            "ids_sha256": _sha256_text("\n".join(ids_sorted)),
        }
    except Exception as e:
        return {
            "error": str(e),
            "repository": repository,
            "parser_type_passes": passes_for_blob,
        }


def fingerprint_fusion_catalog_light(
    client_id: str,
    client_secret: str,
    cloud_region: str,
) -> Dict[str, Any]:
    """Single-page meta totals only (triggers may be capped in API)."""
    falcon = Workflows(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    out: Dict[str, Any] = {}

    def _total(fetch, **kw):
        r = fetch(**kw)
        if r.get("status_code") != 200:
            return None
        pag = (r.get("body") or {}).get("meta", {}).get("pagination") or {}
        return pag.get("total")

    try:
        out["activities_reported_total"] = _total(
            falcon.search_activities, limit=1, offset=0
        )
    except Exception as e:
        out["activities_error"] = str(e)
    try:
        out["activities_content_reported_total"] = _total(
            falcon.search_activities_content, limit=1, offset=0
        )
    except Exception as e:
        out["activities_content_error"] = str(e)
    try:
        r = falcon.search_triggers()
        if r.get("status_code") == 200:
            body = r.get("body") or {}
            res = body.get("resources") or []
            pag = (body.get("meta") or {}).get("pagination") or {}
            out["triggers_fetched"] = len(res)
            out["triggers_reported_total"] = pag.get("total")
    except Exception as e:
        out["triggers_error"] = str(e)
    try:
        out["executions_reported_total"] = _total(
            falcon.search_executions, limit=1, offset=0
        )
    except Exception as e:
        out["executions_error"] = str(e)
    return out


def collect_fingerprint_bundle(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    backup_filter: Optional[str],
    *,
    include_rules: bool = True,
    include_workflows: bool = True,
    include_ngsiem_lookups: bool = True,
    include_ngsiem_parsers: bool = True,
    include_fusion_light: bool = False,
    ngsiem_parser_types: Optional[str] = None,
) -> Dict[str, Any]:
    bundle: Dict[str, Any] = {
        "v": FORMAT_VERSION,
        "cloud_region": cloud_region,
    }
    if backup_filter is not None:
        bundle["backup_filter"] = backup_filter
    if include_rules:
        bundle["correlation_rules"] = fingerprint_correlation_rules(
            client_id, client_secret, cloud_region, backup_filter
        )
    if include_workflows:
        bundle["workflows"] = fingerprint_workflows(
            client_id, client_secret, cloud_region
        )
    if include_ngsiem_lookups:
        bundle["ngsiem_lookups"] = fingerprint_ngsiem_lookups(
            client_id, client_secret, cloud_region
        )
    if include_ngsiem_parsers:
        bundle["ngsiem_parsers"] = fingerprint_ngsiem_parsers(
            client_id, client_secret, cloud_region, parser_types_cli=ngsiem_parser_types
        )
    if include_fusion_light:
        bundle["fusion_catalog_light"] = fingerprint_fusion_catalog_light(
            client_id, client_secret, cloud_region
        )
    return bundle


def state_path(output_dir: str) -> Path:
    return Path(output_dir) / STATE_FILENAME


def load_saved_fingerprints(output_dir: str) -> Optional[Dict[str, Any]]:
    p = state_path(output_dir)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def save_fingerprints(output_dir: str, bundle: Dict[str, Any]) -> None:
    p = state_path(output_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def merge_saved_with_bundle(
    existing: Optional[Dict[str, Any]], bundle: Dict[str, Any]
) -> Dict[str, Any]:
    """Overlay keys from bundle onto existing (for partial command updates)."""
    out = dict(existing) if existing else {}
    for k, v in bundle.items():
        if k == "v":
            continue
        out[k] = v
    out["v"] = FORMAT_VERSION
    return out


def bundle_matches_saved(saved: Optional[Dict[str, Any]], current: Dict[str, Any]) -> bool:
    if not saved:
        return False
    if saved.get("v") != FORMAT_VERSION or current.get("v") != FORMAT_VERSION:
        return False
    if saved.get("cloud_region") != current.get("cloud_region"):
        return False
    if "backup_filter" in current:
        if saved.get("backup_filter") != current.get("backup_filter"):
            return False
    for key in current:
        if key in ("v", "cloud_region", "backup_filter"):
            continue
        if saved.get(key) != current.get(key):
            return False
    return True


def env_skip_if_unchanged() -> bool:
    import os

    return os.getenv("BACKUP_SKIP_IF_UNCHANGED", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
