#!/usr/bin/env python3
"""
NGSIEM **parser definitions** backup (FalconPy ``NGSIEM.list_parsers`` + ``get_parser``).

This is separate from ``ngsiem_lookups_backup`` (lookup files). Parser **entities** for
NGSIEM content live under repository ``parsers-repository``. The ListParsers API supports
``parser_type=custom`` (your authored parsers) vs ``ootb`` (out-of-the-box). **By default
this tool backs up only ``custom``** so you get the log parsers you wrote for sources,
not the full OOTB catalog.

Filesystem writes (under ``Path(output_dir) / <date_stamp> / ngsiem_parsers/``)
------------------------------------------------------------------------------
- ``<sanitized_name>_<parser_id>.json`` -- full parser document from ``GetParser``.
- ``_ngsiem_parsers_summary.json`` -- list metadata, counts, failures, parser types used.

Requires ``crowdstrike-falconpy`` recent enough that ListParsers accepts ``parser_type``
(1.6.1+). Override scope with ``NGSIEM_PARSER_TYPES`` or ``--ngsiem-parser-types``.
List rows may use PascalCase ``ID`` / ``Name``; those are recognized alongside lowercase keys.

Author: Ibrahim Al-Shinnawi
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from falconpy import NGSIEM
from rich.console import Console

from utils.validators import sanitize_filename

console = Console()
logger = logging.getLogger(__name__)

DEFAULT_REPOSITORY = "parsers-repository"
# Sentinel: one tuple element None means call ListParsers without parser_type (all types).
ParserTypePasses = Tuple[Optional[str], ...]


def _parse_parser_types_str(raw: str) -> ParserTypePasses:
    key = raw.strip().lower()
    if key == "all":
        return (None,)
    parts = tuple(p.strip().lower() for p in raw.split(",") if p.strip())
    allowed = {"custom", "ootb"}
    bad = set(parts) - allowed
    if bad:
        raise ValueError(
            f"Invalid parser type(s) {bad!r}; use 'all', 'custom', 'ootb', or comma-separated "
            f"custom,ootb"
        )
    return parts if parts else ("custom",)


def resolve_parser_type_passes(cli_value: Optional[str]) -> ParserTypePasses:
    """
    Decide which ListParsers ``parser_type`` passes to run.

    Precedence: non-empty CLI string, else env ``NGSIEM_PARSER_TYPES``, else ``(\"custom\",)``.
    """
    if cli_value is not None and str(cli_value).strip():
        return _parse_parser_types_str(str(cli_value))
    env_raw = os.environ.get("NGSIEM_PARSER_TYPES", "").strip()
    if env_raw:
        return _parse_parser_types_str(env_raw)
    return ("custom",)


def _json_default(o: Any) -> str:
    return str(o)


def _entries_from_list_batch(batch: List[Any]) -> List[Tuple[str, Optional[str]]]:
    """Return (parser_id, name_or_none) for each list item."""
    out: List[Tuple[str, Optional[str]]] = []
    for item in batch:
        if isinstance(item, str):
            out.append((item, None))
            continue
        if not isinstance(item, dict):
            continue
        pid = (
            item.get("id")
            or item.get("ID")
            or item.get("parser_id")
            or item.get("parserId")
            or item.get("uuid")
        )
        if not pid:
            continue
        name = (
            item.get("name")
            or item.get("Name")
            or item.get("displayName")
            or item.get("title")
        )
        out.append((str(pid), str(name) if name is not None else None))
    return out


def _list_all_parsers(
    ngsiem: NGSIEM,
    repository: str,
    limit: int = 500,
    *,
    parser_type_passes: ParserTypePasses = ("custom",),
) -> Tuple[List[Tuple[str, Optional[str]]], List[dict]]:
    """Paginate ListParsers; merge multiple ``parser_type`` passes, dedupe by parser id."""
    merged: Dict[str, Optional[str]] = {}
    page_metas: List[dict] = []

    for pt in parser_type_passes:
        extra: Dict[str, str] = {}
        if pt is not None:
            extra["parser_type"] = pt
        offset = 0
        reported_total: Optional[int] = None

        while True:
            response = ngsiem.list_parsers(
                limit=str(min(limit, 9999)),
                offset=str(offset),
                repository=repository,
                **extra,
            )
            if response.get("status_code") != 200:
                raise RuntimeError(
                    f"ListParsers failed ({repository!r}, parser_type={pt!r}): "
                    f"{response.get('body', {}).get('errors', response)}"
                )
            body = response.get("body") or {}
            batch = body.get("resources") or []
            meta = body.get("meta") or {}
            page_metas.append({"parser_type": pt, **meta})

            for pid, pname in _entries_from_list_batch(batch):
                merged.setdefault(pid, pname)

            pag = meta.get("pagination") or {}
            if reported_total is None and pag.get("total") is not None:
                reported_total = int(pag["total"])

            if not batch:
                break
            offset += len(batch)
            if reported_total is not None and offset >= reported_total:
                break
            if len(batch) < limit:
                break

    entries = sorted(merged.items(), key=lambda x: x[0])
    return [(k, v) for k, v in entries], page_metas


def _write_get_parser_response(response: Any, target: Path) -> None:
    if not isinstance(response, dict):
        raise RuntimeError(f"unexpected get_parser type {type(response)}")
    if response.get("status_code") != 200:
        raise RuntimeError(
            response.get("body", {}).get("errors", response.get("status_code"))
        )
    body = response.get("body") or {}
    resources = body.get("resources")
    if isinstance(resources, list) and len(resources) == 1:
        to_save: Any = resources[0]
    elif isinstance(resources, list) and len(resources) > 1:
        to_save = resources
    else:
        to_save = body
    target.write_text(
        json.dumps(to_save, indent=2, default=_json_default),
        encoding="utf-8",
    )


def _passes_for_summary(passes: ParserTypePasses) -> List[Union[str, None]]:
    return [None if p is None else p for p in passes]


def backup_ngsiem_parsers(
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-2",
    output_dir: str = "backups",
    date_stamp: Optional[str] = None,
    repository: str = DEFAULT_REPOSITORY,
    parser_type_passes: Optional[ParserTypePasses] = None,
    parser_types_cli: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Backup parser JSON via GetParser for each id from ListParsers.

    ``parser_type_passes`` if set is used as-is; otherwise ``parser_types_cli`` and env
    ``NGSIEM_PARSER_TYPES`` are resolved via ``resolve_parser_type_passes``.
    """
    stamp = date_stamp or datetime.now().strftime("%Y-%m-%d")
    root = Path(output_dir) / stamp / "ngsiem_parsers"
    root.mkdir(parents=True, exist_ok=True)

    passes: ParserTypePasses
    if parser_type_passes is not None:
        passes = parser_type_passes
    else:
        passes = resolve_parser_type_passes(parser_types_cli)

    logger.info(
        "NGSIEM parsers backup started: cloud=%s repository=%s passes=%s path=%s",
        cloud_region,
        repository,
        _passes_for_summary(passes),
        root,
    )

    ngsiem = NGSIEM(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )

    summary: Dict[str, Any] = {
        "backup_timestamp": datetime.now().isoformat(),
        "cloud_region": cloud_region,
        "repository": repository,
        "parser_type_passes": _passes_for_summary(passes),
        "directory": str(root),
        "listed": 0,
        "downloaded": 0,
        "failed": [],
        "list_pages": [],
    }

    try:
        entries, metas = _list_all_parsers(
            ngsiem, repository, parser_type_passes=passes
        )
        summary["list_pages"] = metas
        summary["listed"] = len(entries)
        console.print(
            f"[cyan]NGSIEM parsers: repository={repository!r} "
            f"parser_type_passes={_passes_for_summary(passes)!r} "
            f"listed {len(entries)} parser(s)[/cyan]"
        )

        for parser_id, pname in entries:
            base_name = sanitize_filename(pname) if pname else "parser"
            if not base_name:
                base_name = "parser"
            fname = f"{base_name}_{parser_id}.json"
            if len(fname) > 220:
                fname = f"parser_{parser_id}.json"
            target = root / fname
            try:
                resp = ngsiem.get_parser(ids=parser_id, repository=repository)
                _write_get_parser_response(resp, target)
                summary["downloaded"] += 1
            except Exception as ex:
                logger.exception("get_parser %s", parser_id)
                summary["failed"].append({"id": parser_id, "name": pname, "error": str(ex)})

    except Exception as e:
        logger.exception("NGSIEM parsers list failed")
        summary["error"] = str(e)
        console.print(f"[yellow]NGSIEM parsers list failed: {e}[/yellow]")

    idx = root / "_ngsiem_parsers_summary.json"
    idx.write_text(json.dumps(summary, indent=2, default=_json_default), encoding="utf-8")
    console.print(f"[green]NGSIEM parsers summary -> {idx.name}[/green]")
    logger.info(
        "NGSIEM parsers backup finished: listed=%s downloaded=%s failed=%s path=%s",
        summary.get("listed", 0),
        summary.get("downloaded", 0),
        len(summary.get("failed") or []),
        root,
    )
    return summary
