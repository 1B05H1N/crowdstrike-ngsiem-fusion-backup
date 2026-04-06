#!/usr/bin/env python3
"""
NGSIEM **lookup file** backup via FalconPy ``NGSIEM`` (``list_lookup_files`` /
``get_lookup_file``).

This is **not** the same as NGSIEM **parser entity** backup (``ListParsers`` /
``GetParser``); custom parsers you wrote are saved by ``tools/ngsiem_parsers_backup.py``
under ``ngsiem_parsers/``. The ``parsers-repository`` **domain** here still refers to
**lookup-style files** exposed in that content view, not the parser definitions API.

For each ``search_domain`` in ``SEARCH_DOMAINS`` (``all``, ``falcon``, ``third-party``,
``dashboards``, ``parsers-repository``), paginate ``list_lookup_files``, then
``get_lookup_file`` per listed name. Responses may be ``bytes`` or HTTP-style dicts.

Filesystem writes (under ``Path(output_dir) / <date_stamp> / ngsiem_lookups/``)
-------------------------------------------------------------------------------
- ``<sanitized_domain>/`` -- one subdirectory per domain; lookup files named with
  ``sanitize_filename`` of the API filename.
- ``_ngsiem_lookups_summary.json`` -- per-domain list/download counts, failures, and
  pagination metadata from list calls.

``date_stamp`` defaults to today ``%Y-%m-%d`` or is passed in from the CLI so NGSIEM
output lands in the same folder as workflow backups from the same ``all`` run.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from falconpy import NGSIEM
from rich.console import Console

from utils.validators import sanitize_filename

console = Console()
logger = logging.getLogger(__name__)

SEARCH_DOMAINS = (
    "all",
    "falcon",
    "third-party",
    "dashboards",
    "parsers-repository",
)


def _json_default(o: Any) -> str:
    return str(o)


def _list_all_lookups(
    ngsiem: NGSIEM, search_domain: str, limit: int = 500
) -> Tuple[List[str], List[dict]]:
    offset = 0
    names: List[str] = []
    page_metas: List[dict] = []
    reported_total: Optional[int] = None

    while True:
        response = ngsiem.list_lookup_files(
            limit=str(min(limit, 9999)),
            offset=str(offset),
            search_domain=search_domain,
        )
        if response.get("status_code") != 200:
            raise RuntimeError(
                f"ListLookupFiles failed ({search_domain}): "
                f"{response.get('body', {}).get('errors', response)}"
            )
        body = response.get("body") or {}
        batch = body.get("resources") or []
        meta = body.get("meta") or {}
        page_metas.append(meta)

        for item in batch:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
            elif isinstance(item, dict) and item.get("filename"):
                names.append(str(item["filename"]))

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

    return names, page_metas


def backup_ngsiem_lookups(
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-2",
    output_dir: str = "backups",
    date_stamp: Optional[str] = None,
) -> Dict[str, Any]:
    stamp = date_stamp or datetime.now().strftime("%Y-%m-%d")
    root = Path(output_dir) / stamp / "ngsiem_lookups"
    root.mkdir(parents=True, exist_ok=True)

    logger.info(
        "NGSIEM lookups backup started: cloud=%s output_dir=%s date=%s path=%s",
        cloud_region,
        output_dir,
        stamp,
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
        "directory": str(root),
        "domains": {},
    }

    for domain in SEARCH_DOMAINS:
        domain_dir = root / sanitize_filename(domain)
        domain_dir.mkdir(parents=True, exist_ok=True)
        domain_summary: Dict[str, Any] = {
            "search_domain": domain,
            "listed": 0,
            "downloaded": 0,
            "failed": [],
            "list_pages": [],
        }
        try:
            filenames, metas = _list_all_lookups(ngsiem, domain)
            domain_summary["list_pages"] = metas
            domain_summary["listed"] = len(filenames)
            console.print(
                f"[cyan]NGSIEM lookups: domain={domain!r} listed {len(filenames)} file(s)[/cyan]"
            )

            for raw_name in filenames:
                safe = sanitize_filename(raw_name)
                if not safe:
                    safe = "unnamed_lookup"
                target = domain_dir / safe
                try:
                    blob = ngsiem.get_lookup_file(
                        filename=raw_name, search_domain=domain
                    )
                    if isinstance(blob, (bytes, bytearray)):
                        target.write_bytes(bytes(blob))
                    elif isinstance(blob, dict) and blob.get("status_code") == 200:
                        body = blob.get("body")
                        if isinstance(body, (bytes, bytearray)):
                            target.write_bytes(bytes(body))
                        elif isinstance(body, str):
                            target.write_text(body, encoding="utf-8")
                        else:
                            target.write_text(
                                json.dumps(body, indent=2, default=_json_default),
                                encoding="utf-8",
                            )
                    else:
                        raise RuntimeError(f"unexpected response type {type(blob)}")
                    domain_summary["downloaded"] += 1
                except Exception as ex:
                    logger.exception("lookup download %s/%s", domain, raw_name)
                    domain_summary["failed"].append({"filename": raw_name, "error": str(ex)})

        except Exception as e:
            logger.exception("lookup list domain %s", domain)
            domain_summary["error"] = str(e)
            console.print(f"[yellow]NGSIEM lookups list failed for domain={domain!r}: {e}[/yellow]")

        summary["domains"][domain] = domain_summary

    idx = root / "_ngsiem_lookups_summary.json"
    idx.write_text(json.dumps(summary, indent=2, default=_json_default), encoding="utf-8")
    console.print(f"[green]NGSIEM lookups summary -> {idx.name}[/green]")
    listed_total = sum(int(d.get("listed") or 0) for d in summary["domains"].values())
    downloaded_total = sum(int(d.get("downloaded") or 0) for d in summary["domains"].values())
    logger.info(
        "NGSIEM lookups backup finished: listed=%s downloaded=%s path=%s",
        listed_total,
        downloaded_total,
        root,
    )
    return summary
