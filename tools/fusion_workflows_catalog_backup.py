#!/usr/bin/env python3
"""
Fusion / Workflows **catalog** JSON (not per-definition YAML export).

Supplements ``workflows_backup`` (which uses ``search_definitions`` + ``export_definition``).
This module calls other Workflows API search endpoints to dump bulk catalog data.

Endpoints (via FalconPy ``Workflows``)
--------------------------------------
- ``search_activities`` / ``search_activities_content`` -- fully paginated (500/page).
- ``search_triggers`` -- **may return a capped page** (e.g. 100 rows); JSON includes a
  note when ``reported_total`` exceeds fetched rows.
- ``search_executions`` -- paginated but **stopped** after ``FUSION_EXECUTIONS_MAX``
  records (default ``10000``, env var) to bound runtime and disk.

Human-input entities have no combined list API; ``_human_inputs_note.json`` documents
using ``get_human_input`` when you already have an id.

Filesystem writes (under ``Path(output_dir) / <date_stamp> / fusion_catalog/``)
------------------------------------------------------------------------------
- ``_catalog_workflow_activities.json``
- ``_catalog_workflow_activities_content.json``
- ``_catalog_workflow_triggers.json``
- ``_catalog_workflow_executions.json``
- ``_human_inputs_note.json``
- ``_fusion_catalog_summary.json`` -- index of what succeeded/failed per section.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from falconpy import Workflows
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


def _json_default(o: Any) -> str:
    return str(o)


def _paginate_workflow_query(
    fetch: Callable[..., dict],
    limit: int = 500,
    max_records: Optional[int] = None,
) -> Tuple[List[Any], List[dict], Optional[int]]:
    offset = 0
    all_resources: List[Any] = []
    page_metas: List[dict] = []
    reported_total: Optional[int] = None

    while True:
        response = fetch(limit=limit, offset=offset)
        if response.get("status_code") != 200:
            raise RuntimeError(
                f"Workflow API error: {response.get('body', {}).get('errors', response)}"
            )
        body = response.get("body") or {}
        batch = body.get("resources") or []
        meta = body.get("meta") or {}
        page_metas.append(meta)
        all_resources.extend(batch)

        pag = meta.get("pagination") or {}
        if reported_total is None and pag.get("total") is not None:
            reported_total = int(pag["total"])

        if max_records is not None and len(all_resources) >= max_records:
            all_resources = all_resources[:max_records]
            break

        if not batch:
            break
        offset += len(batch)
        if reported_total is not None and offset >= reported_total:
            break
        if len(batch) < limit:
            break

    return all_resources, page_metas, reported_total


def backup_fusion_workflows_catalog(
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-2",
    output_dir: str = "backups",
    date_stamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Write catalog JSON under backups/<date>/fusion_catalog/.
    """
    stamp = date_stamp or datetime.now().strftime("%Y-%m-%d")
    base = Path(output_dir) / stamp / "fusion_catalog"
    base.mkdir(parents=True, exist_ok=True)

    logger.info(
        "Fusion catalog backup started: cloud=%s output_dir=%s date=%s path=%s",
        cloud_region,
        output_dir,
        stamp,
        base,
    )

    falcon = Workflows(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )

    executions_max = int(os.environ.get("FUSION_EXECUTIONS_MAX", "10000"))

    summary: Dict[str, Any] = {
        "backup_timestamp": datetime.now().isoformat(),
        "cloud_region": cloud_region,
        "directory": str(base),
    }

    # Activities
    try:
        res, metas, total = _paginate_workflow_query(
            lambda limit, offset: falcon.search_activities(limit=limit, offset=offset),
            limit=500,
        )
        payload = {
            "backup_timestamp": datetime.now().isoformat(),
            "reported_total": total,
            "fetched_count": len(res),
            "search_pages": metas,
            "resources": res,
        }
        path = base / "_catalog_workflow_activities.json"
        path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
        summary["activities"] = {"file": path.name, "fetched": len(res), "reported_total": total}
        console.print(f"[green]Fusion catalog: activities -> {path.name} ({len(res)} items)[/green]")
    except Exception as e:
        logger.exception("activities catalog failed")
        summary["activities"] = {"error": str(e)}
        console.print(f"[yellow]Fusion catalog activities failed: {e}[/yellow]")

    # Activity content (large; same pagination)
    try:
        res, metas, total = _paginate_workflow_query(
            lambda limit, offset: falcon.search_activities_content(limit=limit, offset=offset),
            limit=500,
        )
        payload = {
            "backup_timestamp": datetime.now().isoformat(),
            "reported_total": total,
            "fetched_count": len(res),
            "search_pages": metas,
            "resources": res,
        }
        path = base / "_catalog_workflow_activities_content.json"
        path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
        summary["activities_content"] = {
            "file": path.name,
            "fetched": len(res),
            "reported_total": total,
        }
        console.print(
            f"[green]Fusion catalog: activities_content -> {path.name} ({len(res)} items)[/green]"
        )
    except Exception as e:
        logger.exception("activities_content catalog failed")
        summary["activities_content"] = {"error": str(e)}
        console.print(f"[yellow]Fusion catalog activities_content failed: {e}[/yellow]")

    # Triggers (API often returns max 100 rows per call; offset may be ignored)
    try:
        response = falcon.search_triggers()
        if response.get("status_code") != 200:
            raise RuntimeError(response.get("body", {}).get("errors", response))
        body = response.get("body") or {}
        res = body.get("resources") or []
        meta = body.get("meta") or {}
        pag = meta.get("pagination") or {}
        total = pag.get("total")
        truncated = total is not None and len(res) < int(total)
        payload = {
            "backup_timestamp": datetime.now().isoformat(),
            "reported_total": total,
            "fetched_count": len(res),
            "meta": meta,
            "resources": res,
            "note": (
                "Trigger list may be capped per request (e.g. 100 rows). "
                "If reported_total > fetched_count, use Falcon UI or support for a full export."
                if truncated
                else None
            ),
        }
        path = base / "_catalog_workflow_triggers.json"
        path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
        summary["triggers"] = {
            "file": path.name,
            "fetched": len(res),
            "reported_total": total,
            "possibly_truncated": truncated,
        }
        console.print(
            f"[green]Fusion catalog: triggers -> {path.name} ({len(res)}"
            f"{' / ' + str(total) + ' reported' if total is not None else ''})[/green]"
        )
    except Exception as e:
        logger.exception("triggers catalog failed")
        summary["triggers"] = {"error": str(e)}
        console.print(f"[yellow]Fusion catalog triggers failed: {e}[/yellow]")

    # Executions (capped)
    try:
        res, metas, total = _paginate_workflow_query(
            lambda limit, offset: falcon.search_executions(limit=limit, offset=offset),
            limit=500,
            max_records=executions_max,
        )
        payload = {
            "backup_timestamp": datetime.now().isoformat(),
            "reported_total": total,
            "fetched_count": len(res),
            "cap_applied": executions_max,
            "search_pages": metas,
            "resources": res,
        }
        path = base / "_catalog_workflow_executions.json"
        path.write_text(json.dumps(payload, indent=2, default=_json_default), encoding="utf-8")
        summary["executions"] = {
            "file": path.name,
            "fetched": len(res),
            "reported_total": total,
            "max_records_env": "FUSION_EXECUTIONS_MAX",
        }
        console.print(
            f"[green]Fusion catalog: executions -> {path.name} ({len(res)} items, cap {executions_max})[/green]"
        )
    except Exception as e:
        logger.exception("executions catalog failed")
        summary["executions"] = {"error": str(e)}
        console.print(f"[yellow]Fusion catalog executions failed: {e}[/yellow]")

    note_path = base / "_human_inputs_note.json"
    note_path.write_text(
        json.dumps(
            {
                "api": "WorkflowGetHumanInputV1",
                "note": (
                    "There is no combined list API for pending human inputs. "
                    "Fetch by id via get_human_input(ids=...) when you have execution or alert context."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    summary["human_inputs"] = {"file": note_path.name}

    idx = base / "_fusion_catalog_summary.json"
    idx.write_text(json.dumps(summary, indent=2, default=_json_default), encoding="utf-8")
    logger.info("Fusion catalog backup finished: path=%s sections=%s", base, list(summary.keys()))
    return summary
