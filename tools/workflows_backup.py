#!/usr/bin/env python3
"""
Falcon Fusion SOAR workflow **definitions** backup (Falcon ``Workflows`` API).

Not the NGSIEM content API (``/ngsiem-content/...``). Uses paginated
``search_definitions`` (WorkflowDefinitionsCombined) and per-id ``export_definition``.

API flow
--------
1. Paginate ``search_definitions`` until all workflow resources are retrieved.
2. Persist a full snapshot JSON of that listing.
3. For each workflow, call ``export_definition``. FalconPy may return **bytes** (YAML);
   those are decoded to UTF-8 (replacement on errors) and saved as ``.yaml``. Dict/JSON
   bodies are written as ``.json`` or ``.txt`` depending on shape.
4. Each search payload is also saved as ``*.definition.json`` (enabled, version, graph).

Filesystem writes (under ``Path(output_dir) / <YYYY-MM-DD> / workflows/``)
--------------------------------------------------------------------------
- ``_definitions_api_snapshot.json`` -- full search result + pagination meta.
- ``_workflows_backup_summary.json`` -- per-workflow outcomes and metadata.
- ``<safe_name>_<id>.yaml`` (or ``.json`` / ``.txt``) -- export body.
- ``<safe_name>_<id>.definition.json`` -- raw definition from search (when available).

Author: Ibrahim Al-Shinnawi
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from falconpy import Workflows
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from utils.validators import sanitize_filename

console = Console()
logger = logging.getLogger(__name__)


def _export_errors(export_response) -> str:
    if isinstance(export_response, dict):
        body = export_response.get("body")
        if isinstance(body, dict) and body.get("errors"):
            return str(body.get("errors"))
        return str(export_response.get("status_code", export_response))
    return type(export_response).__name__


def _json_default(o: Any) -> str:
    return str(o)


def _meta_from_workflow(wf: object) -> Dict[str, Any]:
    if not isinstance(wf, dict):
        return {}
    keys = (
        "enabled",
        "version",
        "last_modified_timestamp",
        "has_validation_errors",
        "description",
    )
    return {k: wf.get(k) for k in keys if k in wf}


def _write_workflow_definition_json(
    backup_path: Path, safe_name: str, workflow_id: str, workflow: object
) -> Optional[str]:
    if not isinstance(workflow, dict):
        return None
    name = f"{safe_name}_{workflow_id}.definition.json"
    with open(backup_path / name, "w", encoding="utf-8") as jf:
        json.dump(workflow, jf, indent=2, default=_json_default)
    return name


def _fetch_all_workflow_definitions(falcon: Workflows) -> Tuple[List[dict], List[dict], Optional[int]]:
    """Paginate WorkflowDefinitionsCombined until all resources are retrieved."""
    all_resources: List[dict] = []
    page_metas: List[dict] = []
    limit = 500
    offset = 0
    total: Optional[int] = None

    while True:
        response = falcon.search_definitions(limit=limit, offset=offset)
        if response.get("status_code") != 200:
            raise Exception(
                f"Failed to query workflows: {response.get('body', {}).get('errors', [])}"
            )
        body = response.get("body") or {}
        batch = body.get("resources") or []
        meta = body.get("meta") or {}
        page_metas.append(meta)
        all_resources.extend(batch)

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

    return all_resources, page_metas, total


def _write_export_body(
    body,
    backup_path: Path,
    safe_name: str,
    workflow_id: str,
) -> str:
    """Persist export payload; FalconPy often returns YAML as bytes, not JSON."""
    if isinstance(body, (bytes, bytearray)):
        filename = f"{safe_name}_{workflow_id}.yaml"
        text = bytes(body).decode("utf-8", errors="replace")
        (backup_path / filename).write_text(text, encoding="utf-8")
        return filename
    if isinstance(body, str):
        ext = ".yaml" if body.lstrip().startswith("---") or "definition:" in body[:200] else ".txt"
        filename = f"{safe_name}_{workflow_id}{ext}"
        (backup_path / filename).write_text(body, encoding="utf-8")
        return filename
    filename = f"{safe_name}_{workflow_id}.json"
    with open(backup_path / filename, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2, default=_json_default)
    return filename


def backup_all_workflows(
    client_id: str, 
    client_secret: str, 
    cloud_region: str = "us-2",
    output_dir: str = "backups"
) -> Dict[str, Any]:
    """
    Backup all Falcon Fusion SOAR workflow definitions via the Falcon Workflows API.

    Args:
        client_id: CrowdStrike API Client ID
        client_secret: CrowdStrike API Client Secret
        cloud_region: CrowdStrike Cloud Region (default: us-2)
        output_dir: Output directory for backups (default: backups)
        
    Returns:
        Dict with ``date_stamp``, paths under ``workflows/``, snapshot and summary
        filenames, and per-workflow success metadata (see module docstring).
    """
    
    try:
        # Create output directory with date-based organization
        timestamp = datetime.now().strftime("%Y-%m-%d")
        backup_path = Path(output_dir) / timestamp / "workflows"
        backup_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Workflow definitions backup started: cloud=%s output_dir=%s path=%s",
            cloud_region,
            output_dir,
            backup_path,
        )

        console.print(f"[green]Workflows backup directory: {backup_path}[/green]")
        
        # Initialize CrowdStrike Falcon Workflows API client
        falcon = Workflows(
            client_id=client_id,
            client_secret=client_secret,
            cloud=cloud_region
        )
        
        console.print("[yellow]Fetching workflows from CrowdStrike...[/yellow]")

        workflow_ids, page_metas, reported_total = _fetch_all_workflow_definitions(falcon)
        total_workflows = len(workflow_ids)

        snapshot_payload = {
            "backup_timestamp": datetime.now().isoformat(),
            "cloud_region": cloud_region,
            "api_operation": "WorkflowDefinitionsCombined",
            "reported_total": reported_total,
            "fetched_count": total_workflows,
            "search_pages": page_metas,
            "resources": workflow_ids,
        }
        snapshot_path = backup_path / "_definitions_api_snapshot.json"
        with open(snapshot_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_payload, f, indent=2, default=_json_default)

        console.print(
            f"[green]Found {total_workflows} workflows[/green]"
            + (f" (API total: {reported_total})" if reported_total is not None else "")
        )
        console.print(f"[dim]API snapshot: {snapshot_path.name}[/dim]")

        logger.info(
            "Workflow definitions: listed %s workflow(s)%s",
            total_workflows,
            f" api_total={reported_total}" if reported_total is not None else "",
        )

        if total_workflows == 0:
            console.print("[yellow]No workflows found to backup[/yellow]")
            return {
                "timestamp": datetime.now().isoformat(),
                "date_stamp": timestamp,
                "total_workflows": 0,
                "backed_up_workflows": 0,
                "failed_workflows": 0,
                "backup_directory": str(backup_path),
                "definitions_api_snapshot": snapshot_path.name,
            }
        
        backed_up_workflows = []
        failed_workflows = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Backing up workflows...", total=total_workflows)
            
            for workflow in workflow_ids:
                try:
                    workflow_id = workflow.get("id") if isinstance(workflow, dict) else workflow
                    workflow_name = workflow.get("name", "unnamed") if isinstance(workflow, dict) else "unnamed"
                    
                    export_response = falcon.export_definition(id=workflow_id)
                    safe_name = sanitize_filename(workflow_name)

                    meta_extra = _meta_from_workflow(workflow)

                    if isinstance(export_response, (bytes, bytearray)):
                        filename = _write_export_body(
                            export_response, backup_path, safe_name, workflow_id
                        )
                        def_json = _write_workflow_definition_json(
                            backup_path, safe_name, workflow_id, workflow
                        )
                        backed_up_workflows.append({
                            "id": workflow_id,
                            "name": workflow_name,
                            "filename": filename,
                            "definition_json": def_json,
                            "format": "yaml",
                            **meta_extra,
                        })
                    elif isinstance(export_response, dict) and export_response.get("status_code") == 200:
                        body = export_response.get("body")
                        if body in (None, {}):
                            if isinstance(workflow, dict):
                                filename = _write_export_body(
                                    workflow, backup_path, safe_name, workflow_id
                                )
                                def_json = _write_workflow_definition_json(
                                    backup_path, safe_name, workflow_id, workflow
                                )
                                backed_up_workflows.append({
                                    "id": workflow_id,
                                    "name": workflow_name,
                                    "filename": filename,
                                    "definition_json": def_json,
                                    "note": "Empty export body; saved search listing only",
                                    **meta_extra,
                                })
                            else:
                                failed_workflows.append({
                                    "id": workflow_id,
                                    "error": "Export returned 200 with empty body",
                                })
                        else:
                            filename = _write_export_body(
                                body, backup_path, safe_name, workflow_id
                            )
                            fmt = "yaml" if filename.endswith(".yaml") else "json"
                            def_json = _write_workflow_definition_json(
                                backup_path, safe_name, workflow_id, workflow
                            )
                            backed_up_workflows.append({
                                "id": workflow_id,
                                "name": workflow_name,
                                "filename": filename,
                                "definition_json": def_json,
                                "format": fmt,
                                **meta_extra,
                            })
                    else:
                        if isinstance(workflow, dict):
                            filename = f"{safe_name}_{workflow_id}.definition.json"
                            filepath = backup_path / filename
                            with open(filepath, "w", encoding="utf-8") as f:
                                json.dump(workflow, f, indent=2, default=_json_default)
                            backed_up_workflows.append({
                                "id": workflow_id,
                                "name": workflow_name,
                                "filename": filename,
                                "definition_json": filename,
                                "format": "json",
                                "note": "Saved from search results (export failed)",
                                "export_error": _export_errors(export_response),
                                **meta_extra,
                            })
                        else:
                            failed_workflows.append({
                                "id": workflow_id,
                                "error": f"Export failed: {_export_errors(export_response)}",
                            })
                        
                except Exception as e:
                    wf_id = workflow.get("id") if isinstance(workflow, dict) else workflow
                    failed_workflows.append({
                        "id": wf_id,
                        "error": str(e)
                    })
                
                progress.advance(task)
        
        # Create backup summary
        summary = {
            "timestamp": datetime.now().isoformat(),
            "date_stamp": timestamp,
            "total_workflows": total_workflows,
            "backed_up_workflows": len(backed_up_workflows),
            "failed_workflows": len(failed_workflows),
            "backup_directory": str(backup_path),
            "cloud_region": cloud_region,
            "definitions_api_snapshot": snapshot_path.name,
            "successful_workflows": backed_up_workflows,
            "failed_workflows_details": failed_workflows,
        }
        
        # Save summary
        summary_file = backup_path / "_workflows_backup_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=_json_default)
        
        console.print(f"\n[bold green]Workflows backup completed![/bold green]")
        console.print(f"[green]SUCCESS:[/green] Backed up: {len(backed_up_workflows)} workflows")
        if failed_workflows:
            console.print(f"[red]FAILED:[/red] Failed: {len(failed_workflows)} workflows")
        console.print(f"[blue]LOCATION:[/blue] {backup_path}")

        logger.info(
            "Workflow definitions backup finished: backed_up=%s failed=%s path=%s",
            len(backed_up_workflows),
            len(failed_workflows),
            backup_path,
        )

        return summary

    except Exception as e:
        error_msg = f"Workflows backup failed: {str(e)}"
        console.print(f"[red]{error_msg}[/red]")
        logger.error(error_msg, exc_info=True)
        raise


