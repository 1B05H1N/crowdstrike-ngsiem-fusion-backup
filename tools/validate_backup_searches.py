#!/usr/bin/env python3
"""
Live API smoke checks for every **list / search** style call the backup stack relies on.

Use this before long runs to confirm credentials, ``BACKUP_FILTER`` FQL, and optional
NGSIEM / Fusion scopes succeed with minimal traffic (typically ``limit=1`` per call).

Author: Ibrahim Al-Shinnawi
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from falconpy import CorrelationRules, NGSIEM, Workflows

from tools.ngsiem_lookups_backup import SEARCH_DOMAINS
from tools.ngsiem_parsers_backup import DEFAULT_REPOSITORY, resolve_parser_type_passes

logger = logging.getLogger(__name__)


def _detail_from_response(response: Any) -> str:
    if not isinstance(response, dict):
        return str(type(response))
    body = response.get("body")
    if isinstance(body, dict) and body.get("errors") is not None:
        return str(body.get("errors"))[:800]
    return ""


def _list_parsers_probe(
    client: NGSIEM, repository: str, parser_type: Optional[str]
) -> Any:
    if parser_type is None:
        return client.list_parsers(
            limit="1",
            offset="0",
            repository=repository,
        )
    return client.list_parsers(
        limit="1",
        offset="0",
        repository=repository,
        parser_type=parser_type,
    )


def _run_check(name: str, call: Callable[[], Any]) -> Dict[str, Any]:
    try:
        r = call()
        if not isinstance(r, dict):
            return {
                "name": name,
                "ok": False,
                "http_status": None,
                "detail": f"unexpected response type {type(r).__name__}",
            }
        sc = r.get("status_code")
        if sc == 200:
            return {"name": name, "ok": True, "http_status": 200, "detail": "OK"}
        tail = _detail_from_response(r)
        msg = f"HTTP {sc}" + (f": {tail}" if tail else "")
        return {"name": name, "ok": False, "http_status": sc, "detail": msg[:800]}
    except Exception as e:
        logger.debug("check %s failed", name, exc_info=True)
        return {"name": name, "ok": False, "http_status": None, "detail": str(e)[:800]}


def validate_backup_api_searches(
    client_id: str,
    client_secret: str,
    cloud_region: str = "us-2",
    backup_filter: str = "*",
    *,
    include_fusion_catalog: bool = True,
    include_ngsiem_lookups: bool = True,
    include_ngsiem_parsers: bool = True,
    ngsiem_parser_types: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run minimal successful API reads mirroring backup ``search`` / list usage.

    Returns a dict with ``checks`` (list of per-call results), ``all_ok`` (bool),
    and ``cloud_region`` / ``backup_filter`` echo.
    """
    checks: List[Dict[str, Any]] = []

    cr = CorrelationRules(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    checks.append(
        _run_check(
            "correlation_rules.query_rules",
            lambda: cr.query_rules(filter=backup_filter, limit=1, offset=0),
        )
    )

    wf = Workflows(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )
    checks.append(
        _run_check(
            "workflows.search_definitions",
            lambda: wf.search_definitions(limit=1, offset=0),
        )
    )

    if include_fusion_catalog:
        checks.append(
            _run_check(
                "workflows.search_activities",
                lambda: wf.search_activities(limit=1, offset=0),
            )
        )
        checks.append(
            _run_check(
                "workflows.search_activities_content",
                lambda: wf.search_activities_content(limit=1, offset=0),
            )
        )
        checks.append(
            _run_check(
                "workflows.search_triggers",
                lambda: wf.search_triggers(),
            )
        )
        checks.append(
            _run_check(
                "workflows.search_executions",
                lambda: wf.search_executions(limit=1, offset=0),
            )
        )

    ngsiem = NGSIEM(
        client_id=client_id,
        client_secret=client_secret,
        cloud=cloud_region,
    )

    if include_ngsiem_lookups:
        for domain in SEARCH_DOMAINS:
            checks.append(
                _run_check(
                    f"ngsiem.list_lookup_files[{domain}]",
                    lambda d=domain: ngsiem.list_lookup_files(
                        limit="1",
                        offset="0",
                        search_domain=d,
                    ),
                )
            )

    if include_ngsiem_parsers:
        passes = resolve_parser_type_passes(ngsiem_parser_types)
        for pt in passes:
            label = "all" if pt is None else pt
            checks.append(
                _run_check(
                    f"ngsiem.list_parsers({label})",
                    lambda c=ngsiem, r=DEFAULT_REPOSITORY, p=pt: _list_parsers_probe(
                        c, r, p
                    ),
                )
            )

    all_ok = all(c.get("ok") for c in checks)
    return {
        "all_ok": all_ok,
        "cloud_region": cloud_region,
        "backup_filter": backup_filter,
        "checks": checks,
        "included": {
            "fusion_catalog": include_fusion_catalog,
            "ngsiem_lookups": include_ngsiem_lookups,
            "ngsiem_parsers": include_ngsiem_parsers,
        },
    }
