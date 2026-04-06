#!/usr/bin/env python3
"""
CLI for CrowdStrike Falcon backups (correlation rules, Fusion workflows, NGSIEM lookups).

Execution flow (high level)
---------------------------
- ``load_dotenv()`` loads ``.env`` from the current working directory into the process
  environment before Click parses options (flags can still override env).
- ``backup`` / ``workflows`` / ``all`` call ``validate_directory_path(output_dir)`` and
  ``validate_api_credentials(..., cloud=cloud_region)``, then invoke the appropriate
  ``tools.*`` backup functions.
- ``validate-searches`` runs ``tools.validate_backup_searches.validate_backup_api_searches``:
  minimal live list/search calls (including ``BACKUP_FILTER`` on ``query_rules``) to
  confirm API scopes before a long backup.
- ``all`` runs correlation rules, then workflows. Fusion catalog and NGSIEM steps run
  only if the workflow step succeeds (see ``_run_fusion_catalog_and_ngsiem_lookups``).
- After a successful partial or full run, ``publish_compressed_backup`` may write a zip
  and audit files under ``BACKUP_REMOTE_DIR`` / ``OUTPUT_SHARE`` (see
  ``tools.backup_remote_publish``).
- ``--skip-if-unchanged`` (or ``BACKUP_SKIP_IF_UNCHANGED``) compares API fingerprints to
  ``<output_dir>/.backup_fingerprints.json`` and exits before heavy work when unchanged.
- Remote zip publish copies only to ``BACKUP_REMOTE_DIR`` / ``OUTPUT_SHARE`` when
  ``BACKUP_REMOTE_PUBLISH`` is enabled; there is no network upload in this tool.

Writes (defaults)
-----------------
- Backup payloads: ``<output_dir>/<YYYY-MM-DD>/`` (rules at top level; workflows under
  ``workflows/``; optional ``fusion_catalog/``, ``ngsiem_lookups/``, ``ngsiem_parsers/``).
- Logs: ``logs/correlation_rules_backup_<timestamp>.log`` via ``utils.logger``.
- Remote: optional ``<BACKUP_REMOTE_SUBDIR>/archives/*.zip``, ``audits/*.json``,
  ``previous_file_manifest.json``.

Author: Ibrahim Al-Shinnawi
"""
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import setup_logger, get_log_filename
from utils.validators import validate_api_credentials, validate_directory_path, ValidationError
from tools.correlation_rules_backup import backup_all_correlation_rules
from tools.fusion_workflows_catalog_backup import backup_fusion_workflows_catalog
from tools.ngsiem_lookups_backup import backup_ngsiem_lookups
from tools.ngsiem_parsers_backup import backup_ngsiem_parsers
from tools.workflows_backup import backup_all_workflows
from tools.backup_remote_publish import publish_compressed_backup
from tools.validate_backup_searches import validate_backup_api_searches
from tools.backup_fingerprints import (
    bundle_matches_saved,
    collect_fingerprint_bundle,
    env_skip_if_unchanged,
    load_saved_fingerprints,
    merge_saved_with_bundle,
    save_fingerprints,
)

# Load environment variables from .env file if it exists
load_dotenv()

console = Console()


def _date_stamp_for_publish(
    rules_success: bool,
    rules_summary: Optional[Dict[str, Any]],
    workflows_success: bool,
    wf_summary: Optional[Dict[str, Any]],
) -> str:
    if rules_success and rules_summary and rules_summary.get("date_stamp"):
        return str(rules_summary["date_stamp"])
    if workflows_success and wf_summary and wf_summary.get("date_stamp"):
        return str(wf_summary["date_stamp"])
    return datetime.now().strftime("%Y-%m-%d")


def _display_backup_filter_public(backup_filter: str) -> str:
    """Avoid echoing custom FQL (emails, logic) to shared logs or terminals."""
    return backup_filter if backup_filter == "*" else "(custom FQL; not shown - see .env)"


def _ngsiem_parsers_step_ok(summary: Dict[str, Any]) -> bool:
    if summary.get("error"):
        return False
    if summary.get("listed", 0) == 0:
        return True
    return summary.get("downloaded", 0) > 0


def _format_remote_publish_result(pub: Optional[Dict[str, Any]]) -> str:
    if pub is None:
        return "Skipped (no BACKUP_REMOTE_DIR / OUTPUT_SHARE)"
    if pub.get("skipped"):
        reason = pub.get("reason", "unknown")
        if reason == "remote_publish_disabled":
            return (
                "Skipped (set BACKUP_REMOTE_PUBLISH=1 to copy zips to the configured share)"
            )
        return f"Skipped ({reason})"
    return str(pub.get("zip_path", "published"))


def _effective_skip_if_unchanged(cli_flag: bool) -> bool:
    return bool(cli_flag or env_skip_if_unchanged())


def _extras_ok_for_state(
    no_fusion_catalog: bool,
    no_ngsiem_lookups: bool,
    no_ngsiem_parsers: bool,
    extras: Dict[str, bool],
) -> bool:
    if not no_fusion_catalog and not extras.get("fusion_catalog"):
        return False
    if not no_ngsiem_lookups and not extras.get("ngsiem_lookups"):
        return False
    if not no_ngsiem_parsers and not extras.get("ngsiem_parsers"):
        return False
    return True


def _run_fusion_catalog_and_ngsiem_lookups(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    output_dir: str,
    date_stamp: str,
    logger: Any,
    *,
    fusion_catalog: bool = True,
    ngsiem_lookups: bool = True,
    ngsiem_parsers: bool = True,
    ngsiem_parser_types: Optional[str] = None,
) -> Dict[str, bool]:
    """Run optional Fusion catalog, NGSIEM lookups, and NGSIEM parser entity backups."""
    out = {"fusion_catalog": False, "ngsiem_lookups": False, "ngsiem_parsers": False}
    if fusion_catalog:
        try:
            backup_fusion_workflows_catalog(
                client_id,
                client_secret,
                cloud_region,
                output_dir,
                date_stamp=date_stamp,
            )
            out["fusion_catalog"] = True
        except Exception as e:
            console.print(f"[yellow]Fusion workflow catalog backup failed: {e}[/yellow]")
            console.print(
                "[yellow]Needs Workflows API read for activities, executions, triggers.[/yellow]"
            )
            logger.error("Fusion catalog backup failed: %s", e, exc_info=True)
    if ngsiem_lookups:
        try:
            backup_ngsiem_lookups(
                client_id,
                client_secret,
                cloud_region,
                output_dir,
                date_stamp=date_stamp,
            )
            out["ngsiem_lookups"] = True
        except Exception as e:
            console.print(f"[yellow]NGSIEM lookups backup failed: {e}[/yellow]")
            console.print("[yellow]Needs NGSIEM API scopes for lookup list/download.[/yellow]")
            logger.error("NGSIEM lookups backup failed: %s", e, exc_info=True)
    if ngsiem_parsers:
        try:
            psum = backup_ngsiem_parsers(
                client_id,
                client_secret,
                cloud_region,
                output_dir,
                date_stamp=date_stamp,
                parser_types_cli=ngsiem_parser_types,
            )
            out["ngsiem_parsers"] = _ngsiem_parsers_step_ok(psum)
        except Exception as e:
            console.print(f"[yellow]NGSIEM parsers backup failed: {e}[/yellow]")
            console.print(
                "[yellow]Needs NGSIEM API scopes for ListParsers / GetParser.[/yellow]"
            )
            logger.error("NGSIEM parsers backup failed: %s", e, exc_info=True)
    return out


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """CrowdStrike Falcon backup: rules, Fusion workflows, NGSIEM lookups & parsers (unofficial tool)."""
    pass

@cli.command()
@click.option('--client-id', envvar='FALCON_CLIENT_ID', help='CrowdStrike API Client ID')
@click.option('--client-secret', envvar='FALCON_CLIENT_SECRET', help='CrowdStrike API Client Secret')
@click.option('--cloud-region', envvar='FALCON_CLOUDREGION', default='us-2', help='CrowdStrike Cloud Region')
@click.option('--backup-filter', envvar='BACKUP_FILTER', default='*', help='Filter for correlation rules (default: *)')
@click.option('--output-dir', default='backups', help='Output directory for backups')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--dry-run', is_flag=True, help='Validate credentials without performing backup')
@click.option(
    '--skip-if-unchanged',
    is_flag=True,
    help='Skip backup when rule IDs match last run (see output_dir/.backup_fingerprints.json; BACKUP_SKIP_IF_UNCHANGED=1)',
)
def backup(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    backup_filter: str,
    output_dir: str,
    log_file: Optional[str],
    verbose: bool,
    dry_run: bool,
    skip_if_unchanged: bool,
):
    """
    Backup all correlation rules from CrowdStrike Falcon
    
    This command performs a comprehensive backup of correlation rules from the
    CrowdStrike Falcon platform. It supports filtering, dry-run mode for testing,
    and detailed logging for monitoring and troubleshooting.
    
    Examples:
        # Basic backup
        python cli.py backup
        
        # Backup with custom filter (only enabled rules)
        python cli.py backup --backup-filter "status:'enabled'"
        
        # Test credentials without backing up
        python cli.py backup --dry-run
        
        # Verbose logging for debugging
        python cli.py backup --verbose
    """
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    if not log_file:
        log_file = get_log_filename()
    
    logger = setup_logger(log_file=log_file, level=log_level)
    
    try:
        # Display welcome message
        console.print(Panel.fit(
            "[bold blue]CrowdStrike Correlation Rules Backup Tool[/bold blue]\n"
            "Backing up correlation rules from CrowdStrike Falcon API",
            title="Backup Tool"
        ))
        
        # Validate credentials
        if not client_id or not client_secret:
            console.print("[red]Error: Missing API credentials[/red]")
            console.print("Please provide FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")
            console.print("You can set them as environment variables or use --client-id and --client-secret options")
            sys.exit(1)
        
        # Validate output directory
        try:
            validate_directory_path(output_dir)
        except ValidationError as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            sys.exit(1)
        
        # Test API credentials
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Validating API credentials...", total=None)
            
            try:
                validate_api_credentials(client_id, client_secret, cloud_region)
                progress.update(task, description="API credentials validated")
            except ValidationError as e:
                progress.update(task, description="API credentials invalid")
                console.print(f"[red]Error: {str(e)}[/red]")
                sys.exit(1)
        
        if dry_run:
            console.print("[green]Dry run completed successfully![/green]")
            console.print("Credentials are valid and ready for backup.")
            console.print(f"Backup filter: {_display_backup_filter_public(backup_filter)}")
            return

        skip_u = _effective_skip_if_unchanged(skip_if_unchanged)
        current_fp: Optional[Dict[str, Any]] = None
        if skip_u:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Checking correlation rules fingerprint...", total=None
                )
                current_fp = collect_fingerprint_bundle(
                    client_id,
                    client_secret,
                    cloud_region,
                    backup_filter,
                    include_rules=True,
                    include_workflows=False,
                    include_ngsiem_lookups=False,
                    include_ngsiem_parsers=False,
                    include_fusion_light=False,
                )
                progress.update(task, description="Fingerprint ready")
            saved_fp = load_saved_fingerprints(output_dir)
            if bundle_matches_saved(saved_fp, current_fp):
                console.print(
                    "[green]No correlation rule changes detected; skipping backup "
                    "(.backup_fingerprints.json).[/green]"
                )
                return

        # Perform backup
        console.print(f"\n[bold]Starting backup to: {output_dir}[/bold]")
        console.print(f"[bold]Using filter: {_display_backup_filter_public(backup_filter)}[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Backing up correlation rules...", total=None)
            rules_only_summary = backup_all_correlation_rules(
                client_id, client_secret, cloud_region, backup_filter, output_dir
            )
            progress.update(task, description="Backup completed successfully!")

        if skip_u and current_fp is not None:
            save_fingerprints(
                output_dir,
                merge_saved_with_bundle(load_saved_fingerprints(output_dir), current_fp),
            )

        # Display summary
        console.print("\n[bold green]Backup Summary:[/bold green]")
        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Item", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Output Directory", output_dir)
        summary_table.add_row("Log File", log_file)
        summary_table.add_row("Cloud Region", cloud_region)
        summary_table.add_row("Backup Filter", _display_backup_filter_public(backup_filter))
        summary_table.add_row("Status", "Completed")
        ds = rules_only_summary.get("date_stamp") or datetime.now().strftime("%Y-%m-%d")
        publish_label = "-"
        try:
            pub = publish_compressed_backup(
                output_dir,
                ds,
                {
                    "command": "backup",
                    "backup_date_folder": ds,
                    "correlation_rules": "success",
                    "cloud_region": cloud_region,
                    "backup_filter": _display_backup_filter_public(backup_filter),
                    "backed_up_rules": rules_only_summary.get("backed_up_rules"),
                    "failed_rules": rules_only_summary.get("failed_rules"),
                },
            )
            publish_label = _format_remote_publish_result(pub)
        except Exception as e:
            logger.warning("Remote compressed backup failed: %s", e, exc_info=True)
            publish_label = f"Failed: {e}"
        summary_table.add_row("Remote compressed backup", publish_label)

        console.print(summary_table)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Backup interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
@click.option('--client-id', envvar='FALCON_CLIENT_ID', help='CrowdStrike API Client ID')
@click.option('--client-secret', envvar='FALCON_CLIENT_SECRET', help='CrowdStrike API Client Secret')
@click.option('--cloud-region', envvar='FALCON_CLOUDREGION', default='us-2', help='CrowdStrike Cloud Region')
@click.option('--output-dir', default='backups', help='Output directory for backups')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option(
    '--no-fusion-catalog',
    is_flag=True,
    help='Skip Fusion activities/triggers/executions catalog JSON (definitions only)',
)
@click.option(
    '--no-ngsiem-lookups',
    is_flag=True,
    help='Skip NGSIEM lookup file download',
)
@click.option(
    '--no-ngsiem-parsers',
    is_flag=True,
    help='Skip NGSIEM parser definitions (ListParsers / GetParser, parsers-repository)',
)
@click.option(
    '--ngsiem-parser-types',
    'ngsiem_parser_types',
    envvar='NGSIEM_PARSER_TYPES',
    default=None,
    help=(
        'ListParsers scope: custom (default if unset), ootb, all, or custom,ootb. '
        'Env: NGSIEM_PARSER_TYPES.'
    ),
)
@click.option(
    '--skip-if-unchanged',
    is_flag=True,
    help='Skip when workflow/NGSIEM/fusion fingerprints match last run (.backup_fingerprints.json)',
)
def workflows(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    output_dir: str,
    log_file: Optional[str],
    verbose: bool,
    no_fusion_catalog: bool,
    no_ngsiem_lookups: bool,
    no_ngsiem_parsers: bool,
    ngsiem_parser_types: Optional[str],
    skip_if_unchanged: bool,
):
    """
    Backup Falcon Fusion SOAR: workflow definitions, optional workflow catalog,
    NGSIEM lookups, and NGSIEM parser entities (custom parsers in parsers-repository).
    """
    
    log_level = "DEBUG" if verbose else "INFO"
    if not log_file:
        log_file = get_log_filename()
    
    logger = setup_logger(log_file=log_file, level=log_level)
    
    try:
        console.print(Panel.fit(
            "[bold blue]Falcon Fusion SOAR Workflows Backup[/bold blue]\n"
            "Workflow definitions via Falcon Workflows API (/workflows/)",
            title="Fusion / Workflows Backup"
        ))
        
        if not client_id or not client_secret:
            console.print("[red]Error: Missing API credentials[/red]")
            sys.exit(1)
        
        try:
            validate_directory_path(output_dir)
        except ValidationError as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            sys.exit(1)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Validating API credentials...", total=None)
            try:
                validate_api_credentials(client_id, client_secret, cloud_region)
                progress.update(task, description="API credentials validated")
            except ValidationError as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                sys.exit(1)

        skip_u = _effective_skip_if_unchanged(skip_if_unchanged)
        current_fp: Optional[Dict[str, Any]] = None
        if skip_u:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Checking workflows / NGSIEM fingerprint...", total=None)
                current_fp = collect_fingerprint_bundle(
                    client_id,
                    client_secret,
                    cloud_region,
                    None,
                    include_rules=False,
                    include_workflows=True,
                    include_ngsiem_lookups=not no_ngsiem_lookups,
                    include_ngsiem_parsers=not no_ngsiem_parsers,
                    include_fusion_light=not no_fusion_catalog,
                    ngsiem_parser_types=ngsiem_parser_types,
                )
                progress.update(task, description="Fingerprint ready")
            if bundle_matches_saved(load_saved_fingerprints(output_dir), current_fp):
                console.print(
                    "[green]No workflow-related changes detected; skipping (.backup_fingerprints.json).[/green]"
                )
                return

        console.print(f"\n[bold]Starting workflows backup to: {output_dir}[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Backing up workflows...", total=None)
            wf_summary = backup_all_workflows(client_id, client_secret, cloud_region, output_dir)
            progress.update(task, description="Workflows backup completed!")

        stamp = wf_summary.get("date_stamp") or datetime.now().strftime("%Y-%m-%d")
        extras = _run_fusion_catalog_and_ngsiem_lookups(
            client_id,
            client_secret,
            cloud_region,
            output_dir,
            stamp,
            logger,
            fusion_catalog=not no_fusion_catalog,
            ngsiem_lookups=not no_ngsiem_lookups,
            ngsiem_parsers=not no_ngsiem_parsers,
            ngsiem_parser_types=ngsiem_parser_types,
        )
        
        console.print("\n[bold green]Workflows Backup Summary:[/bold green]")
        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Item", style="cyan")
        summary_table.add_column("Value", style="green")
        summary_table.add_row("Output Directory", output_dir)
        summary_table.add_row("Log File", log_file)
        summary_table.add_row("Cloud Region", cloud_region)
        summary_table.add_row("Fusion catalog", "Yes" if extras["fusion_catalog"] else "Skipped or failed")
        summary_table.add_row("NGSIEM lookups", "Yes" if extras["ngsiem_lookups"] else "Skipped or failed")
        summary_table.add_row("NGSIEM parsers", "Yes" if extras["ngsiem_parsers"] else "Skipped or failed")
        summary_table.add_row("Status", "Completed")
        publish_label = "-"
        try:
            pub = publish_compressed_backup(
                output_dir,
                stamp,
                {
                    "command": "workflows",
                    "backup_date_folder": stamp,
                    "fusion_catalog": "yes" if extras["fusion_catalog"] else "no",
                    "ngsiem_lookups": "yes" if extras["ngsiem_lookups"] else "no",
                    "ngsiem_parsers": "yes" if extras["ngsiem_parsers"] else "no",
                    "cloud_region": cloud_region,
                },
            )
            publish_label = _format_remote_publish_result(pub)
        except Exception as e:
            logger.warning("Remote compressed backup failed: %s", e, exc_info=True)
            publish_label = f"Failed: {e}"
        summary_table.add_row("Remote compressed backup", publish_label)
        if skip_u and current_fp is not None and _extras_ok_for_state(
            no_fusion_catalog,
            no_ngsiem_lookups,
            no_ngsiem_parsers,
            extras,
        ):
            save_fingerprints(
                output_dir,
                merge_saved_with_bundle(load_saved_fingerprints(output_dir), current_fp),
            )
        console.print(summary_table)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Backup interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option('--client-id', envvar='FALCON_CLIENT_ID', help='CrowdStrike API Client ID')
@click.option('--client-secret', envvar='FALCON_CLIENT_SECRET', help='CrowdStrike API Client Secret')
@click.option('--cloud-region', envvar='FALCON_CLOUDREGION', default='us-2', help='CrowdStrike Cloud Region')
@click.option('--backup-filter', envvar='BACKUP_FILTER', default='*', help='Filter for correlation rules')
@click.option('--output-dir', default='backups', help='Output directory for backups')
@click.option('--log-file', help='Log file path (optional)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--no-fusion-catalog', is_flag=True, help='Skip Fusion activities/triggers/executions catalog')
@click.option('--no-ngsiem-lookups', is_flag=True, help='Skip NGSIEM lookup file download')
@click.option(
    '--no-ngsiem-parsers',
    is_flag=True,
    help='Skip NGSIEM parser definitions (ListParsers / GetParser)',
)
@click.option(
    '--ngsiem-parser-types',
    'ngsiem_parser_types',
    envvar='NGSIEM_PARSER_TYPES',
    default=None,
    help=(
        'ListParsers scope: custom (default if unset), ootb, all, or custom,ootb. '
        'Env: NGSIEM_PARSER_TYPES.'
    ),
)
@click.option(
    '--skip-if-unchanged',
    is_flag=True,
    help='Skip entire run when all fingerprints match last success (.backup_fingerprints.json)',
)
def all(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    backup_filter: str,
    output_dir: str,
    log_file: Optional[str],
    verbose: bool,
    no_fusion_catalog: bool,
    no_ngsiem_lookups: bool,
    no_ngsiem_parsers: bool,
    ngsiem_parser_types: Optional[str],
    skip_if_unchanged: bool,
):
    """
    Backup correlation rules, Falcon Fusion workflows (definitions + catalog), NGSIEM lookups,
    and NGSIEM parser entities (custom parsers).
    """
    
    log_level = "DEBUG" if verbose else "INFO"
    if not log_file:
        log_file = get_log_filename()
    
    logger = setup_logger(log_file=log_file, level=log_level)
    
    try:
        console.print(Panel.fit(
            "[bold blue]CrowdStrike Full Backup Tool[/bold blue]\n"
            "Correlation rules + Falcon Fusion SOAR workflows",
            title="Full Backup"
        ))
        
        if not client_id or not client_secret:
            console.print("[red]Error: Missing API credentials[/red]")
            sys.exit(1)
        
        try:
            validate_directory_path(output_dir)
        except ValidationError as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            sys.exit(1)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Validating API credentials...", total=None)
            try:
                validate_api_credentials(client_id, client_secret, cloud_region)
                progress.update(task, description="API credentials validated")
            except ValidationError as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                sys.exit(1)

        skip_u = _effective_skip_if_unchanged(skip_if_unchanged)
        current_fp: Optional[Dict[str, Any]] = None
        if skip_u:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Checking full backup fingerprint...", total=None)
                current_fp = collect_fingerprint_bundle(
                    client_id,
                    client_secret,
                    cloud_region,
                    backup_filter,
                    include_rules=True,
                    include_workflows=True,
                    include_ngsiem_lookups=not no_ngsiem_lookups,
                    include_ngsiem_parsers=not no_ngsiem_parsers,
                    include_fusion_light=not no_fusion_catalog,
                    ngsiem_parser_types=ngsiem_parser_types,
                )
                progress.update(task, description="Fingerprint ready")
            if bundle_matches_saved(load_saved_fingerprints(output_dir), current_fp):
                console.print(
                    "[green]No changes detected for this full backup; skipping "
                    "(.backup_fingerprints.json).[/green]"
                )
                return

        # Backup correlation rules
        rules_success = False
        workflows_success = False
        rules_summary: Optional[Dict[str, Any]] = None

        console.print(f"\n[bold]1. Backing up correlation rules...[/bold]")
        try:
            rules_summary = backup_all_correlation_rules(
                client_id, client_secret, cloud_region, backup_filter, output_dir
            )
            rules_success = True
        except Exception as e:
            console.print(f"[red]Correlation rules backup failed: {str(e)}[/red]")
        
        # Falcon Fusion SOAR definitions (Falcon Workflows API)
        console.print(f"\n[bold]2. Backing up Falcon Fusion SOAR workflows...[/bold]")
        wf_summary = None
        try:
            wf_summary = backup_all_workflows(client_id, client_secret, cloud_region, output_dir)
            workflows_success = True
        except Exception as e:
            console.print(f"[yellow]Fusion / workflows backup failed: {str(e)}[/yellow]")
            console.print(
                "[yellow]Note: API client needs Workflows API read (e.g. search definitions + export).[/yellow]"
            )

        fusion_catalog_ok = False
        ngsiem_ok = False
        ngsiem_parsers_ok = False
        if workflows_success and wf_summary:
            stamp = wf_summary.get("date_stamp")
            if stamp:
                console.print(
                    "\n[bold]3. Fusion catalog + NGSIEM lookups + NGSIEM parsers...[/bold]"
                )
                extras = _run_fusion_catalog_and_ngsiem_lookups(
                    client_id,
                    client_secret,
                    cloud_region,
                    output_dir,
                    stamp,
                    logger,
                    fusion_catalog=not no_fusion_catalog,
                    ngsiem_lookups=not no_ngsiem_lookups,
                    ngsiem_parsers=not no_ngsiem_parsers,
                    ngsiem_parser_types=ngsiem_parser_types,
                )
                fusion_catalog_ok = extras["fusion_catalog"]
                ngsiem_ok = extras["ngsiem_lookups"]
                ngsiem_parsers_ok = extras["ngsiem_parsers"]
        
        if rules_success or workflows_success:
            console.print("\n[bold green]Backup Complete![/bold green]")
        else:
            console.print("\n[bold red]All backups failed![/bold red]")
            sys.exit(1)
        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Item", style="cyan")
        summary_table.add_column("Value", style="green")
        summary_table.add_row("Output Directory", output_dir)
        summary_table.add_row("Log File", log_file)
        summary_table.add_row("Cloud Region", cloud_region)
        summary_table.add_row(
            "Correlation Rules Filter", _display_backup_filter_public(backup_filter)
        )
        summary_table.add_row("Correlation Rules", "Success" if rules_success else "Failed")
        summary_table.add_row("Fusion SOAR workflows", "Success" if workflows_success else "Failed (needs API scope)")
        summary_table.add_row(
            "Fusion catalog",
            "Success" if fusion_catalog_ok else ("N/A" if not workflows_success else "Skipped or failed"),
        )
        summary_table.add_row(
            "NGSIEM lookups",
            "Success" if ngsiem_ok else ("N/A" if not workflows_success else "Skipped or failed"),
        )
        summary_table.add_row(
            "NGSIEM parsers",
            "Success" if ngsiem_parsers_ok else ("N/A" if not workflows_success else "Skipped or failed"),
        )

        date_stamp = _date_stamp_for_publish(
            rules_success, rules_summary, workflows_success, wf_summary
        )
        publish_ctx: Dict[str, Any] = {
            "command": "all",
            "backup_date_folder": date_stamp,
            "correlation_rules": "success" if rules_success else "failed",
            "workflows": "success" if workflows_success else "failed",
            "fusion_catalog": (
                "success"
                if fusion_catalog_ok
                else ("n_a" if not workflows_success else "skipped_or_failed")
            ),
            "ngsiem_lookups": (
                "success"
                if ngsiem_ok
                else ("n_a" if not workflows_success else "skipped_or_failed")
            ),
            "ngsiem_parsers": (
                "success"
                if ngsiem_parsers_ok
                else ("n_a" if not workflows_success else "skipped_or_failed")
            ),
            "cloud_region": cloud_region,
            "backup_filter": _display_backup_filter_public(backup_filter),
        }
        publish_label = "-"
        try:
            pub = publish_compressed_backup(output_dir, date_stamp, publish_ctx)
            publish_label = _format_remote_publish_result(pub)
        except Exception as e:
            logger.warning("Remote compressed backup failed: %s", e, exc_info=True)
            publish_label = f"Failed: {e}"
        summary_table.add_row("Remote compressed backup", publish_label)

        if skip_u and current_fp is not None and rules_success and workflows_success:
            if _extras_ok_for_state(
                no_fusion_catalog,
                no_ngsiem_lookups,
                no_ngsiem_parsers,
                {
                    "fusion_catalog": fusion_catalog_ok,
                    "ngsiem_lookups": ngsiem_ok,
                    "ngsiem_parsers": ngsiem_parsers_ok,
                },
            ):
                save_fingerprints(
                    output_dir,
                    merge_saved_with_bundle(load_saved_fingerprints(output_dir), current_fp),
                )

        console.print(summary_table)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Backup interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command("validate-searches")
@click.option("--client-id", envvar="FALCON_CLIENT_ID", help="CrowdStrike API Client ID")
@click.option(
    "--client-secret", envvar="FALCON_CLIENT_SECRET", help="CrowdStrike API Client Secret"
)
@click.option(
    "--cloud-region", envvar="FALCON_CLOUDREGION", default="us-2", help="CrowdStrike Cloud"
)
@click.option(
    "--backup-filter",
    envvar="BACKUP_FILTER",
    default="*",
    help="Same FQL as correlation rule backup (validates query_rules)",
)
@click.option(
    "--no-fusion-catalog",
    is_flag=True,
    help="Skip Fusion workflow search_* probes",
)
@click.option(
    "--no-ngsiem-lookups",
    is_flag=True,
    help="Skip NGSIEM list_lookup_files per domain",
)
@click.option(
    "--no-ngsiem-parsers",
    is_flag=True,
    help="Skip NGSIEM list_parsers probes",
)
@click.option(
    "--ngsiem-parser-types",
    "ngsiem_parser_types",
    envvar="NGSIEM_PARSER_TYPES",
    default=None,
    help="Same as workflows/all (scopes list_parsers passes)",
)
@click.option("--verbose", "-v", is_flag=True, help="Log tracebacks for failed checks")
def validate_searches(
    client_id: str,
    client_secret: str,
    cloud_region: str,
    backup_filter: str,
    no_fusion_catalog: bool,
    no_ngsiem_lookups: bool,
    no_ngsiem_parsers: bool,
    ngsiem_parser_types: Optional[str],
    verbose: bool,
):
    """
    Run minimal live API reads for each backup list/search (query_rules FQL, workflows,
    optional Fusion and NGSIEM). Exits with code 1 if any enabled check fails.
    """
    if verbose:
        import logging as _logging

        _logging.basicConfig(
            level=_logging.DEBUG,
            format="[%(levelname)s] %(name)s: %(message)s",
        )

    if not client_id or not client_secret:
        console.print("[red]Missing FALCON_CLIENT_ID / FALCON_CLIENT_SECRET[/red]")
        sys.exit(1)

    try:
        validate_api_credentials(client_id, client_secret, cloud_region)
    except ValidationError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(
        Panel.fit(
            "[bold]Validating backup API searches[/bold] (minimal limit=1 reads)",
            title="validate-searches",
        )
    )
    result = validate_backup_api_searches(
        client_id,
        client_secret,
        cloud_region,
        backup_filter,
        include_fusion_catalog=not no_fusion_catalog,
        include_ngsiem_lookups=not no_ngsiem_lookups,
        include_ngsiem_parsers=not no_ngsiem_parsers,
        ngsiem_parser_types=ngsiem_parser_types,
    )

    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Check", style="cyan")
    tbl.add_column("HTTP", style="white")
    tbl.add_column("Result", style="green")
    tbl.add_column("Detail", style="dim")

    for c in result["checks"]:
        ok = c.get("ok")
        tbl.add_row(
            c.get("name", ""),
            str(c.get("http_status", "")),
            "[green]OK[/green]" if ok else "[red]FAIL[/red]",
            (c.get("detail") or "")[:120],
        )

    console.print(tbl)
    if verbose:
        for c in result["checks"]:
            if not c.get("ok"):
                console.print(f"[yellow]{c.get('name')}:[/yellow] {c.get('detail', '')}")

    if result["all_ok"]:
        console.print("\n[green]All enabled checks passed.[/green]")
        sys.exit(0)
    console.print("\n[red]One or more checks failed.[/red]")
    sys.exit(1)


@cli.command()
def status():
    """
    Check the status of your configuration
    
    This command validates the current configuration and displays the status
    of all required and optional settings. It helps troubleshoot configuration
    issues before running backup operations.
    
    Examples:
        # Check configuration status
        python cli.py status
    """
    console.print(Panel.fit(
        "[bold blue]Configuration Status[/bold blue]",
        title="Status Check"
    ))
    
    # Check environment variables
    status_table = Table(show_header=True, header_style="bold magenta")
    status_table.add_column("Setting", style="cyan")
    status_table.add_column("Value", style="green")
    status_table.add_column("Status", style="yellow")
    
    # Check credentials
    client_id = os.getenv('FALCON_CLIENT_ID')
    client_secret = os.getenv('FALCON_CLIENT_SECRET')
    cloud_region = os.getenv('FALCON_CLOUDREGION', 'us-2')
    backup_filter = os.getenv('BACKUP_FILTER', '*')

    filter_display = _display_backup_filter_public(backup_filter)
    
    status_table.add_row(
        "FALCON_CLIENT_ID",
        "***" if client_id else "Not set",
        "Set" if client_id else "Missing",
    )
    
    status_table.add_row(
        "FALCON_CLIENT_SECRET", 
        "***" if client_secret else "Not set",
        "Set" if client_secret else "Missing"
    )
    
    status_table.add_row(
        "FALCON_CLOUDREGION", 
        cloud_region,
        "Set"
    )
    
    status_table.add_row(
        "BACKUP_FILTER",
        filter_display,
        "Set",
    )

    remote_dir = os.getenv("BACKUP_REMOTE_DIR") or os.getenv("OUTPUT_SHARE") or ""
    remote_sub = os.getenv("BACKUP_REMOTE_SUBDIR", "crowdstrike-backup")
    max_arch = os.getenv("BACKUP_REMOTE_MAX_ARCHIVES", "30")
    pub_raw = os.getenv("BACKUP_REMOTE_PUBLISH", "").strip().lower()
    publish_on = pub_raw in ("1", "true", "yes", "on")
    status_table.add_row(
        "BACKUP_REMOTE_DIR / OUTPUT_SHARE",
        remote_dir if remote_dir else "Not set",
        "Set" if remote_dir else "Optional",
    )
    status_table.add_row(
        "BACKUP_REMOTE_PUBLISH",
        pub_raw if pub_raw else "unset",
        "Zips will copy to share when set" if publish_on else "No zip copy (enable 1/true/yes)",
    )
    status_table.add_row("BACKUP_REMOTE_SUBDIR", remote_sub, "Set")
    status_table.add_row("BACKUP_REMOTE_MAX_ARCHIVES", max_arch, "Set")
    
    console.print(status_table)
    
    # Check if .env file exists
    env_file = Path('.env')
    if env_file.exists():
        console.print(f"\n[green].env file found: {env_file}[/green]")
    else:
        console.print(f"\n[yellow]No .env file found. Consider creating one for easier configuration.[/yellow]")

@cli.command()
def setup():
    """
    Interactive setup for the backup tool
    
    This command provides an interactive wizard to configure the backup tool
    with your CrowdStrike API credentials and preferences. It creates a .env
    file with the provided configuration.
    
    Examples:
        # Run interactive setup
        python cli.py setup
    """
    console.print(Panel.fit(
        "[bold blue]Interactive Setup[/bold blue]\n"
        "This will help you configure the backup tool",
        title="Setup"
    ))
    
    # Get API credentials
    console.print("\n[bold]Step 1: API Credentials[/bold]")
    client_id = click.prompt("Enter your CrowdStrike API Client ID")
    client_secret = click.prompt("Enter your CrowdStrike API Client Secret", hide_input=True)
    cloud_region = click.prompt("Enter your CrowdStrike Cloud Region", default="us-2")
    
    # Get backup filter with explanation
    console.print("\n[bold]Step 2: Backup Filter[/bold]")
    console.print("The backup filter determines which correlation rules to backup:")
    console.print("• \"*\" = Backup all rules (default)")
    console.print("• \"user_id:!'user@example.com'\" = Exclude rules by user")
    console.print("• \"status:'enabled'\" = Only backup enabled rules")
    console.print("• \"name:'*test*'\" = Only backup rules with 'test' in name")
    console.print("• \"user_id:'admin@example.com'+status:'enabled'\" = Multiple conditions")
    
    backup_filter = click.prompt(
        "Enter backup filter", 
        default="*"
    )
    
    # Create .env file
    env_content = f"""# CrowdStrike API Configuration
FALCON_CLIENT_ID={client_id}
FALCON_CLIENT_SECRET={client_secret}
FALCON_CLOUDREGION={cloud_region}
BACKUP_FILTER={backup_filter}
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    console.print(f"\n[green]Configuration saved to .env file[/green]")
    console.print(f"[green]Backup filter set to: {backup_filter}[/green]")
    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. Run 'python cli.py status' to verify your configuration")
    console.print("2. Run './run-crowdstrike-backup.sh' or 'python cli.py all --no-fusion-catalog' for a full backup")
    console.print("3. Run 'python cli.py backup --dry-run' to validate credentials without backing up")

if __name__ == '__main__':
    cli() 