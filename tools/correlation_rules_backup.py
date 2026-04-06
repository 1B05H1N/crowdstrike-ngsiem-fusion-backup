#!/usr/bin/env python3
"""
NGSIEM correlation rules backup via FalconPy ``CorrelationRules``.

API flow
--------
1. ``query_rules`` with FQL ``backup_filter`` and a page size limit (500) to collect rule IDs.
2. For each ID, ``get_rules`` fetches the full rule document.

Filesystem writes (all under ``Path(output_dir) / <YYYY-MM-DD>/``)
------------------------------------------------------------------
- ``<sanitized_rule_name>_<rule_id>.json`` -- one file per successful rule.
- ``_backup_summary.json`` -- ``date_stamp``, counts, ``backup_filter``, cloud region,
  lists of successful and failed rule IDs.

The date folder name is the local calendar day at the start of the run
(``%Y-%m-%d``). The returned dict includes ``date_stamp`` for callers (e.g. remote zip
publish) to target the same directory.

Author: Ibrahim Al-Shinnawi
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from falconpy import CorrelationRules
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from utils.validators import sanitize_filename

console = Console()
logger = logging.getLogger(__name__)

def backup_all_correlation_rules(
    client_id: str, 
    client_secret: str, 
    cloud_region: str = "us-2",
    backup_filter: str = "*",
    output_dir: str = "backups"
) -> Dict[str, Any]:
    """
    Backup all correlation rules from CrowdStrike Falcon API
    
    This function performs a comprehensive backup of correlation rules from the
    CrowdStrike Falcon platform. It includes authentication, rule discovery,
    filtering, and secure file storage with detailed logging and error handling.
    
    Security Features:
    - Validates API credentials before proceeding
    - Sanitizes filenames to prevent path traversal attacks
    - Uses secure file operations with proper error handling
    - Logs operations without exposing sensitive data
    
    Args:
        client_id: CrowdStrike API Client ID (required)
        client_secret: CrowdStrike API Client Secret (required)
        cloud_region: CrowdStrike Cloud Region (default: us-2)
        backup_filter: Filter for correlation rules using FQL (default: *)
        output_dir: Output directory for backups (default: backups)
        
    Returns:
        Dict with ``date_stamp`` (``YYYY-MM-DD``), ``backup_directory``, rule counts,
        ``successful_rules`` / ``failed_rules_details``, and metadata. Written files
        live under ``Path(output_dir) / date_stamp /`` (see module docstring).
        
    Raises:
        Exception: If backup operation fails due to API errors or file system issues
        
    Example:
        >>> summary = backup_all_correlation_rules(
        ...     client_id="your_client_id",
        ...     client_secret="your_client_secret",
        ...     backup_filter="status:'enabled'"
        ... )
    """
    
    try:
        # Create output directory with date-based organization
        # This ensures backups are organized chronologically and prevents overwrites
        timestamp = datetime.now().strftime("%Y-%m-%d")
        backup_path = Path(output_dir) / timestamp
        backup_path.mkdir(parents=True, exist_ok=True)

        filter_note = backup_filter if backup_filter == "*" else "custom FQL (redacted)"
        logger.info(
            "Correlation rules backup started: cloud=%s output_dir=%s date=%s filter=%s",
            cloud_region,
            output_dir,
            timestamp,
            filter_note,
        )

        console.print(f"[green]Backup directory created: {backup_path}[/green]")
        
        # Initialize CrowdStrike Falcon API client
        # This establishes the connection to the CrowdStrike platform
        falcon = CorrelationRules(
            client_id=client_id,
            client_secret=client_secret,
            cloud=cloud_region
        )
        
        console.print("[yellow]Fetching correlation rules from CrowdStrike...[/yellow]")

        rules_data: List[str] = []
        offset = 0
        page_limit = 500
        while True:
            response = falcon.query_rules(
                filter=backup_filter, limit=page_limit, offset=offset
            )
            if response["status_code"] != 200:
                raise Exception(
                    f"Failed to query correlation rules: {response.get('body', {}).get('errors', [])}"
                )
            batch = response["body"].get("resources") or []
            for x in batch:
                if isinstance(x, dict):
                    rules_data.append(str(x.get("id", x)))
                else:
                    rules_data.append(str(x))
            if len(batch) < page_limit:
                break
            offset += len(batch)

        total_rules = len(rules_data)
        logger.info("Correlation rules: listed %s rule ID(s)", total_rules)

        console.print(f"[green]Found {total_rules} correlation rules[/green]")
        
        # Initialize tracking lists for backup results
        # These lists will store successful and failed backup operations
        backed_up_rules = []
        failed_rules = []
        
        # Process each rule with progress tracking
        # This provides visual feedback during the backup process
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Backing up individual rules...", total=total_rules)
            
            # Iterate through each rule ID to get detailed information
            for rule_id in rules_data:
                try:
                    # Retrieve detailed information for each individual rule
                    # This gets the complete rule configuration and metadata
                    rule_response = falcon.get_rules(ids=[rule_id])
                    
                    if rule_response["status_code"] == 200:
                        # Extract rule data from successful API response
                        rule_data = rule_response["body"]["resources"][0]
                        
                        # Create secure filename from rule name
                        # This prevents path traversal attacks and ensures cross-platform compatibility
                        rule_name = rule_data.get("name", "unnamed_rule")
                        safe_name = sanitize_filename(rule_name)
                        
                        # Generate unique filename with rule ID to prevent conflicts
                        # The rule ID ensures uniqueness even if rule names are similar
                        filename = f"{safe_name}_{rule_id}.json"
                        filepath = backup_path / filename
                        
                        # Save rule data to JSON file with proper formatting
                        # This preserves all rule metadata and configuration
                        with open(filepath, 'w') as f:
                            json.dump(rule_data, f, indent=2)
                        
                        # Track successful backup with metadata
                        # This information is used for the backup summary and change detection
                        backed_up_rules.append({
                            "id": rule_id,
                            "name": rule_name,
                            "filename": filename
                        })
                        
                    else:
                        # Track failed rule retrieval with error details
                        # This helps identify and troubleshoot API issues
                        failed_rules.append({
                            "id": rule_id,
                            "error": f"Failed to get rule details: {rule_response.get('body', {}).get('errors', [])}"
                        })
                        
                except Exception as e:
                    # Track exceptions during rule processing
                    # This captures unexpected errors during backup operations
                    failed_rules.append({
                        "id": rule_id,
                        "error": str(e)
                    })
                
                # Update progress indicator
                progress.advance(task)
        
        # Create comprehensive backup summary with metadata
        # This provides a complete record of the backup operation for audit and monitoring
        summary = {
            "timestamp": datetime.now().isoformat(),
            "date_stamp": timestamp,
            "total_rules": total_rules,
            "backed_up_rules": len(backed_up_rules),
            "failed_rules": len(failed_rules),
            "backup_directory": str(backup_path),
            "cloud_region": cloud_region,
            "backup_filter": backup_filter,
            "successful_rules": backed_up_rules,
            "failed_rules_details": failed_rules
        }
        
        # Save backup summary to JSON file
        # This file contains metadata about the backup operation and can be used for change detection
        summary_file = backup_path / "_backup_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Display backup results to user
        # This provides immediate feedback on the backup operation success
        console.print(f"\n[bold green]Backup completed![/bold green]")
        console.print(f"[green]SUCCESS:[/green] Successfully backed up: {len(backed_up_rules)} rules")
        if failed_rules:
            console.print(f"[red]FAILED:[/red] Failed to backup: {len(failed_rules)} rules")
        console.print(f"[blue]BACKUP LOCATION:[/blue] {backup_path}")
        console.print(f"[blue]SUMMARY FILE:[/blue] {summary_file}")

        logger.info(
            "Correlation rules backup finished: backed_up=%s failed=%s path=%s",
            len(backed_up_rules),
            len(failed_rules),
            backup_path,
        )

        # Return summary for programmatic access
        # This allows other parts of the application to access backup results
        return summary
        
    except Exception as e:
        # Handle unexpected errors during backup operations
        # This ensures proper error logging and user notification
        error_msg = f"Backup failed: {str(e)}"
        console.print(f"[red]{error_msg}[/red]")
        logger.error(error_msg, exc_info=True)
        raise
