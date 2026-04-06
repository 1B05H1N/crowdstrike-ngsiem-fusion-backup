"""
Logging helpers for the CLI backup commands.

``setup_logger`` configures the **root** logger with a stdout ``StreamHandler`` and
optionally a UTF-8 ``FileHandler``, so ``tools.*`` and ``utils.*`` module loggers
propagate into the same handlers. ``get_log_filename`` returns a path under **``logs/``**
(created if missing):

    logs/correlation_rules_backup_YYYYMMDD_HHMMSS.log

The CLI passes that path when ``--log-file`` is omitted so each process run gets its
own file. Log format is ``[timestamp] LEVEL: message``.

Author: Ibrahim Al-Shinnawi
"""
import logging
import sys
import os
from datetime import datetime
from typing import Optional

def ensure_log_directory():
    """
    Ensure the logs directory exists and is accessible
    
    Creates the logs directory if it doesn't exist and ensures proper
    permissions for logging operations.
    
    Returns:
        str: Path to the logs directory
        
    Raises:
        OSError: If directory creation fails due to permissions or disk space
    """
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir, exist_ok=True)
    return logs_dir

def setup_logger(
    name: str = "correlation_rules_backup",
    level: str = "INFO",
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configure the root logger so all library and ``tools.*`` logs share handlers.

    Returns the named logger (for CLI ``logger.info`` / ``logger.error``); it propagates
    to root like other modules.
    """
    log_level = getattr(logging, level.upper())
    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    if log_file:
        ensure_log_directory()
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    return logging.getLogger(name)

def get_log_filename() -> str:
    """
    Generate a log filename based on current timestamp
    
    Creates a unique log filename using the current date and time to prevent
    conflicts and enable chronological organization of log files.
    
    Returns:
        str: Log filename in format "correlation_rules_backup_YYYYMMDD_HHMMSS.log"
        
    Example:
        >>> filename = get_log_filename()
        >>> print(filename)
        'logs/correlation_rules_backup_20250901_140530.log'
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create logs directory if it doesn't exist
    ensure_log_directory()
    
    filename = os.path.join("logs", f"correlation_rules_backup_{timestamp}.log")
    return filename
