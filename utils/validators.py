"""
Validation helpers used by ``cli.py`` and backup tools.

- ``validate_api_credentials`` -- instantiates ``falconpy.CorrelationRules`` with the
  same ``cloud=`` region as backups and performs a minimal read (``get_rules_combined``)
  to verify OAuth2 client id/secret.
- ``validate_directory_path`` -- ensures ``output_dir`` exists or is creatable and is
  writable (probe file in that directory).
- ``sanitize_filename`` -- strips unsafe characters for rule/workflow/lookup filenames
  written under ``backups/<date>/...``.
- ``validate_rule_data`` -- optional structural check for rule dicts.

For live probes of every backup list/search API (including ``BACKUP_FILTER`` on
``query_rules``), use ``tools.validate_backup_searches.validate_backup_api_searches`` or
``cli.py validate-searches``.

Raises ``ValidationError`` on failure. Backup modules write only through paths built
from ``sanitize_filename`` plus known suffixes; see README “Where data is written”.

Author: Ibrahim Al-Shinnawi
"""
import logging
import os
from typing import Dict, Any, Optional

from falconpy import CorrelationRules

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """
    Custom exception for validation errors
    
    This exception is raised when validation fails for any input data,
    API credentials, file paths, or rule data structures.
    
    Attributes:
        message: Human-readable error message describing the validation failure
    """
    pass

def validate_api_credentials(client_id: str, client_secret: str, cloud: str = "us-2") -> bool:
    """
    Validate API credentials by attempting to create a client
    
    Performs a test authentication with the CrowdStrike Falcon API using the
    provided credentials to ensure they are valid before proceeding with backup
    operations. This prevents failures during the actual backup process.
    
    Args:
        client_id: CrowdStrike API client ID (required)
        client_secret: CrowdStrike API client secret (required)
        cloud: CrowdStrike cloud region (same as FALCON_CLOUDREGION, default us-2)
        
    Returns:
        bool: True if credentials are valid and can authenticate successfully
        
    Raises:
        ValidationError: If credentials are invalid, empty, or authentication fails
        
    Example:
        >>> try:
        ...     validate_api_credentials("your_client_id", "your_client_secret")
        ...     print("Credentials are valid")
        ... except ValidationError as e:
        ...     print(f"Invalid credentials: {e}")
    """
    try:
        client = CorrelationRules(
            client_id=client_id,
            client_secret=client_secret,
            cloud=cloud,
        )
        response = client.get_rules_combined(limit=1)
        if response.get("status_code") == 200:
            return True
        code = response.get("status_code")
        logger.debug(
            "get_rules_combined returned non-200 during credential check: status_code=%s",
            code,
        )
        raise ValidationError(
            f"API credential check failed (HTTP {code}). Verify FALCON_CLIENT_ID and "
            "FALCON_CLIENT_SECRET, ensure the API client has Correlation Rules read access, "
            "and confirm FALCON_CLOUDREGION matches your tenant."
        )
    except ValidationError:
        raise
    except Exception:
        logger.debug("Credential validation failed with an exception", exc_info=True)
        raise ValidationError(
            "Could not validate API credentials. Verify FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, "
            "FALCON_CLOUDREGION, and network access to CrowdStrike APIs. "
            "Run with --verbose for detailed logs."
        ) from None

def validate_directory_path(path: str) -> bool:
    """
    Validate that a directory path is writable
    
    Checks if a directory path exists, can be created if it doesn't exist,
    and is writable by the current user. This ensures backup operations
    can proceed without file system permission issues.
    
    Args:
        path: Directory path to validate (required)
        
    Returns:
        bool: True if path is valid, exists or can be created, and is writable
        
    Raises:
        ValidationError: If path is invalid, cannot be created, or is not writable
        
    Example:
        >>> try:
        ...     validate_directory_path("./backups")
        ...     print("Directory is valid and writable")
        ... except ValidationError as e:
        ...     print(f"Directory validation failed: {e}")
    """
    try:
        # Check if directory exists or can be created
        if os.path.exists(path):
            if not os.path.isdir(path):
                raise ValidationError(f"Path exists but is not a directory: {path}")
        else:
            # Try to create the directory
            os.makedirs(path, exist_ok=True)
        
        # Check if directory is writable
        test_file = os.path.join(path, ".test_write")
        try:
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            raise ValidationError(f"Directory is not writable: {path} - {str(e)}")
        
        return True
        
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"Invalid directory path: {path} - {str(e)}")

def validate_rule_data(rule: Dict[str, Any]) -> bool:
    """
    Validate that a rule object has required fields
    
    Validates the structure and content of correlation rule data to ensure
    it contains the minimum required fields for backup operations.
    
    Args:
        rule: Rule data dictionary from CrowdStrike API (required)
        
    Returns:
        bool: True if rule contains all required fields and has valid data types
        
    Raises:
        ValidationError: If rule is missing required fields or has invalid data types
        
    Example:
        >>> rule_data = {"id": "123", "name": "Test Rule", "status": "enabled"}
        >>> try:
        ...     validate_rule_data(rule_data)
        ...     print("Rule data is valid")
        ... except ValidationError as e:
        ...     print(f"Rule validation failed: {e}")
    """
    required_fields = ["id"]
    optional_fields = ["name", "description", "status"]
    
    # Check required fields
    for field in required_fields:
        if field not in rule:
            raise ValidationError(f"Rule missing required field: {field}")
    
    # Check that optional fields are strings if present
    for field in optional_fields:
        if field in rule and not isinstance(rule[field], str):
            raise ValidationError(f"Rule field '{field}' must be a string")
    
    return True

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe file system usage
    
    Removes or replaces potentially dangerous characters in filenames to prevent
    path traversal attacks and ensure compatibility across different operating
    systems and file systems.
    
    Security Features:
    - Removes path traversal characters (../, ..\\, etc.)
    - Replaces spaces with underscores
    - Removes special characters that could cause issues
    - Limits filename length to prevent buffer overflow attacks
    - Ensures filename is not empty
    
    Args:
        filename: Original filename to sanitize (required)
        
    Returns:
        str: Sanitized filename safe for file system operations
        
    Example:
        >>> sanitize_filename("My Rule (Test).json")
        'My_Rule_Test.json'
        >>> sanitize_filename("../../../etc/passwd")
        'unnamed_file'
    """
    # Remove or replace problematic characters
    import re
    
    # Replace spaces with underscores
    sanitized = filename.replace(' ', '_')
    
    # Remove special characters except alphanumeric, underscore, hyphen, and dot
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', sanitized)
    
    # Ensure it's not empty
    if not sanitized:
        sanitized = "unnamed_file"
    
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    
    return sanitized 