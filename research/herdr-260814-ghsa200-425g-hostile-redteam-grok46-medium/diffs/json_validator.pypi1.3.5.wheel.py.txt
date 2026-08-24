#!/usr/bin/env python3
"""
Secure JSON Validation Module - MED-8 Security Fix

This module provides comprehensive JSON schema validation to prevent
malformed JSON injection attacks and enforce secure data structure limits.

Security Features:
- JSON schema validation with strict type checking
- Size limits to prevent DoS attacks
- Depth limits to prevent stack overflow
- Content sanitization and validation
- Support for multiple metadata format versions (3, 4, 5)
"""

import json
import os
import sys
from typing import Any, Dict, Optional, Union

try:
    import jsonschema
    from jsonschema import Draft202012Validator, ValidationError, validate

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    print("Warning: jsonschema library not available. JSON validation will be limited.")


class JSONSecurityError(Exception):
    """Raised when JSON content violates security constraints."""

    pass


class JSONValidationError(Exception):
    """Raised when JSON content fails schema validation."""

    pass


class SecureJSONValidator:
    """
    Secure JSON validator with comprehensive security constraints.

    This validator prevents common JSON-based attacks including:
    - DoS through excessive memory usage
    - Stack overflow through deep nesting
    - Schema violations and type confusion
    - Injection through malformed structures
    """

    # Security limits to prevent DoS attacks
    MAX_JSON_SIZE = 1024 * 1024  # 1MB maximum JSON size
    MAX_NESTING_DEPTH = 20  # Maximum nesting depth
    MAX_STRING_LENGTH = 65536  # Maximum string length (64KB for PQC keys)
    MAX_ARRAY_LENGTH = 1000  # Maximum array length
    MAX_OBJECT_PROPERTIES = 1000  # Maximum object properties

    def __init__(self):
        """Initialize the JSON validator with schema loading."""
        self.schemas = {}
        self._load_schemas()

    def _load_schemas(self):
        """Load all JSON schemas from the schemas directory."""
        try:
            # Get the directory containing this module
            current_dir = os.path.dirname(os.path.abspath(__file__))
            schemas_dir = os.path.join(os.path.dirname(current_dir), "schemas")

            # Schema file mappings
            schema_files = {
                "config_template": "config_template_schema.json",
                "keystore": "keystore_schema.json",
                "metadata_v3": "metadata_v3_schema.json",
                "metadata_v4": "metadata_v4_schema.json",
                "metadata_v5": "metadata_v5_schema.json",
                "metadata_v6": "metadata_v6_schema.json",
                "metadata_v7": "metadata_v7_schema.json",
            }

            for schema_name, filename in schema_files.items():
                schema_path = os.path.join(schemas_dir, filename)
                if os.path.exists(schema_path):
                    try:
                        with open(schema_path, "r", encoding="utf-8") as f:
                            schema_content = f.read()
                            # Validate schema size
                            if len(schema_content) > self.MAX_JSON_SIZE:
                                print(f"Warning: Schema file {filename} is too large, skipping")
                                continue

                            schema_data = json.loads(schema_content)
                            self.schemas[schema_name] = schema_data
                    except (json.JSONDecodeError, OSError) as e:
                        print(f"Warning: Could not load schema {filename}: {e}")
                else:
                    print(f"Warning: Schema file {schema_path} not found")

        except Exception as e:
            print(f"Warning: Error loading schemas: {e}")

    def validate_json_security(self, json_string: str) -> None:
        """
        Validate JSON string against security constraints.

        Args:
            json_string (str): JSON string to validate

        Raises:
            JSONSecurityError: If JSON violates security constraints
        """
        # Size limit check
        if len(json_string) > self.MAX_JSON_SIZE:
            raise JSONSecurityError(
                f"JSON size ({len(json_string)} bytes) exceeds maximum allowed size "
                f"({self.MAX_JSON_SIZE} bytes)"
            )

        # Basic syntax check
        if not json_string.strip():
            raise JSONSecurityError("Empty JSON string")

        # Character validation - prevent control characters that could cause issues
        for i, char in enumerate(json_string):
            if ord(char) < 32 and char not in ["\t", "\n", "\r"]:
                raise JSONSecurityError(
                    f"Invalid control character found at position {i}: {repr(char)}"
                )

    def validate_json_structure(self, data: Any, path: str = "root", depth: int = 0) -> None:
        """
        Recursively validate JSON structure against security limits.

        Args:
            data: JSON data to validate
            path: Current path in the structure (for error messages)
            depth: Current nesting depth

        Raises:
            JSONSecurityError: If structure violates security constraints
        """
        # Depth limit check
        if depth > self.MAX_NESTING_DEPTH:
            raise JSONSecurityError(
                f"JSON nesting depth ({depth}) exceeds maximum allowed depth "
                f"({self.MAX_NESTING_DEPTH}) at {path}"
            )

        if isinstance(data, dict):
            # Object property limit check
            if len(data) > self.MAX_OBJECT_PROPERTIES:
                raise JSONSecurityError(
                    f"Object at {path} has {len(data)} properties, exceeding maximum "
                    f"allowed ({self.MAX_OBJECT_PROPERTIES})"
                )

            # Validate keys and recursively validate values
            for key, value in data.items():
                # Key validation
                if not isinstance(key, str):
                    raise JSONSecurityError(f"Non-string key found at {path}: {type(key)}")

                if len(key) > 256:
                    raise JSONSecurityError(f"Key too long at {path}: {len(key)} characters")

                # Recursively validate value
                self.validate_json_structure(value, f"{path}.{key}", depth + 1)

        elif isinstance(data, list):
            # Array length limit check
            if len(data) > self.MAX_ARRAY_LENGTH:
                raise JSONSecurityError(
                    f"Array at {path} has {len(data)} items, exceeding maximum "
                    f"allowed ({self.MAX_ARRAY_LENGTH})"
                )

            # Recursively validate array items
            for i, item in enumerate(data):
                self.validate_json_structure(item, f"{path}[{i}]", depth + 1)

        elif isinstance(data, str):
            # String length limit check
            if len(data) > self.MAX_STRING_LENGTH:
                raise JSONSecurityError(
                    f"String at {path} is {len(data)} characters long, exceeding maximum "
                    f"allowed ({self.MAX_STRING_LENGTH})"
                )

    def parse_and_validate_json(self, json_string: str) -> Dict[str, Any]:
        """
        Securely parse and validate JSON string.

        Args:
            json_string (str): JSON string to parse

        Returns:
            Dict[str, Any]: Parsed JSON data

        Raises:
            JSONSecurityError: If JSON violates security constraints
            JSONValidationError: If JSON is malformed
        """
        # Security validation first
        self.validate_json_security(json_string)

        try:
            # Parse JSON
            data = json.loads(json_string)
        except json.JSONDecodeError as e:
            raise JSONValidationError(f"Invalid JSON syntax: {e}")

        # Validate structure constraints
        self.validate_json_structure(data)

        return data

    def validate_against_schema(self, data: Dict[str, Any], schema_name: str) -> None:
        """
        Validate JSON data against a specific schema.

        Args:
            data (Dict[str, Any]): JSON data to validate
            schema_name (str): Name of schema to validate against

        Raises:
            JSONValidationError: If data doesn't match schema
        """
        if not JSONSCHEMA_AVAILABLE:
            print(
                f"Warning: Cannot validate against schema '{schema_name}' - jsonschema library not available"
            )
            return

        if schema_name not in self.schemas:
            raise JSONValidationError(f"Schema '{schema_name}' not found")

        schema = self.schemas[schema_name]

        try:
            validate(instance=data, schema=schema, cls=Draft202012Validator)
        except ValidationError as e:
            # Create user-friendly error message
            error_path = ".".join(str(x) for x in e.path) if e.path else "root"
            raise JSONValidationError(f"Schema validation failed at {error_path}: {e.message}")

    def validate_metadata(self, json_string: str) -> Dict[str, Any]:
        """
        Validate file metadata JSON with version-specific schema validation.

        Args:
            json_string (str): Metadata JSON string

        Returns:
            Dict[str, Any]: Validated metadata

        Raises:
            JSONSecurityError: If JSON violates security constraints
            JSONValidationError: If JSON is malformed or doesn't match schema
        """
        # Parse and perform basic security validation
        data = self.parse_and_validate_json(json_string)

        # Determine format version and validate against appropriate schema
        format_version = data.get("format_version")

        if format_version == 3:
            schema_name = "metadata_v3"
        elif format_version == 4:
            schema_name = "metadata_v4"
        elif format_version == 5:
            schema_name = "metadata_v5"
        elif format_version == 6:
            schema_name = "metadata_v6"
        elif format_version == 7:
            schema_name = "metadata_v7"
        else:
            # For unknown versions, perform basic validation without schema
            print(
                f"Warning: Unknown metadata format version {format_version}, skipping schema validation"
            )
            return data

        # Validate against version-specific schema
        self.validate_against_schema(data, schema_name)

        return data

    def validate_config_template(self, json_string: str) -> Dict[str, Any]:
        """
        Validate configuration template JSON.

        Args:
            json_string (str): Configuration template JSON string

        Returns:
            Dict[str, Any]: Validated configuration template

        Raises:
            JSONSecurityError: If JSON violates security constraints
            JSONValidationError: If JSON is malformed or doesn't match schema
        """
        # Parse and perform basic security validation
        data = self.parse_and_validate_json(json_string)

        # Validate against configuration template schema
        self.validate_against_schema(data, "config_template")

        return data

    def validate_keystore(self, json_string: str) -> Dict[str, Any]:
        """
        Validate keystore JSON.

        Args:
            json_string (str): Keystore JSON string

        Returns:
            Dict[str, Any]: Validated keystore data

        Raises:
            JSONSecurityError: If JSON violates security constraints
            JSONValidationError: If JSON is malformed or doesn't match schema
        """
        # Parse and perform basic security validation
        data = self.parse_and_validate_json(json_string)

        # Validate against keystore schema
        self.validate_against_schema(data, "keystore")

        return data


# Global validator instance
_validator_instance = None


def get_json_validator() -> SecureJSONValidator:
    """Get the global JSON validator instance (singleton pattern)."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = SecureJSONValidator()
    return _validator_instance


def secure_json_loads(json_string: str, schema_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Securely load and validate JSON string.

    This is a drop-in replacement for json.loads() with security validation.

    Args:
        json_string (str): JSON string to parse
        schema_name (str, optional): Schema name for validation

    Returns:
        Dict[str, Any]: Parsed and validated JSON data

    Raises:
        JSONSecurityError: If JSON violates security constraints
        JSONValidationError: If JSON is malformed or doesn't match schema
    """
    validator = get_json_validator()
    data = validator.parse_and_validate_json(json_string)

    if schema_name:
        validator.validate_against_schema(data, schema_name)

    return data


def secure_metadata_loads(json_string: str) -> Dict[str, Any]:
    """
    Securely load and validate metadata JSON with version-specific validation.

    Args:
        json_string (str): Metadata JSON string

    Returns:
        Dict[str, Any]: Validated metadata

    Raises:
        JSONSecurityError: If JSON violates security constraints
        JSONValidationError: If JSON is malformed or doesn't match schema
    """
    validator = get_json_validator()
    return validator.validate_metadata(json_string)


def secure_template_loads(json_string: str) -> Dict[str, Any]:
    """
    Securely load and validate configuration template JSON.

    Args:
        json_string (str): Configuration template JSON string

    Returns:
        Dict[str, Any]: Validated configuration template

    Raises:
        JSONSecurityError: If JSON violates security constraints
        JSONValidationError: If JSON is malformed or doesn't match schema
    """
    validator = get_json_validator()
    return validator.validate_config_template(json_string)


def secure_keystore_loads(json_string: str) -> Dict[str, Any]:
    """
    Securely load and validate keystore JSON.

    Args:
        json_string (str): Keystore JSON string

    Returns:
        Dict[str, Any]: Validated keystore data

    Raises:
        JSONSecurityError: If JSON violates security constraints
        JSONValidationError: If JSON is malformed or doesn't match schema
    """
    validator = get_json_validator()
    return validator.validate_keystore(json_string)
