# === Webprobe Mask System (src_webprobe_mask) v1 ===
#  Dependencies: re, pathlib, yaml, pydantic, webprobe.models
# Mask system for suppressing known or expected security findings by matching URL patterns, title patterns, and categories against configurable rules loaded from YAML files.

# Module invariants:
#   - Default mask file search paths are ['webprobe-mask.yaml', '.webprobe/mask.yaml'] in order
#   - MaskRule default url_pattern and title_pattern is '.*' (matches everything)
#   - MaskRule with empty category string matches any category
#   - apply_mask preserves all findings across (kept, suppressed) partitions
#   - First matching rule suppresses a finding (rules are evaluated in order)

class MaskRule:
    """A single suppression rule with patterns and category matching"""
    url_pattern: str = .*                    # optional, Regex pattern matched against finding URL
    title_pattern: str = .*                  # optional, Regex pattern matched against finding title
    category: str = None                     # optional, If set, must match finding category exactly
    reason: str = None                       # optional, Documentation explaining why this finding is suppressed

class MaskConfig:
    """Collection of suppression rules loaded from YAML configuration"""
    rules: list[MaskRule] = []               # optional, List of mask rules to apply

def load_mask(
    path: str | Path | None = None,
) -> MaskConfig:
    """
    Load mask configuration from a YAML file. Searches default locations if path is None. Returns empty MaskConfig if file doesn't exist or path is invalid.

    Postconditions:
      - Returns valid MaskConfig instance (never None)
      - If path is None and no default files exist, returns empty MaskConfig with empty rules list
      - If specified path doesn't exist, returns empty MaskConfig with empty rules list
      - If file exists and is valid YAML, returns MaskConfig with parsed rules

    Errors:
      - yaml_parse_error (yaml.YAMLError): YAML file contains invalid syntax
      - pydantic_validation_error (pydantic.ValidationError): YAML structure doesn't match MaskConfig schema
      - file_read_error (OSError): File exists but cannot be read (permissions, encoding issues)

    Side effects: Reads from filesystem
    Idempotent: yes
    """
    ...

def apply_mask(
    findings: list[SecurityFinding],
    mask: MaskConfig,
) -> tuple[list[SecurityFinding], list[SecurityFinding]]:
    """
    Apply mask rules to a list of security findings, splitting them into kept and suppressed lists. Matches findings against rules using regex patterns for URL and title, and exact match for category.

    Preconditions:
      - findings is a list (may be empty)
      - mask is a valid MaskConfig instance
      - Each finding has url (optional), title (required), and category attributes

    Postconditions:
      - Returns tuple of (kept_findings, suppressed_findings)
      - kept_findings + suppressed_findings contains all original findings (no loss)
      - No finding appears in both kept and suppressed lists (mutually exclusive)
      - If mask.rules is empty, returns (findings, [])
      - A finding is suppressed if ANY rule matches all conditions (url_pattern AND title_pattern AND category)
      - If finding.url is None, url_pattern check is treated as True (match)

    Errors:
      - regex_error (re.error): url_pattern or title_pattern contains invalid regex syntax
      - attribute_error (AttributeError): SecurityFinding missing required attributes (url, title, category)

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['MaskRule', 'MaskConfig', 'load_mask', 'apply_mask']
