"""Mask system: suppress known/expected findings by URL pattern + finding pattern."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from webprobe.models import SecurityFinding


class MaskRule(BaseModel):
    """A single suppression rule."""

    url_pattern: str = ".*"          # Regex matched against finding URL
    title_pattern: str = ".*"        # Regex matched against finding title
    category: str = ""               # If set, must match finding category
    reason: str = ""                 # Why this is suppressed (documentation)


class MaskConfig(BaseModel):
    """Collection of suppression rules loaded from YAML."""

    rules: list[MaskRule] = Field(default_factory=list)


def load_mask(path: str | Path | None = None) -> MaskConfig:
    """Load mask from YAML file. Returns empty mask if file doesn't exist."""
    if path is None:
        # Check default locations
        for p in [Path("webprobe-mask.yaml"), Path(".webprobe/mask.yaml")]:
            if p.exists():
                path = p
                break
    if path is None:
        return MaskConfig()
    p = Path(path)
    if not p.exists():
        return MaskConfig()
    data = yaml.safe_load(p.read_text()) or {}
    return MaskConfig.model_validate(data)


def apply_mask(findings: list[SecurityFinding], mask: MaskConfig) -> tuple[list[SecurityFinding], list[SecurityFinding]]:
    """Apply mask rules to findings.

    Returns (kept, suppressed) -- both lists for transparency in reports.
    """
    if not mask.rules:
        return findings, []

    kept: list[SecurityFinding] = []
    suppressed: list[SecurityFinding] = []

    for finding in findings:
        masked = False
        for rule in mask.rules:
            url_match = re.search(rule.url_pattern, finding.url) if finding.url else True
            title_match = re.search(rule.title_pattern, finding.title)
            cat_match = (not rule.category) or (rule.category == finding.category.value)
            if url_match and title_match and cat_match:
                masked = True
                break
        if masked:
            suppressed.append(finding)
        else:
            kept.append(finding)

    return kept, suppressed
