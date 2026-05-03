"""Accessibility dimension analyzer (Dimension 8).

v1 strategy: read axe-core results when present (stored as a `well_known`
artifact with synthetic URL `<base>#axe_core`), plus DOM/meta_tags artifacts
for stand-alone checks. The runtime layer (Playwright) injects axe-core
and writes the artifact; this analyzer just interprets results.

v1 checks (10, all mechanical except keyboard_focus_indicators which is runtime):

  accessibility.axe_violations_critical
  accessibility.axe_violations_serious
  accessibility.axe_violations_moderate
  accessibility.color_contrast        (uses existing visual.py contrast logic)
  accessibility.alt_text_present
  accessibility.heading_order
  accessibility.aria_roles_valid
  accessibility.form_labels_present
  accessibility.keyboard_focus_indicators (runtime)
  accessibility.lang_attribute_present
"""

from __future__ import annotations

import time

from webprobe.artifact_store import ArtifactStore
from webprobe.models import (
    Artifact,
    ArtifactRef,
    ArtifactType,
    CaptureStatus,
    CheckMode,
    CheckResult,
    CheckSeverity,
    CheckStatus,
    DimensionId,
    Fix,
    FixActionType,
    HttpExchange,
    Reference,
    RuntimeProbe,
)


DIMENSION = DimensionId.accessibility
_NUM_CHECKS = 10
_W = 1.0 / _NUM_CHECKS

_WCAG_REF = Reference(label="WCAG 2.1", url="https://www.w3.org/TR/WCAG21/")
_AXE_REF = Reference(label="axe-core rules", url="https://dequeuniversity.com/rules/axe/")


def _axe_artifact(store: ArtifactStore, base_url: str) -> Artifact | None:
    return store.find(ArtifactType.well_known, base_url + "#axe_core")


def _meta(store: ArtifactStore, url: str) -> Artifact | None:
    return store.find(ArtifactType.meta_tags, url)


def _ref(art: Artifact, excerpt: str = "") -> ArtifactRef:
    return ArtifactRef(artifact_id=art.artifact_id, excerpt=excerpt)


def _axe_violations_by_impact(art: Artifact) -> dict[str, list[dict]]:
    """Group axe-core violations by impact level."""
    payload = art.payload or {}
    violations = payload.get("violations") or []
    by_impact: dict[str, list[dict]] = {}
    for v in violations:
        if not isinstance(v, dict):
            continue
        impact = v.get("impact", "minor")
        by_impact.setdefault(impact, []).append(v)
    return by_impact


def _axe_severity_check(impact: str, severity: CheckSeverity, store: ArtifactStore, url: str) -> CheckResult:
    """Generic shape: count axe violations at the given impact level. PASS if 0."""
    cid = f"accessibility.axe_violations_{impact}"
    title = f"axe-core {impact} violations"
    goal = f"Zero axe-core {impact} violations"
    art = _axe_artifact(store, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id=cid, title=title, goal=goal,
            status=CheckStatus.not_detected, severity=severity, mode=CheckMode.mechanical, weight=_W,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=url, status=None),
            reason="artifact_unavailable:axe_core:not_run",
        )
    by_impact = _axe_violations_by_impact(art)
    violations = by_impact.get(impact, [])
    if not violations:
        return CheckResult(
            dimension=DIMENSION, check_id=cid, title=title, goal=goal,
            status=CheckStatus.pass_, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
            evidence=_ref(art, f"0 {impact} violations"),
        )
    rule_ids = sorted({v.get("id", "") for v in violations})[:5]
    return CheckResult(
        dimension=DIMENSION, check_id=cid, title=title, goal=goal,
        status=CheckStatus.fail, severity=severity, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, f"{len(violations)} violation(s); rules: {rule_ids}"),
        fix=Fix(
            action_type=FixActionType.other, target=url,
            payload={"axe_rule_ids": rule_ids, "violation_count": len(violations), "impact": impact},
            summary=f"Fix {len(violations)} axe-core {impact} violation(s) ({rule_ids})",
            references=[_AXE_REF, _WCAG_REF],
        ),
    )


def check_axe_violations_critical(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_severity_check("critical", CheckSeverity.critical, store, url)


def check_axe_violations_serious(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_severity_check("serious", CheckSeverity.warning, store, url)


def check_axe_violations_moderate(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_severity_check("moderate", CheckSeverity.suggestion, store, url)


def check_color_contrast(store: ArtifactStore, url: str) -> CheckResult:
    """Look at axe-core's color-contrast rule outcome (WCAG 1.4.3)."""
    art = _axe_artifact(store, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id="accessibility.color_contrast",
            title="Color contrast (WCAG 1.4.3)",
            goal="No axe-core color-contrast violations",
            status=CheckStatus.not_detected, severity=CheckSeverity.warning, mode=CheckMode.mechanical, weight=_W,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=url, status=None),
            reason="artifact_unavailable:axe_core:not_run",
        )
    payload = art.payload or {}
    violations = payload.get("violations") or []
    contrast = [v for v in violations if v.get("id") == "color-contrast"]
    if not contrast:
        return CheckResult(
            dimension=DIMENSION, check_id="accessibility.color_contrast",
            title="Color contrast (WCAG 1.4.3)",
            goal="No axe-core color-contrast violations",
            status=CheckStatus.pass_, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
            evidence=_ref(art, "no color-contrast violations"),
        )
    nodes = []
    for v in contrast:
        nodes.extend(v.get("nodes") or [])
    return CheckResult(
        dimension=DIMENSION, check_id="accessibility.color_contrast",
        title="Color contrast (WCAG 1.4.3)",
        goal="No axe-core color-contrast violations",
        status=CheckStatus.fail, severity=CheckSeverity.warning, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, f"{len(nodes)} contrast violation(s)"),
        fix=Fix(action_type=FixActionType.other, target=url,
                payload={"node_count": len(nodes)},
                summary="Increase contrast ratio of foreground vs background to ≥4.5:1 (large text 3:1)",
                references=[_AXE_REF, _WCAG_REF]),
    )


def _axe_rule_check(check_id: str, title: str, goal: str, rule_ids: list[str],
                    store: ArtifactStore, url: str, severity: CheckSeverity) -> CheckResult:
    art = _axe_artifact(store, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
            status=CheckStatus.not_detected, severity=severity, mode=CheckMode.mechanical, weight=_W,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=url, status=None),
            reason="artifact_unavailable:axe_core:not_run",
        )
    violations = (art.payload or {}).get("violations") or []
    matched = [v for v in violations if v.get("id") in rule_ids]
    if not matched:
        return CheckResult(
            dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
            status=CheckStatus.pass_, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
            evidence=_ref(art, f"no {rule_ids} violations"),
        )
    return CheckResult(
        dimension=DIMENSION, check_id=check_id, title=title, goal=goal,
        status=CheckStatus.fail, severity=severity, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, f"{len(matched)} violation(s) matching {rule_ids}"),
        fix=Fix(action_type=FixActionType.other, target=url,
                payload={"axe_rules": rule_ids, "violation_count": len(matched)},
                summary=f"Fix axe rules: {rule_ids}",
                references=[_AXE_REF, _WCAG_REF]),
    )


def check_alt_text_present(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_rule_check("accessibility.alt_text_present",
                           "Image alt text (WCAG 1.1.1)",
                           "all images have alt attributes",
                           ["image-alt", "input-image-alt", "area-alt"],
                           store, url, CheckSeverity.warning)


def check_heading_order(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_rule_check("accessibility.heading_order",
                           "Heading order (WCAG 1.3.1)",
                           "headings used in semantic order",
                           ["heading-order", "empty-heading", "page-has-heading-one"],
                           store, url, CheckSeverity.suggestion)


def check_aria_roles_valid(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_rule_check("accessibility.aria_roles_valid",
                           "ARIA roles valid (WCAG 4.1.2)",
                           "all aria-* attributes are valid",
                           ["aria-valid-attr", "aria-valid-attr-value", "aria-allowed-attr", "aria-roles"],
                           store, url, CheckSeverity.warning)


def check_form_labels_present(store: ArtifactStore, url: str) -> CheckResult:
    return _axe_rule_check("accessibility.form_labels_present",
                           "Form labels (WCAG 3.3.2)",
                           "form controls have associated labels",
                           ["label", "form-field-multiple-labels", "select-name"],
                           store, url, CheckSeverity.warning)


def check_keyboard_focus_indicators(store: ArtifactStore, url: str, mode: str) -> CheckResult:
    """Runtime: focusable elements show visible focus. Read from axe-core when available;
    otherwise NOT_DETECTED."""
    art = _axe_artifact(store, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id="accessibility.keyboard_focus_indicators",
            title="Keyboard focus indicators (WCAG 2.4.7)",
            goal="focusable elements show visible focus",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion,
            mode=CheckMode.runtime, weight=_W,
            evidence=RuntimeProbe(url=url, action="check_focus_indicators", observation={}),
            reason="artifact_unavailable:axe_core:not_run",
        )
    violations = (art.payload or {}).get("violations") or []
    matched = [v for v in violations if v.get("id") in ("focus-order-semantics", "tabindex")]
    if not matched:
        return CheckResult(
            dimension=DIMENSION, check_id="accessibility.keyboard_focus_indicators",
            title="Keyboard focus indicators (WCAG 2.4.7)",
            goal="focusable elements show visible focus",
            status=CheckStatus.pass_, severity=CheckSeverity.info, mode=CheckMode.runtime, weight=_W,
            evidence=_ref(art, "no focus-related violations"),
        )
    return CheckResult(
        dimension=DIMENSION, check_id="accessibility.keyboard_focus_indicators",
        title="Keyboard focus indicators (WCAG 2.4.7)",
        goal="focusable elements show visible focus",
        status=CheckStatus.fail, severity=CheckSeverity.suggestion, mode=CheckMode.runtime, weight=_W,
        evidence=_ref(art, f"{len(matched)} focus-related violation(s)"),
        fix=Fix(action_type=FixActionType.other, target=url,
                payload={"axe_rules": ["focus-order-semantics", "tabindex"]},
                summary="Ensure focusable elements have visible focus indicators and logical tab order",
                references=[_AXE_REF, _WCAG_REF]),
    )


def check_lang_attribute_present(store: ArtifactStore, url: str) -> CheckResult:
    art = _meta(store, url)
    if art is None or art.capture_status != CaptureStatus.ok:
        return CheckResult(
            dimension=DIMENSION, check_id="accessibility.lang_attribute_present",
            title="<html lang> attribute (WCAG 3.1.1)",
            goal="<html lang='...'> declared",
            status=CheckStatus.not_detected, severity=CheckSeverity.suggestion, mode=CheckMode.mechanical, weight=_W,
            evidence=ArtifactRef(artifact_id=art.artifact_id, excerpt=art.capture_error) if art is not None else HttpExchange(method="GET", url=url, status=None),
            reason="artifact_unavailable:meta_tags:not_captured",
        )
    lang = (art.payload or {}).get("lang", "")
    if lang:
        return CheckResult(
            dimension=DIMENSION, check_id="accessibility.lang_attribute_present",
            title="<html lang> attribute (WCAG 3.1.1)",
            goal="<html lang='...'> declared",
            status=CheckStatus.pass_, severity=CheckSeverity.info, mode=CheckMode.mechanical, weight=_W,
            evidence=_ref(art, f"lang={lang}"),
        )
    return CheckResult(
        dimension=DIMENSION, check_id="accessibility.lang_attribute_present",
        title="<html lang> attribute (WCAG 3.1.1)",
        goal="<html lang='...'> declared",
        status=CheckStatus.fail, severity=CheckSeverity.suggestion, mode=CheckMode.mechanical, weight=_W,
        evidence=_ref(art, "missing"),
        fix=Fix(action_type=FixActionType.add_meta_tag, target=url,
                payload={"attribute": "lang", "element": "html"},
                summary="Add lang attribute to <html> (e.g. <html lang='en'>)",
                references=[_WCAG_REF]),
    )


class AccessibilityAnalyzer:
    name: str = DIMENSION.value
    mode_class: CheckMode = CheckMode.runtime  # axe-core needs Playwright; meta-tag check works without
    depends_on_analyzers: tuple[str, ...] = ()

    async def run(
        self,
        store: ArtifactStore,
        *,
        mode: str = "full",
        prior_results: list[CheckResult] | None = None,
        config: dict | None = None,
    ) -> list[CheckResult]:
        config = config or {}
        url = config.get("base_url") or ""
        t0 = time.perf_counter()
        results = [
            check_axe_violations_critical(store, url),
            check_axe_violations_serious(store, url),
            check_axe_violations_moderate(store, url),
            check_color_contrast(store, url),
            check_alt_text_present(store, url),
            check_heading_order(store, url),
            check_aria_roles_valid(store, url),
            check_form_labels_present(store, url),
            check_keyboard_focus_indicators(store, url, mode),
            check_lang_attribute_present(store, url),
        ]
        elapsed = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r.elapsed_ms = max(r.elapsed_ms, elapsed / len(results))
        return results


__all__ = ["DIMENSION", "AccessibilityAnalyzer"]
