"""Visual analysis: WCAG contrast checking, hidden element detection, LLM vision analysis."""

from __future__ import annotations

import json
import math
from pathlib import Path

from webprobe.llm_provider import LLMProvider, transmogrify_prompt
from webprobe.models import (
    AuthContext,
    NodeCapture,
    SecurityCategory,
    SecurityFinding,
    SecuritySeverity,
)


# ---- WCAG Contrast Checking (computational, no LLM) ----


def _relative_luminance(r: int, g: int, b: int) -> float:
    """Calculate relative luminance per WCAG 2.1 (sRGB linearization)."""
    def _linearize(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4
    return 0.2126 * _linearize(r) + 0.7152 * _linearize(g) + 0.0722 * _linearize(b)


def contrast_ratio(color1: tuple[int, int, int], color2: tuple[int, int, int]) -> float:
    """WCAG 2.1 contrast ratio between two RGB colors."""
    l1 = _relative_luminance(*color1)
    l2 = _relative_luminance(*color2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def check_wcag_aa(ratio: float, large_text: bool = False) -> bool:
    """WCAG AA: 4.5:1 for normal text, 3:1 for large text (>=18pt or >=14pt bold)."""
    return ratio >= (3.0 if large_text else 4.5)


def check_wcag_aaa(ratio: float, large_text: bool = False) -> bool:
    """WCAG AAA: 7:1 for normal text, 4.5:1 for large text."""
    return ratio >= (4.5 if large_text else 7.0)


def _parse_rgb(css_color: str) -> tuple[int, int, int] | None:
    """Parse rgb(r,g,b) or rgba(r,g,b,a) to (r,g,b). Returns None if unparseable."""
    css_color = css_color.strip()
    if css_color.startswith("rgb"):
        # Extract numbers
        import re
        nums = re.findall(r"[\d.]+", css_color)
        if len(nums) >= 3:
            return (int(float(nums[0])), int(float(nums[1])), int(float(nums[2])))
    elif css_color.startswith("#"):
        hex_str = css_color[1:]
        if len(hex_str) == 3:
            hex_str = "".join(c * 2 for c in hex_str)
        if len(hex_str) == 6:
            return (int(hex_str[0:2], 16), int(hex_str[2:4], 16), int(hex_str[4:6], 16))
    return None


# ---- Playwright-based contrast extraction ----

CONTRAST_CHECK_JS = """() => {
    const results = [];
    const textElements = document.querySelectorAll(
        'p, h1, h2, h3, h4, h5, h6, span, a, li, td, th, label, button, input, textarea, div'
    );
    const seen = new Set();
    for (const el of textElements) {
        const text = el.innerText?.trim();
        if (!text || text.length < 2 || seen.has(text.slice(0, 50))) continue;
        seen.add(text.slice(0, 50));
        if (results.length >= 100) break;
        const style = getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue;
        const fontSize = parseFloat(style.fontSize);
        const fontWeight = parseInt(style.fontWeight) || (style.fontWeight === 'bold' ? 700 : 400);
        results.push({
            text: text.slice(0, 80),
            color: style.color,
            backgroundColor: style.backgroundColor,
            fontSize: fontSize,
            fontWeight: fontWeight,
            tagName: el.tagName.toLowerCase(),
        });
    }
    return results;
}"""


HIDDEN_ELEMENTS_JS = """() => {
    const results = [];
    const all = document.querySelectorAll('*');
    for (const el of all) {
        if (results.length >= 50) break;
        const style = getComputedStyle(el);
        const hasContent = el.innerText?.trim() || el.querySelector('img, svg, canvas, video');
        if (!hasContent) continue;
        const isHidden = style.display === 'none' ||
                         style.visibility === 'hidden' ||
                         style.opacity === '0' ||
                         (style.position === 'absolute' && (
                             parseInt(style.left) < -9000 ||
                             parseInt(style.top) < -9000
                         )) ||
                         (el.offsetWidth === 0 && el.offsetHeight === 0 && style.overflow === 'hidden');
        if (isHidden) {
            results.push({
                tagName: el.tagName.toLowerCase(),
                id: el.id || '',
                className: (el.className && typeof el.className === 'string') ? el.className.slice(0, 100) : '',
                text: (el.innerText || '').slice(0, 100),
                reason: style.display === 'none' ? 'display:none' :
                        style.visibility === 'hidden' ? 'visibility:hidden' :
                        style.opacity === '0' ? 'opacity:0' :
                        'offscreen/zero-size',
            });
        }
    }
    return results;
}"""


async def check_contrast_from_page(page: object) -> list[SecurityFinding]:
    """Extract text elements and check WCAG contrast ratios via Playwright page."""
    findings: list[SecurityFinding] = []
    try:
        elements = await page.evaluate(CONTRAST_CHECK_JS)  # type: ignore[attr-defined]
    except Exception:
        return findings

    for el in elements:
        fg = _parse_rgb(el.get("color", ""))
        bg = _parse_rgb(el.get("backgroundColor", ""))
        if not fg or not bg:
            continue
        ratio = contrast_ratio(fg, bg)
        font_size = el.get("fontSize", 16)
        font_weight = el.get("fontWeight", 400)
        large_text = font_size >= 18 or (font_size >= 14 and font_weight >= 700)

        if not check_wcag_aa(ratio, large_text):
            findings.append(SecurityFinding(
                category=SecurityCategory.xss,  # Using closest category; we extend below
                severity=SecuritySeverity.medium,
                title=f"WCAG AA contrast failure ({ratio:.1f}:1)",
                detail=f"Text '{el['text'][:40]}' has insufficient contrast. "
                       f"Foreground: {el['color']}, Background: {el['backgroundColor']}. "
                       f"{'Large' if large_text else 'Normal'} text needs {'3' if large_text else '4.5'}:1.",
                evidence=f"ratio={ratio:.2f}, tag={el['tagName']}, size={font_size}px, weight={font_weight}",
            ))
        elif not check_wcag_aaa(ratio, large_text):
            findings.append(SecurityFinding(
                category=SecurityCategory.xss,
                severity=SecuritySeverity.info,
                title=f"WCAG AAA contrast warning ({ratio:.1f}:1)",
                detail=f"Text '{el['text'][:40]}' passes AA but fails AAA. "
                       f"{'Large' if large_text else 'Normal'} text needs {'4.5' if large_text else '7'}:1 for AAA.",
                evidence=f"ratio={ratio:.2f}, tag={el['tagName']}",
            ))

    return findings


async def detect_hidden_elements(page: object) -> list[SecurityFinding]:
    """Detect elements present in DOM but hidden from view."""
    findings: list[SecurityFinding] = []
    try:
        elements = await page.evaluate(HIDDEN_ELEMENTS_JS)  # type: ignore[attr-defined]
    except Exception:
        return findings

    for el in elements:
        findings.append(SecurityFinding(
            category=SecurityCategory.information_disclosure,
            severity=SecuritySeverity.low,
            title=f"Hidden element: <{el['tagName']}> ({el['reason']})",
            detail=f"Element contains content but is hidden via {el['reason']}. "
                   f"May contain sensitive info or indicate a rendering issue.",
            evidence=f"id={el.get('id', '')}, class={el.get('className', '')[:50]}, "
                     f"text={el.get('text', '')[:60]}",
        ))

    return findings


# ---- LLM Vision Analysis ----

_VISION_SYSTEM = """You are a visual QA analyst examining a website screenshot.
Identify issues that a human tester would notice:
- Layout problems: overlapping elements, misaligned content, broken grids
- Text issues: truncated text, text overflowing containers, unreadable text
- Visual broken elements: missing images (broken image icons), empty containers that look wrong
- Inconsistencies: elements that don't match the visual style of the rest of the page
- Accessibility: tiny click targets, text too small to read

Respond in JSON format as a list of findings:
[{"title": "short description", "detail": "explanation", "severity": "high|medium|low|info", "evidence": "what you see"}]

If the page looks fine, return an empty list: []
Be specific. Only flag things that are clearly wrong, not stylistic preferences."""


async def analyze_screenshot(
    llm: LLMProvider,
    screenshot_path: str | Path,
    url: str,
    auth_context: AuthContext = AuthContext.anonymous,
) -> list[SecurityFinding]:
    """Use LLM vision to analyze a screenshot for visual defects."""
    findings: list[SecurityFinding] = []
    path = Path(screenshot_path)
    if not path.exists():
        return findings

    prompt = await transmogrify_prompt(
        f"Analyze this screenshot of {url}. Identify any visual defects, layout issues, or accessibility problems.",
        llm.model,
    )

    try:
        response = await llm.vision(_VISION_SYSTEM, prompt, path, max_tokens=2048)
        # Parse JSON response
        # Handle markdown code blocks
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()
            if text.startswith("json"):
                text = text[4:].strip()

        items = json.loads(text)
        for item in items:
            sev_map = {
                "high": SecuritySeverity.high,
                "medium": SecuritySeverity.medium,
                "low": SecuritySeverity.low,
                "info": SecuritySeverity.info,
            }
            findings.append(SecurityFinding(
                category=SecurityCategory.information_disclosure,
                severity=sev_map.get(item.get("severity", "low"), SecuritySeverity.low),
                title=f"Visual: {item.get('title', 'Unknown issue')}",
                detail=item.get("detail", ""),
                evidence=item.get("evidence", ""),
                url=url,
                auth_context=auth_context,
            ))
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    except Exception:
        pass

    return findings
