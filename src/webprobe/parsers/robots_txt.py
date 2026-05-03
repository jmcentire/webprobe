"""robots.txt parser.

Extracts User-agent groups, Allow/Disallow rules, Sitemap directives,
Crawl-delay, and Content-Signal directives. Exposes a matrix-evaluation
helper used by both the discoverability and bot_access dimensions.

Reference: RFC 9309 (robots.txt) plus emerging Content-Signal extension
(contentsignals.org).
"""

from __future__ import annotations

import re
import time

from webprobe.parsers import ParseResult


# Default AI/search user-agent matrix (CA016). Operators can extend via config.
DEFAULT_AI_USER_AGENT_MATRIX: tuple[str, ...] = (
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "anthropic-ai",
    "PerplexityBot",
    "Google-Extended",
    "Googlebot",
    "Bingbot",
    "Applebot-Extended",
    "Meta-ExternalAgent",
    "CCBot",
    "claude-web",
    "Bytespider",
    "cohere-ai",
)


_DIRECTIVE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*?)\s*$")


def _normalize_lines(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        # Strip comments after '#'
        if "#" in raw:
            raw = raw.split("#", 1)[0]
        line = raw.strip()
        if line:
            out.append(line)
    return out


def parse(raw: bytes | str, *, source_url: str = "") -> ParseResult:
    """Parse a robots.txt payload. Never raises (CO005)."""
    started = time.perf_counter()
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as e:  # pragma: no cover — replace=errors makes this near-impossible
            return ParseResult(ok=False, payload={}, error=f"decode_error: {e!r}")
    else:
        text = raw

    if not text.strip():
        return ParseResult(
            ok=False,
            payload={"groups": [], "sitemaps": [], "content_signals": []},
            error="empty_payload",
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    groups: list[dict] = []
    sitemaps: list[str] = []
    content_signals: list[dict] = []
    warnings: list[str] = []

    current_uas: list[str] = []
    current_rules: list[dict] = []
    crawl_delay: float | None = None

    def flush_group() -> None:
        if current_uas:
            groups.append(
                {
                    "user_agents": list(current_uas),
                    "rules": list(current_rules),
                    "crawl_delay": crawl_delay,
                }
            )

    last_was_ua = False

    for line in _normalize_lines(text):
        m = _DIRECTIVE_RE.match(line)
        if not m:
            warnings.append(f"unparseable_line: {line[:80]!r}")
            continue
        directive = m.group(1).lower()
        value = m.group(2)

        if directive == "user-agent":
            if not last_was_ua and (current_rules or crawl_delay is not None):
                flush_group()
                current_uas = []
                current_rules = []
                crawl_delay = None
            current_uas.append(value)
            last_was_ua = True
        elif directive in ("allow", "disallow"):
            current_rules.append({"action": directive, "path": value})
            last_was_ua = False
        elif directive == "crawl-delay":
            try:
                crawl_delay = float(value)
            except ValueError:
                warnings.append(f"bad_crawl_delay: {value!r}")
            last_was_ua = False
        elif directive == "sitemap":
            sitemaps.append(value)
            last_was_ua = False
        elif directive == "content-signal":
            # Content-Signal: ai-train=no, search=yes, ai-input=no
            entries = {}
            for part in value.split(","):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    entries[k.strip()] = v.strip()
            content_signals.append({"raw": value, "signals": entries})
            last_was_ua = False
        else:
            warnings.append(f"unknown_directive: {directive!r}")
            last_was_ua = False

    flush_group()

    payload = {
        "groups": groups,
        "sitemaps": sitemaps,
        "content_signals": content_signals,
        "source_url": source_url,
    }
    return ParseResult(
        ok=True,
        payload=payload,
        warnings=warnings,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )


def _path_matches(rule_path: str, target_path: str) -> bool:
    """RFC 9309 longest-match path semantics (simplified).

    Empty rule path matches nothing (Allow:) / matches all (Disallow:) per spec.
    Trailing '$' anchors. '*' is a wildcard.
    """
    if rule_path == "":
        # Allow: with empty path matches nothing; Disallow: with empty path
        # matches nothing too (per RFC). Our caller treats both as "no match",
        # which is the correct behavior for evaluate().
        return False
    pattern = re.escape(rule_path).replace(r"\*", ".*")
    if pattern.endswith(r"\$"):
        pattern = pattern[:-2] + "$"
    return re.match("^" + pattern, target_path) is not None


def evaluate(
    payload: dict,
    *,
    user_agent: str,
    target_path: str = "/",
) -> dict:
    """Decide whether a given user-agent is allowed to fetch ``target_path``.

    Returns a dict with:
      - ``decision``: "allow" | "disallow" | "no_rule"
      - ``matched_group``: the User-agent token that matched (most-specific), or None
      - ``matched_rule``: the matching rule dict, or None

    Used by both Discoverability (sitewide allow check) and Bot Access (per-bot matrix).
    """
    groups = payload.get("groups") or []
    ua_lower = user_agent.lower()

    # Match groups: explicit token match wins over '*'. Tokens match case-insensitively
    # via prefix (RFC 9309: User-agents match when the bot's product token starts with
    # the rule's User-agent string, case-insensitive).
    explicit_group = None
    star_group = None
    for g in groups:
        for ua in g.get("user_agents") or []:
            ua_token = ua.strip()
            if ua_token == "*":
                if star_group is None:
                    star_group = (ua_token, g)
                continue
            if ua_lower.startswith(ua_token.lower()):
                explicit_group = (ua_token, g)
                break
        if explicit_group:
            break

    chosen = explicit_group or star_group
    if chosen is None:
        return {"decision": "no_rule", "matched_group": None, "matched_rule": None}

    matched_token, group = chosen

    # Find the longest matching rule. Allow wins ties (RFC 9309 §2.2.2).
    best: tuple[int, dict] | None = None  # (path-length, rule)
    for rule in group.get("rules") or []:
        rp = rule.get("path", "")
        if _path_matches(rp, target_path):
            length = len(rp)
            if best is None or length > best[0] or (
                length == best[0] and rule.get("action") == "allow"
            ):
                best = (length, rule)

    if best is None:
        return {
            "decision": "allow",  # No matching rule = allowed by default
            "matched_group": matched_token,
            "matched_rule": None,
        }
    rule = best[1]
    return {
        "decision": "allow" if rule.get("action") == "allow" else "disallow",
        "matched_group": matched_token,
        "matched_rule": rule,
    }


def evaluate_matrix(
    payload: dict,
    *,
    user_agents: tuple[str, ...] = DEFAULT_AI_USER_AGENT_MATRIX,
    target_path: str = "/",
) -> dict[str, dict]:
    """Evaluate a robots payload against a set of user-agents (CA016).

    Returns ``{user_agent: evaluate(...) result}``. Used by the bot_access
    dimension to produce a single CheckResult that summarizes per-bot status.
    """
    return {ua: evaluate(payload, user_agent=ua, target_path=target_path) for ua in user_agents}
