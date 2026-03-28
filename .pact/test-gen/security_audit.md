# Security Audit Report

**Generated:** 2026-03-27T19:41:56.952675

## Summary

- Critical: 2
- High: 1
- Medium: 0
- Low: 0
- Info: 0
- **Total: 3**

## CRITICAL (2)

- **_compute_graph_metrics** (src/webprobe/analyzer.py:34) [NOT COVERED]
  - Pattern: variable: root
  - Complexity: 6
  - Suggestion: Ensure branch on 'root' is tested with both truthy and falsy values
- **parse_sitemap** (src/webprobe/mapper.py:125) [NOT COVERED]
  - Pattern: variable: root
  - Complexity: 9
  - Suggestion: Ensure branch on 'root' is tested with both truthy and falsy values

## HIGH (1)

- **new_context** (src/webprobe/browser.py:23) [NOT COVERED]
  - Pattern: variable: auth
  - Complexity: 4
  - Suggestion: Ensure branch on 'auth' is tested with both truthy and falsy values
