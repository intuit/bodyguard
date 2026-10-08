# Web Application Attack Coverage

**Owner:** appsec-team (Slack: #appsec)
**Audience:** Security leadership, quarterly risk review
**Last reviewed:** 2025-06-30
**Applies to:** `web_attack.sql`

## Summary

The AppSec detection layer sits on top of the WAF managed rules and produces SIEM-ready incidents for the OWASP categories most relevant to `portal.example.com`. Coverage has been complete for the four categories below since the 2025-Q2 hardening programme.

| Category | Status | Rule | Severity | Notes |
|---|---|---|---|---|
| Cross-Site Scripting (XSS) | Covered | Rule 1 | High | Reflected, stored and DOM-based variants |
| Layer 7 DDoS / HTTP flood | Covered | Rule 2, Rule 2b | Critical | Rule 2b covers Tor-sourced floods (added after the 2025-Q1 incident) |
| SQL Injection (SQLi) | Covered | Rule 3 | Critical | Boolean, UNION, time-based blind and stacked queries |
| Vulnerability scanning | Covered | Rule 4 | Medium | Correlates `CF_SCANNER_001` blocks with path diversity |

---

## Thresholds

| Rule | Threshold | Rationale |
|---|---|---|
| Rule 2 (DDoS) | > 500 requests / hour, > 90 % blocked | Lowered from 1000 req/h in 2025-Q2 to catch distributed low-and-slow floods |
| Rule 2b (Tor DDoS) | > 200 requests / hour from a Tor exit | Tor exits aggregate many clients, so a lower bar is appropriate |
| Rule 4 (Scanning) | > 100 distinct paths in 24 h with > 90 % blocked | Distinguishes scanners from broken crawlers |

---

## Detection Details

### Rule 1 — XSS

Matches script tags, `javascript:` URIs and event-handler injection in the path or query string, including URL-encoded variants. DOM-based XSS is detected through the same signatures applied to fragment identifiers.

### Rule 2 / 2b — DDoS

Flags source IPs with a sustained abnormal request rate, near-total block rate and minimal path diversity. Browser User-Agents are excluded. Rule 2b applies the same logic to Tor exit nodes with the lower threshold above.

### Rule 3 — SQLi

Matches quotes and comment sequences, boolean conditions, `UNION … SELECT`, time-based probes (`SLEEP`, `WAITFOR`, `BENCHMARK`), data-modifying keywords and stacked queries (`;` followed by a statement).

### Rule 4 — Vulnerability Scanning

Correlates the WAF's `CF_SCANNER_001` managed rule with source-IP path diversity from `ip_30d`. Authorised scanners are excluded via the red-team allowlist.

---

## Known Gaps

- WebSocket traffic is not inspected.
- Attacks inside JSON request bodies are only visible when the WAF managed rule fires; the detection rules themselves inspect URL and query string only.
