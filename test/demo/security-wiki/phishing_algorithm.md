# Phishing Detection Algorithm

## Overview

Our phishing detection system is a SQL-based rules engine that operates over aggregated Cloudflare WAF (Web Application Firewall) logs. It identifies malicious URLs in near real-time by applying pattern-matching rules against known phishing indicators.

The system is intentionally rule-based (not ML-based) to maximize auditability and operator control. Every blocked URL can be traced to a specific rule ID and explained without a model's black box.

---

## Data Pipeline

```
Cloudflare WAF
      │
      │ (raw HTTP events, ~5 min delay)
      ▼
waf_raw_events          ← raw table: one row per HTTP request
      │
      │ (hourly aggregation window)
      ▼
waf_aggregated          ← normalized: (url, rule_id, action) per hour
      │
      │ (detection rules applied)
      ▼
Phishing Detections     ← alerts consumed by SOC / SIEM
```

**Raw data source**: `waf_raw_events` — populated from the Cloudflare WAF firewall logs stream. Each row represents one HTTP request that passed through the WAF, with fields including `url`, `host`, `path`, `client_ip`, `rule_id` (the Cloudflare firewall rule that matched), and `action` (allow / block / challenge).

**Aggregation**: The `waf_aggregated` table rolls up raw events into hourly windows grouped by `(url, rule_id, action)`. This reduces noise and allows the detection rules to work on aggregated counts (`hit_count`, `unique_ips`) rather than individual packets.

---

## Detection Rules

### Rule 1 — Brand Impersonation via Lookalike Domains

**Goal**: Catch domains that visually impersonate trusted brands by substituting characters (e.g., `0` for `o`, `1` for `l`) or appending suspicious keywords.

**Logic**:
- The host must have been blocked by Cloudflare rule `CF_PHISHING_001` or `CF_PHISHING_002`
- The hostname must match a brand impersonation pattern (regex against common substitutions)
- The hostname must contain a suspicious keyword (e.g., `-secure`, `-verify`, `-alert`) AND must NOT end with the legitimate brand domain

**Example**:

> URL: `http://paypa1-secure.login-verify.com/account/verify?token=abc123`

- `paypa1` → matches PayPal lookalike pattern (`paypa[^l]|paypa1`)
- `-secure` → suspicious keyword present
- Host does NOT end in `.paypal.com`
- **Result**: Blocked, classified as `BRAND_IMPERSONATION`, severity `High`

---

### Rule 2 — Credential Harvesting Path Detection

**Goal**: Flag URLs hitting paths commonly used to steal credentials (`/verify`, `/signin`, `/login`, `/account`, `/reset`), combined with a suspicious hostname structure.

**Logic**:
- Request was blocked (`action = 'block'`)
- Path starts with a credential-harvesting endpoint
- Host contains a suspicious pattern: chained TLD-like keywords (e.g., `login-verify.com`) OR an unusually deep subdomain chain (more than 3 levels)

**Example**:

> URL: `http://amaz0n-support.helpdesk-secure.net/signin`

- Path: `/signin` → matches credential harvesting pattern
- Host: `amaz0n-support.helpdesk-secure.net` → contains `-secure.` chain and `amaz0n` substitution
- **Result**: Blocked, classified as `CREDENTIAL_HARVESTING`, severity `Critical`

---

### Rule 3 — Token/Cookie Theft via Query Parameter

**Goal**: Detect URLs where sensitive tokens or user identifiers (tokens, sessions, emails, passwords) appear in the query string of a blocked request — a common pattern in phishing link delivery.

**Logic**:
- Request was blocked
- Query string contains a sensitive parameter name (`token=`, `session=`, `user=`, `email=`, `password=`, `credential=`)
- Host is NOT a legitimate domain (verified allowlist of `.paypal.com`, `.amazon.com`, `.google.com`, `.microsoft.com`, `.apple.com`)

**Example**:

> URL: `http://google-security-alert.com/verify-account?user=victim@example.com`

- Query string: `user=victim@example.com` → matches `user=` sensitive parameter
- Host: `google-security-alert.com` → NOT in the `.google.com` legitimate allowlist
- **Result**: Blocked, classified as `TOKEN_THEFT`, severity `High`

---

## Active Cloudflare Rules Referenced

| Rule ID          | Description                                       | Severity |
|------------------|---------------------------------------------------|----------|
| CF_PHISHING_001  | Lookalike domain pattern match (brand spoofing)   | High     |
| CF_PHISHING_002  | Suspicious TLD chain + credential path            | Critical |

---

## Coverage Summary

| Detection Type        | Rule   | Severity | Example Indicator                              |
|-----------------------|--------|----------|------------------------------------------------|
| Brand Impersonation   | Rule 1 | High     | `paypa1-secure.login-verify.com`               |
| Credential Harvesting | Rule 2 | Critical | `amaz0n-support.helpdesk-secure.net/signin`    |
| Token/Cookie Theft    | Rule 3 | High     | `google-security-alert.com?user=victim@...`    |

---

## Limitations & Known Gaps

- **HTTPS blind spots**: Cloudflare inspection is limited to domains using Cloudflare's SSL termination. Phishing sites on unproxied infrastructure are not covered.
- **No ML scoring**: Rules are static regex patterns. Novel phishing techniques that do not match known patterns will be missed until a new rule is written.
- **Evasion via URL encoding**: Query string obfuscation (e.g., URL-encoded characters) may bypass Rule 3 depending on WAF normalization settings.
- **False positive risk**: Rule 2's deep-subdomain check may flag legitimate services with complex subdomain structures (e.g., internal developer portals).
