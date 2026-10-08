-- =============================================================================
-- phishing.sql
-- Purpose: Phishing detection rules applied over the 30-day aggregated tables.
--          Three complementary rules cover the main phishing vectors observed
--          in gateway/WAF telemetry: lookalike domains, credential harvesting
--          paths, and token/session theft via query parameters.
-- Sources: bodyguard_demo.domains_30d, bodyguard_demo.urls_30d
-- Owner:   brand-protection-team  (Slack: #brand-protection)
-- Dialect: BigQuery Standard SQL. Run with:
--          bq query --use_legacy_sql=false --project_id=<project> < phishing.sql
-- =============================================================================

-- =============================================================================
-- RULE 1 — Brand Impersonation via Lookalike Domains
--
-- Detects domains that visually impersonate protected brands using character
-- substitution (paypa1, amaz0n, micr0soft) or by appending trust keywords
-- (-secure, -verify, -alert, -helpdesk, -support).
--
-- Signal: typosquatting_score >= 0.7 AND impersonated_brand IS NOT NULL
--         AND has_suspicious_kw AND domain is NOT the real brand domain.
--
-- Example hit:
--   domain: paypa1-secure.login-verify.com
--   brand:  PayPal  |  score: 0.92  |  blocked: 840 / 842 requests
-- =============================================================================
SELECT
    d.window_start,
    d.domain,
    d.impersonated_brand,
    d.typosquatting_score,
    d.visits,
    d.blocked_count,
    d.unique_ips,
    d.top_country,
    d.domain_age_days,
    'BRAND_IMPERSONATION'   AS detection_type,
    'High'                  AS severity
FROM bodyguard_demo.domains_30d AS d
WHERE
    d.typosquatting_score  >= 0.7
    AND d.impersonated_brand IS NOT NULL
    AND d.has_suspicious_kw  = TRUE
    -- Exclude the real brand domains
    AND NOT REGEXP_CONTAINS(d.domain, r'(?i)\.(paypal|amazon|google|microsoft|apple|docusign)\.com$')
ORDER BY d.window_start DESC, d.typosquatting_score DESC;


-- =============================================================================
-- RULE 2 — Credential Harvesting via Phishing Paths
--
-- Flags blocked URL requests hitting paths commonly used to steal credentials
-- (/verify, /signin, /login, /reset-password, /confirm) on domains that score
-- as brand lookalikes.
--
-- Signal: suspicious path + typosquatting domain (score >= 0.5).
--
-- Example hit:
--   url:  http://amaz0n-support.helpdesk-secure.net/signin
--   path: /signin  |  blocked: 1199 / 1203 requests  |  severity: Critical
-- =============================================================================
SELECT
    u.window_start,
    u.url,
    u.host,
    u.path,
    u.blocked_count,
    u.unique_ips,
    u.top_country,
    d.impersonated_brand,
    d.typosquatting_score,
    'CREDENTIAL_HARVESTING'  AS detection_type,
    'Critical'               AS severity
FROM bodyguard_demo.urls_30d    AS u
JOIN bodyguard_demo.domains_30d AS d
  ON d.domain = u.host AND d.window_start = u.window_start
WHERE
    u.action = 'block'
    AND REGEXP_CONTAINS(u.path, r'(?i)^/(verify|signin|login|account|reset-password|reset|confirm|update-password)')
    AND d.typosquatting_score >= 0.5
ORDER BY u.window_start DESC, u.blocked_count DESC;


-- =============================================================================
-- RULE 3 — Token / Session Theft via Sensitive Query Parameters
--
-- Detects blocked requests where sensitive identifiers (token, session, email,
-- password, credential, user) appear in the query string of a domain that is
-- neither a protected brand nor one of our own properties. Classic phishing
-- link delivery pattern; also the rule that catches generic (non-brand)
-- credential phishing that Rule 1 scores too low.
--
-- Signal: has_sensitive_params = TRUE + block action + not an allowlisted host.
--
-- Example hit:
--   url:   http://micr0soft-account-verify.net/reset-password?token=xyz789&email=user@corp.example
--   params: token + email  |  severity: High
-- =============================================================================
SELECT
    u.window_start,
    u.url,
    u.host,
    u.path,
    u.query_string,
    u.blocked_count,
    u.unique_ips,
    u.top_country,
    'TOKEN_THEFT'  AS detection_type,
    'High'         AS severity
FROM bodyguard_demo.urls_30d AS u
WHERE
    u.action = 'block'
    AND u.has_sensitive_params = TRUE
    -- Exclude protected brands and our own properties
    AND NOT REGEXP_CONTAINS(u.host, r'(?i)\.(paypal|amazon|google|microsoft|apple|docusign|icloud|example)\.com$')
ORDER BY u.window_start DESC, u.blocked_count DESC;
