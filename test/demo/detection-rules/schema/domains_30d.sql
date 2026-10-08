-- =============================================================================
-- domains_30d.sql
-- Table:   bodyguard_demo.domains_30d
-- Source:  Cloudflare Gateway + WAF logs, WHOIS enrichment, brand-similarity
--          scoring against the protected-brand list.
-- Purpose: Daily aggregation of domain-level activity over a rolling 30-day
--          window. One row per (domain, daily window). Enriched with WHOIS
--          metadata and a typosquatting score.
-- Refresh: Daily
-- Sample:  The INSERT below is the most recent daily window only. The deployed
--          table holds 30 windows; young phishing domains appear only from
--          their registration day onwards.
-- =============================================================================

CREATE TABLE IF NOT EXISTS bodyguard_demo.domains_30d (
    window_start            TIMESTAMP   NOT NULL,
    window_end              TIMESTAMP   NOT NULL,
    domain                  STRING      NOT NULL,
    tld                     STRING,                 -- top-level domain (com, net, ru …)
    visits                  INT64,                  -- total HTTP requests in window
    unique_ips              INT64,                  -- distinct source IPs
    blocked_count           INT64,                  -- WAF-blocked requests
    allowed_count           INT64,                  -- WAF-allowed requests
    top_user_agent          STRING,                 -- most frequent User-Agent
    top_asn                 STRING,                 -- most frequent source ASN
    top_country             STRING,                 -- most frequent source country (ISO-2)
    impersonated_brand      STRING,                 -- brand this domain imitates (NULL if none)
    subdomain_depth         INT64,                  -- max observed subdomain depth
    has_suspicious_kw       BOOL,                   -- hostname contains: -secure -verify -login -helpdesk -alert -update -support
    domain_age_days         INT64,                  -- days since registration (WHOIS)
    typosquatting_score     FLOAT64,                -- 0.0 = no brand match, 1.0 = exact brand lookalike
    entropy                 FLOAT64,                -- Shannon entropy of the domain label
    registrar               STRING,
    PRIMARY KEY (window_start, domain) NOT ENFORCED
);

-- =============================================================================
-- Sample data (last daily window) — phishing, malware infrastructure,
-- authorised red-team simulation, and legitimate traffic.
-- =============================================================================

INSERT INTO bodyguard_demo.domains_30d VALUES
-- ── Phishing — brand impersonation ───────────────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'paypa1-secure.login-verify.com',        'com',  842,  214,  840,    2,
 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0', 'AS64504 Nordlys Networks', 'RU',
 'PayPal',    3, TRUE,  2,  0.92, 4.21, 'Namecheap'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'amaz0n-support.helpdesk-secure.net',    'net',  1203, 389,  1199,   4,
 'python-requests/2.28',                  'AS64496 NimbusHost Cloud', 'DE',
 'Amazon',    2, TRUE,  1,  0.88, 3.95, 'GoDaddy'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'google-security-alert.com',             'com',  670,  178,  668,    2,
 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 'AS64504 Nordlys Networks', 'UA',
 'Google',    1, TRUE,  3,  0.85, 3.64, 'Reg.ru'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'micr0soft-account-verify.net',          'net',  514,  143,  512,    2,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 'AS64501 Helix Hosting', 'FR',
 'Microsoft', 1, TRUE,  4,  0.90, 3.87, 'OVH'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'apple-id-suspended.support-verify.com', 'com',  389,  102,  387,    2,
 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) Safari/604.1', 'AS64496 NimbusHost Cloud', 'CN',
 'Apple',     3, TRUE,  1,  0.87, 4.10, 'NameSilo'),

-- Generic bank phishing: suspicious keywords but no protected brand → score
-- stays below the Rule 1 threshold. Caught by Rule 3 (token theft) instead.
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'secure-netbank-account-update.info',    'info', 291,  88,   289,    2,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 'AS64501 Helix Hosting', 'RO',
 NULL,        2, TRUE,  2,  0.41, 4.55, 'Namecheap'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'invoice-payment.docusign-secure.com',   'com',  178,  54,   176,    2,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 'AS64496 NimbusHost Cloud', 'NL',
 'DocuSign',  2, TRUE,  5,  0.83, 4.33, 'Namecheap'),

-- ── Malware infrastructure ───────────────────────────────────────────────────
-- C2 domain: every request allowed — the WAF has no signature for it.
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'cdn-update.analytics-track.ru',         'ru',   8031, 2,    0,      8031,
 'Go-http-client/2.0',                    'AS64498 OceanDrop Cloud',  'RU',
 NULL,        2, FALSE, 5,  0.05, 3.72, 'Regtime'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'download-win32-patch.update-now.net',   'net',  934,  311,  914,    20,
 'NSIS/3.0 (Windows NT)',                 'AS64501 Helix Hosting',    'US',
 NULL,        2, TRUE,  3,  0.15, 4.44, 'Namecheap'),

-- ── Authorised red-team phishing simulation (REDTEAM.md) ─────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'phishsim.company-test.com',             'com',  640,  118,  612,    28,
 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/128.0', 'AS64500 Example Corp', 'US',
 NULL,        1, FALSE, 412, 0.30, 3.90, 'MarkMonitor'),

-- ── Own property under attack (inbound WAF) ──────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'portal.example.com',                    'com',  221870, 6100, 160480, 61390,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 'AS64500 Example Corp', 'US',
 NULL,        1, FALSE, 3200, 0.00, 3.10, 'MarkMonitor'),

-- ── Legitimate third-party traffic (control) ─────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'login.microsoftonline.com',             'com',  98420, 4820, 12,     98408,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 'AS8075 Microsoft', 'US',
 NULL,        2, FALSE, 4015, 0.02, 2.98, 'MarkMonitor'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'download.microsoft.com',                'com',  15200, 3300, 0,      15200,
 'Microsoft-Delivery-Optimization/10.0',  'AS8075 Microsoft',         'US',
 NULL,        1, FALSE, 9800, 0.01, 3.05, 'MarkMonitor'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'www.amazon.com',                        'com',  241300, 12400, 8,   241292,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 'AS16509 Amazon', 'US',
 NULL,        1, FALSE, 9490, 0.01, 2.72, 'MarkMonitor');
