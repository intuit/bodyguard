-- =============================================================================
-- ip_30d.sql
-- Table:   bodyguard_demo.ip_30d
-- Source:  Cloudflare Gateway + WAF logs, enriched at aggregation time with the
--          IP reputation feeds (see ip_reputation.sql for feed provenance).
-- Purpose: Daily aggregation of source-IP behaviour over a rolling 30-day
--          window. One row per (client_ip, daily window). Carries the
--          behavioural signals the detection rules key on: request rate, path
--          diversity, error/block rate, HTTP method, user agent, and the most
--          contacted host.
-- Refresh: Daily (window_start = 00:00 UTC, window_end = 23:59:59 UTC)
-- Sample:  The INSERT below is the most recent daily window only. The deployed
--          table holds 30 windows.
-- =============================================================================

CREATE TABLE IF NOT EXISTS bodyguard_demo.ip_30d (
    window_start            TIMESTAMP   NOT NULL,
    window_end              TIMESTAMP   NOT NULL,
    client_ip               STRING      NOT NULL,   -- source IPv4 as seen by the edge
    visits                  INT64,                  -- total requests in window
    unique_domains          INT64,                  -- distinct target hosts
    unique_paths            INT64,                  -- distinct paths hit
    blocked_count           INT64,                  -- WAF-blocked requests
    top_asn                 STRING,                 -- most frequent ASN
    top_country             STRING,                 -- most frequent source country (ISO-2)
    top_user_agent          STRING,                 -- most frequent User-Agent
    top_host                STRING,                 -- most contacted host (joins urls_30d.host)
    is_tor_exit             BOOL,                   -- known Tor exit node (from ip_reputation)
    is_vpn                  BOOL,                   -- known VPN/proxy exit (from ip_reputation)
    is_datacenter           BOOL,                   -- datacenter/cloud range (from ip_reputation)
    request_rate_per_h      FLOAT64,                -- avg requests per hour
    top_http_method         STRING,                 -- most used HTTP method
    error_rate              FLOAT64,                -- fraction of 4xx/5xx responses
    avg_payload_bytes       INT64,                  -- average request body size
    PRIMARY KEY (window_start, client_ip) NOT ENFORCED
);

-- =============================================================================
-- Sample data (last daily window) — attackers, C2 clients, scanners, bots,
-- authorised red team, monitoring, and legitimate users.
-- All addresses are RFC 5737 documentation ranges; ASNs are RFC 5398
-- documentation numbers with fictional operator names.
-- =============================================================================

INSERT INTO bodyguard_demo.ip_30d VALUES
-- ── Phishing campaign operators ──────────────────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.17',    842,  7,  12,  840,
 'AS64504 Nordlys Networks',   'RU', 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0',
 'paypa1-secure.login-verify.com',
 TRUE,  FALSE, FALSE,  35.1, 'GET',  0.97, 512),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.88',    1203, 3,   8,  1199,
 'AS64496 NimbusHost Cloud',   'DE', 'python-requests/2.28',
 'amaz0n-support.helpdesk-secure.net',
 FALSE, FALSE, TRUE,   50.1, 'POST', 0.93, 1024),

-- ── C2 beaconing clients (infected hosts checking in) ────────────────────────
-- 198.51.100.23 is also flagged malware_c2 by the reputation feed, while
-- 198.51.100.77 is unknown to every feed — behaviour is the only signal.
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '198.51.100.23',   4821, 1,   2,     0,
 'AS64498 OceanDrop Cloud',    'US', 'Go-http-client/2.0',
 'cdn-update.analytics-track.ru',
 FALSE, FALSE, TRUE,  200.9, 'POST', 0.01, 256),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '198.51.100.77',   3210, 1,   2,     0,
 'AS64498 OceanDrop Cloud',    'SG', 'Go-http-client/2.0',
 'cdn-update.analytics-track.ru',
 FALSE, FALSE, TRUE,  133.8, 'POST', 0.02, 256),

-- ── Web attackers against portal.example.com (XSS / SQLi) ────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '192.0.2.140',     312,  1,  89,   310,
 'AS64499 ShadowRoute VPN',    'BR', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
 'portal.example.com',
 FALSE, TRUE,  FALSE,  13.0, 'GET',  0.97, 420),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '192.0.2.66',      234,  1,  62,   234,
 'AS64502 Meridian Broadband', 'CN', 'sqlmap/1.7 (https://sqlmap.org)',
 'portal.example.com',
 FALSE, FALSE, FALSE,   9.8, 'GET',  1.00, 380),

-- ── DDoS bots (Layer 7 flood) ────────────────────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.200',   98420, 1,  3, 98418,
 'AS64497 EastBridge Telecom', 'CN', 'curl/7.68.0',
 'portal.example.com',
 FALSE, FALSE, FALSE, 4100.8, 'GET', 0.99, 64),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.201',   54310, 1,  2, 54308,
 'AS64505 Kestrel Telecom',    'JP', 'curl/7.74.0',
 'portal.example.com',
 FALSE, FALSE, FALSE, 2263.0, 'GET', 0.98, 64),

-- ── Malware distribution — hosts pulling droppers ────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '198.51.100.9',    934,  1,  14,   914,
 'AS64501 Helix Hosting',      'NL', 'NSIS/3.0 (Windows NT)',
 'download-win32-patch.update-now.net',
 FALSE, FALSE, TRUE,   38.9, 'GET',  0.02, 8192),

-- ── Vulnerability scanners ───────────────────────────────────────────────────
-- Two scanners with near-identical behaviour. 198.51.100.50 is the internal red
-- team (authorised, listed in REDTEAM.md); 203.0.113.55 is hostile. Nothing in
-- this table tells them apart — only the allowlist does.
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '198.51.100.50',   2860, 2, 412,  2791,
 'AS64500 Example Corp',       'US', 'Nuclei/3.1 (redteam-scan)',
 'portal.example.com',
 FALSE, FALSE, FALSE, 119.2, 'GET',  0.98, 96),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.55',    1910, 1, 388,  1902,
 'AS64496 NimbusHost Cloud',   'NL', 'Mozilla/5.0 zgrab/0.x',
 'portal.example.com',
 FALSE, FALSE, TRUE,   79.6, 'GET',  0.99, 90),

-- ── Red team phishing-simulation sender (authorised, REDTEAM.md) ─────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.100',   640,  2,   9,   120,
 'AS64500 Example Corp',       'US', 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/128.0',
 'phishsim.company-test.com',
 FALSE, FALSE, TRUE,   26.7, 'POST', 0.19, 700),

-- ── Uptime monitor — benign, but high rate + single path looks like C2 ──────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '192.0.2.250',     8640, 1,   1,     0,
 'AS64503 PulseCheck Monitoring', 'US', 'PulseCheck/2.4 (+https://pulsecheck.example)',
 'portal.example.com',
 FALSE, FALSE, TRUE,  360.0, 'HEAD', 0.00, 0),

-- ── Tor exit with benign browsing — Tor is not proof of attack ───────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '203.0.113.140',   57,   1,  21,     2,
 'AS64504 Nordlys Networks',   'DE', 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0',
 'portal.example.com',
 TRUE,  FALSE, FALSE,   2.4, 'GET',  0.04, 1800),

-- ── Legitimate clients (control) ─────────────────────────────────────────────
('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '192.0.2.10',      1240, 4,  38,     1,
 'AS64500 Example Corp',       'US', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/17.6',
 'portal.example.com',
 FALSE, FALSE, FALSE,  51.7, 'GET',  0.01, 2048),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '192.0.2.33',      96,   1,  17,     0,
 'AS64506 Alder Fiber',        'US', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) Safari/604.1',
 'portal.example.com',
 FALSE, FALSE, FALSE,   4.0, 'GET',  0.02, 1500),

('2026-09-09 00:00:00+00', '2026-09-09 23:59:59+00',
 '192.0.2.77',      143,  1,  22,     0,
 'AS64502 Meridian Broadband', 'GB', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0 Safari/537.36',
 'portal.example.com',
 FALSE, FALSE, FALSE,   6.0, 'GET',  0.03, 1700);
