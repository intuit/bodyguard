-- =============================================================================
-- ip_reputation.sql
-- Table:   bodyguard_demo.ip_reputation
-- Source:  Threat-intelligence feeds, merged nightly: Tor exit list, VPN and
--          hosting ranges, C2 and botnet trackers, internet-scanner feed, and a
--          curated list of known-benign services (monitoring, CDNs).
-- Purpose: One row per IP with the strongest category and its provenance.
--          Used to enrich ip_30d (is_tor_exit / is_vpn / is_datacenter) and
--          available to rules that want to weigh behaviour against reputation.
--          An IP absent from this table is simply unknown to every feed —
--          absence is not evidence of legitimacy.
-- Refresh: Nightly
-- =============================================================================

CREATE TABLE IF NOT EXISTS bodyguard_demo.ip_reputation (
    ip                      STRING      NOT NULL,   -- IPv4
    category                STRING      NOT NULL,   -- tor_exit | vpn | datacenter | malware_c2 |
                                                    -- malware_distribution | ddos_bot | scanner | monitoring
    source_feed             STRING,                 -- feed the category comes from
    confidence              FLOAT64,                -- 0.0 – 1.0 as published by the feed
    first_seen              DATE,                   -- first day the feed listed the IP
    last_seen               DATE,                   -- most recent day the feed listed the IP
    asn                     STRING,
    country                 STRING,                 -- ISO-2
    notes                   STRING,                 -- feed-provided context, free text
    PRIMARY KEY (ip) NOT ENFORCED
);

-- =============================================================================
-- Sample data. IPs present in ip_30d but absent here (198.51.100.77,
-- 203.0.113.201, 192.0.2.66, the legitimate users) are unknown to all feeds.
-- =============================================================================

INSERT INTO bodyguard_demo.ip_reputation VALUES
-- ── Anonymisation infrastructure ─────────────────────────────────────────────
('203.0.113.17',  'tor_exit',   'tor-exit-list',           0.99, '2026-07-14', '2026-09-09',
 'AS64504 Nordlys Networks',    'RU', 'Tor exit relay nordlys-exit-03'),
('203.0.113.140', 'tor_exit',   'tor-exit-list',           0.99, '2026-05-02', '2026-09-09',
 'AS64504 Nordlys Networks',    'DE', 'Tor exit relay nordlys-exit-11'),
('192.0.2.140',   'vpn',        'vpn-exit-ranges',         0.80, '2026-01-20', '2026-09-09',
 'AS64499 ShadowRoute VPN',     'BR', 'Commercial VPN egress pool'),

-- ── Hosting / datacenter ranges ──────────────────────────────────────────────
('203.0.113.88',  'datacenter', 'hosting-ranges',          0.90, '2025-11-03', '2026-09-09',
 'AS64496 NimbusHost Cloud',    'DE', 'Cloud hosting range, self-service signup'),

-- ── Malware infrastructure ───────────────────────────────────────────────────
('198.51.100.23', 'malware_c2', 'c2-tracker',              0.95, '2026-08-30', '2026-09-08',
 'AS64498 OceanDrop Cloud',     'US', 'Team-server beacon profile observed; malleable C2 over HTTP POST'),
('198.51.100.9',  'malware_distribution', 'malware-url-feed', 0.88, '2026-09-04', '2026-09-09',
 'AS64501 Helix Hosting',       'NL', 'Pulls NSIS droppers from update-now.net staging'),
('203.0.113.200', 'ddos_bot',   'botnet-tracker',          0.91, '2026-08-21', '2026-09-09',
 'AS64497 EastBridge Telecom',  'CN', 'IoT botnet member, HTTP flood module'),

-- ── Scanners — the feed cannot tell authorised from hostile ──────────────────
('198.51.100.50', 'scanner',    'internet-scanner-feed',   0.82, '2026-09-01', '2026-09-09',
 'AS64500 Example Corp',        'US', 'Nuclei template scanning observed against multiple targets'),
('203.0.113.55',  'scanner',    'internet-scanner-feed',   0.86, '2026-06-11', '2026-09-09',
 'AS64496 NimbusHost Cloud',    'NL', 'Mass zgrab banner grabbing, opportunistic'),

-- ── Known benign ─────────────────────────────────────────────────────────────
('192.0.2.250',   'monitoring', 'known-benign-services',   0.97, '2025-01-10', '2026-09-09',
 'AS64503 PulseCheck Monitoring', 'US', 'Uptime probes; high request rate on a single path is by design');
