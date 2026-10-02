-- CodeLedger synthetic Week 1 seed data
-- IMPORTANT:
-- 1. All DEMO-* advisory/CVE/CWE identifiers, package names, findings and URLs
--    in this file are synthetic test fixtures, NOT real security advisories.
-- 2. Run this once against a freshly created, empty `codeledger` schema.
-- 3. This file intentionally uses explicit IDs so test relationships are stable.
-- 4. The scan_findings rows are expected fixture results for UI/query testing;
--    Member C's matcher should independently reproduce/validate them.

USE codeledger;
START TRANSACTION;

-- 1. One ecosystem
INSERT INTO ecosystems (ecosystem_id, name)
VALUES (1, 'PyPI');

-- 2. Synthetic package catalogue
INSERT INTO packages (package_id, ecosystem_id, name, purl) VALUES
    (101, 1, 'demo-http-client', 'pkg:pypi/demo-http-client'),
    (102, 1, 'demo-web-core',    'pkg:pypi/demo-web-core'),
    (103, 1, 'demo-parser',      'pkg:pypi/demo-parser'),
    (104, 1, 'demo-data-lib',    'pkg:pypi/demo-data-lib'),
    (105, 1, 'demo-safe-lib',    'pkg:pypi/demo-safe-lib'),
    (106, 1, 'demo-unfixed-lib', 'pkg:pypi/demo-unfixed-lib');

-- 3. Package versions. These include vulnerable, fixed, gap, and safe versions.
INSERT INTO package_versions (package_version_id, package_id, version) VALUES
    (1001, 101, '1.0.0'),
    (1002, 101, '1.0.1'),
    (1011, 102, '2.0.0'),
    (1012, 102, '2.1.0'),
    (1021, 103, '1.4.0'),
    (1022, 103, '1.5.0'),
    (1023, 103, '1.8.0'),
    (1024, 103, '2.0.0'),
    (1025, 103, '2.1.0'),
    (1031, 104, '3.0.0'),
    (1032, 104, '3.0.1'),
    (1041, 105, '1.0.0'),
    (1051, 106, '3.0.0'),
    (1052, 106, '3.1.0');

-- 4. Synthetic vulnerability/advisory records
INSERT INTO vulnerabilities
    (vulnerability_id, schema_version, summary, details,
     published_at, modified_at, withdrawn_at)
VALUES
    (
      'SECUREDEP-DEMO-001', '1.6.0',
      'Synthetic HTTP client issue with a fixed version',
      'DEMO ONLY. Illustrates a vulnerability affecting demo-http-client 1.0.0; this is not a real advisory.',
      '2026-01-10 00:00:00', '2026-01-12 00:00:00', NULL
    ),
    (
      'SECUREDEP-DEMO-002', '1.6.0',
      'Synthetic issue affecting multiple packages',
      'DEMO ONLY. Illustrates one advisory affecting demo-web-core by range and demo-data-lib by an explicit version list.',
      '2026-02-01 00:00:00', '2026-02-03 00:00:00', NULL
    ),
    (
      'SECUREDEP-DEMO-003', '1.6.0',
      'Second synthetic issue affecting demo-web-core',
      'DEMO ONLY. Provides a second vulnerability for the same package version.',
      '2026-02-11 00:00:00', '2026-02-12 00:00:00', NULL
    ),
    (
      'SECUREDEP-DEMO-004', '1.6.0',
      'Synthetic parser issue with disjoint affected ranges',
      'DEMO ONLY. Affects demo-parser 1.4.0 up to but excluding 1.5.0, and 2.0.0 up to but excluding 2.1.0. Versions in the gap should not match.',
      '2026-03-01 00:00:00', '2026-03-02 00:00:00', NULL
    ),
    (
      'SECUREDEP-DEMO-005', '1.6.0',
      'Synthetic issue without a recorded fixed event',
      'DEMO ONLY. Illustrates a range starting at 3.0.0 with no fixed event recorded in this fixture.',
      '2026-03-10 00:00:00', '2026-03-10 00:00:00', NULL
    );

-- 5. Advisory aliases (all explicitly synthetic)
INSERT INTO vulnerability_alias (alias_id, vulnerability_id, alias_value) VALUES
    (2001, 'SECUREDEP-DEMO-001', 'CVE-DEMO-0001'),
    (2002, 'SECUREDEP-DEMO-001', 'GHSA-DEMO-0001'),
    (2003, 'SECUREDEP-DEMO-002', 'CVE-DEMO-0002'),
    (2004, 'SECUREDEP-DEMO-003', 'GHSA-DEMO-0003'),
    (2005, 'SECUREDEP-DEMO-004', 'CVE-DEMO-0004'),
    (2006, 'SECUREDEP-DEMO-005', 'CVE-DEMO-0005');

-- 6. Advisory-level severity assessments. Scores/vectors are illustrative only.
INSERT INTO vulnerability_severity
    (severity_id, vulnerability_id, severity_type, score_value, base_score, source)
VALUES
    (3001, 'SECUREDEP-DEMO-001', 'CVSS_V3',
     'DEMO_VECTOR:HTTP_CLIENT', 7.5, 'synthetic-test-fixture'),
    (3002, 'SECUREDEP-DEMO-002', 'CVSS_V3',
     'DEMO_VECTOR:MULTI_PACKAGE', 8.1, 'synthetic-test-fixture'),
    (3003, 'SECUREDEP-DEMO-004', 'CVSS_V3',
     'DEMO_VECTOR:DISJOINT_RANGES', 6.5, 'synthetic-test-fixture'),
    (3004, 'SECUREDEP-DEMO-005', 'CVSS_V3',
     'DEMO_VECTOR:NO_FIXED_EVENT', 7.0, 'synthetic-test-fixture');

-- 7. Synthetic reference URLs. example.org is reserved for examples.
INSERT INTO vulnerability_reference
    (reference_id, vulnerability_id, reference_type, url)
VALUES
    (4001, 'SECUREDEP-DEMO-001', 'ADVISORY', 'https://example.org/codeledger/demo-001'),
    (4002, 'SECUREDEP-DEMO-001', 'FIX',      'https://example.org/codeledger/demo-001/fix'),
    (4003, 'SECUREDEP-DEMO-002', 'ADVISORY', 'https://example.org/codeledger/demo-002'),
    (4004, 'SECUREDEP-DEMO-003', 'ADVISORY', 'https://example.org/codeledger/demo-003'),
    (4005, 'SECUREDEP-DEMO-004', 'ADVISORY', 'https://example.org/codeledger/demo-004'),
    (4006, 'SECUREDEP-DEMO-005', 'ADVISORY', 'https://example.org/codeledger/demo-005');

-- 8. Advisory/package associations (the M:N relationship resolution)
INSERT INTO affected_package (affected_package_id, vulnerability_id, package_id) VALUES
    (5001, 'SECUREDEP-DEMO-001', 101),
    (5002, 'SECUREDEP-DEMO-002', 102),
    (5003, 'SECUREDEP-DEMO-002', 104),
    (5004, 'SECUREDEP-DEMO-003', 102),
    (5005, 'SECUREDEP-DEMO-004', 103),
    (5006, 'SECUREDEP-DEMO-005', 106);

-- 9. Package-specific severity (demonstrates severity scope separation)
INSERT INTO affected_package_severity
    (affected_package_severity_id, affected_package_id,
     severity_type, score_value, base_score, source)
VALUES
    (3101, 5004, 'CVSS_V4', 'DEMO_VECTOR:PACKAGE_SPECIFIC', 8.8,
     'synthetic-test-fixture');

-- 10. Explicitly enumerated affected versions (independent of ranges)
INSERT INTO affected_version
    (affected_version_id, affected_package_id, version)
VALUES
    (5101, 5003, '3.0.0');

-- 11. Affected ranges. DEMO-004 deliberately has two disjoint ranges.
INSERT INTO affected_range
    (range_id, affected_package_id, range_ordinal, range_type, repo)
VALUES
    (6001, 5001, 1, 'ECOSYSTEM', NULL),
    (6002, 5002, 1, 'ECOSYSTEM', NULL),
    (6003, 5004, 1, 'ECOSYSTEM', NULL),
    (6004, 5005, 1, 'ECOSYSTEM', NULL),
    (6005, 5005, 2, 'ECOSYSTEM', NULL),
    (6006, 5006, 1, 'ECOSYSTEM', NULL);

-- 12. Ordered events for each range
INSERT INTO range_event
    (event_id, range_id, event_order, event_type, event_value)
VALUES
    -- DEMO-001: 1.0.0 is affected; 1.0.1 is the exclusive fixed boundary.
    (7001, 6001, 1, 'introduced', '1.0.0'),
    (7002, 6001, 2, 'fixed',      '1.0.1'),

    -- DEMO-002 on demo-web-core: 2.0.0 affected; 2.1.0 fixed boundary.
    (7003, 6002, 1, 'introduced', '2.0.0'),
    (7004, 6002, 2, 'fixed',      '2.1.0'),

    -- DEMO-003: all versions before 2.1.0 are represented as affected.
    (7005, 6003, 1, 'introduced', '0'),
    (7006, 6003, 2, 'fixed',      '2.1.0'),

    -- DEMO-004 range 1: [1.4.0, 1.5.0)
    (7007, 6004, 1, 'introduced', '1.4.0'),
    (7008, 6004, 2, 'fixed',      '1.5.0'),

    -- DEMO-004 range 2: [2.0.0, 2.1.0); 1.8.0 is in the gap.
    (7009, 6005, 1, 'introduced', '2.0.0'),
    (7010, 6005, 2, 'fixed',      '2.1.0'),

    -- DEMO-005: no fixed event is present in this fixture.
    (7011, 6006, 1, 'introduced', '3.0.0');

-- 13. Demo project
INSERT INTO projects (project_id, name, description) VALUES
    (9001, 'CodeLedger Demo',
     'Synthetic project for database, matching-engine, and UI integration tests.');

-- 14. Project dependencies. Includes vulnerable, gap, fixed-boundary, and safe versions.
INSERT INTO project_dependencies
    (dependency_id, project_id, package_version_id,
     dependency_scope, source_file, line_number)
VALUES
    (8001, 9001, 1001, 'MANIFEST_ENTRY', 'requirements-demo.txt', 1),
    (8002, 9001, 1011, 'MANIFEST_ENTRY', 'requirements-demo.txt', 2),
    (8003, 9001, 1021, 'MANIFEST_ENTRY', 'requirements-demo.txt', 3),
    (8004, 9001, 1023, 'MANIFEST_ENTRY', 'requirements-demo.txt', 4),
    (8005, 9001, 1031, 'MANIFEST_ENTRY', 'requirements-demo.txt', 5),
    (8006, 9001, 1041, 'MANIFEST_ENTRY', 'requirements-demo.txt', 6),
    (8007, 9001, 1051, 'MANIFEST_ENTRY', 'requirements-demo.txt', 7);

-- 15. Two scans of the same unchanged manifest to demonstrate scan history.
INSERT INTO scans
    (scan_id, project_id, source_filename, file_sha256, status,
     started_at, completed_at, error_message)
VALUES
    (9101, 9001, 'requirements-demo.txt',
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'COMPLETED', '2026-10-01 10:00:00', '2026-10-01 10:00:02', NULL),
    (9102, 9001, 'requirements-demo.txt',
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'COMPLETED', '2026-10-02 10:00:00', '2026-10-02 10:00:02', NULL);

-- 16. Expected fixture findings for scan 1.
-- These are pre-seeded expected results, not proof that the matcher computed them.
INSERT INTO scan_findings
    (finding_id, scan_id, dependency_id, vulnerability_id,
     matched_range_id, match_basis)
VALUES
    (9201, 9101, 8001, 'SECUREDEP-DEMO-001', 6001, 'RANGE'),
    (9202, 9101, 8002, 'SECUREDEP-DEMO-002', 6002, 'RANGE'),
    (9203, 9101, 8002, 'SECUREDEP-DEMO-003', 6003, 'RANGE'),
    (9204, 9101, 8003, 'SECUREDEP-DEMO-004', 6004, 'RANGE'),
    (9205, 9101, 8005, 'SECUREDEP-DEMO-002', NULL, 'EXPLICIT_VERSION'),
    (9206, 9101, 8007, 'SECUREDEP-DEMO-005', 6006, 'RANGE');

-- Expected fixture findings for scan 2 (same unchanged manifest).
INSERT INTO scan_findings
    (finding_id, scan_id, dependency_id, vulnerability_id,
     matched_range_id, match_basis)
VALUES
    (9211, 9102, 8001, 'SECUREDEP-DEMO-001', 6001, 'RANGE'),
    (9212, 9102, 8002, 'SECUREDEP-DEMO-002', 6002, 'RANGE'),
    (9213, 9102, 8002, 'SECUREDEP-DEMO-003', 6003, 'RANGE'),
    (9214, 9102, 8003, 'SECUREDEP-DEMO-004', 6004, 'RANGE'),
    (9215, 9102, 8005, 'SECUREDEP-DEMO-002', NULL, 'EXPLICIT_VERSION'),
    (9216, 9102, 8007, 'SECUREDEP-DEMO-005', 6006, 'RANGE');

-- 17. Synthetic KEV-like entry for relational-enrichment testing only.
-- This is NOT a real CISA KEV catalogue record.
INSERT INTO kev_entries
    (cve_id, vendor_project, product, vulnerability_name,
     short_description, date_added, required_action, due_date,
     known_ransomware_campaign_use, notes)
VALUES
    ('CVE-DEMO-0001', 'Demo Vendor', 'demo-http-client',
     'Synthetic KEV-like test entry',
     'DEMO ONLY. A fictional record for testing the KEV enrichment relationship.',
     '2026-10-01', 'DEMO ONLY: no real remediation action.', '2026-12-31',
     'Unknown', 'Synthetic fixture; must not be represented as real CISA data.');

-- 18. Synthetic CWE-like reference record for relationship testing only.
INSERT INTO kev_cwe (cwe_id, name)
VALUES ('CWE-DEMO-001', 'Synthetic test weakness (not a real CWE identifier)');

-- 19. Connect the synthetic KEV-like entry to its synthetic CWE-like record.
INSERT INTO kev_entry_cwe (kev_entry_cwe_id, cve_id, cwe_id)
VALUES (9301, 'CVE-DEMO-0001', 'CWE-DEMO-001');

-- 20. Link the demo advisory to the synthetic KEV-like record via its alias.
INSERT INTO vulnerability_kev
    (vulnerability_kev_id, vulnerability_id, cve_id, match_method)
VALUES
    (9401, 'SECUREDEP-DEMO-001', 'CVE-DEMO-0001', 'CVE_ALIAS');

COMMIT;

-- Suggested smoke checks (run separately after the seed commits):
-- SELECT COUNT(*) AS ecosystems FROM ecosystems;
-- SELECT COUNT(*) AS packages FROM packages;
-- SELECT COUNT(*) AS vulnerabilities FROM vulnerabilities;
-- SELECT COUNT(*) AS findings FROM scan_findings;
-- SELECT p.name, pv.version, v.vulnerability_id
-- FROM scan_findings sf
-- JOIN project_dependencies pd ON pd.dependency_id = sf.dependency_id
-- JOIN package_versions pv ON pv.package_version_id = pd.package_version_id
-- JOIN packages p ON p.package_id = pv.package_id
-- JOIN vulnerabilities v ON v.vulnerability_id = sf.vulnerability_id
-- WHERE sf.scan_id = 9101
-- ORDER BY p.name, v.vulnerability_id;
