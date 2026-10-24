-- CodeLedger Week 3 / Member B: index and query-plan review.
-- Run only after schema + seed creation and the OSV snapshot ingestion.
-- This script is read-only except ANALYZE TABLE, which refreshes optimizer statistics.
USE codeledger_final;

SELECT VERSION() AS mysql_version, DATABASE() AS target_database;

-- 1. Refresh statistics before recording plans (does not change row contents).
ANALYZE TABLE packages, package_versions, affected_package, affected_version,
              affected_range, range_event, vulnerability_alias,
              vulnerability_severity, project_dependencies, scans, scan_findings;

-- 2. Approximate table footprint. TABLE_ROWS is an InnoDB estimate, not an exact count.
SELECT table_name, table_rows AS estimated_rows,
       ROUND(data_length / 1024 / 1024, 2) AS data_mb,
       ROUND(index_length / 1024 / 1024, 2) AS index_mb
FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'
ORDER BY data_length DESC;

-- 3. Existing index inventory for high-traffic paths.
SHOW INDEX FROM ecosystems;
SHOW INDEX FROM packages;
SHOW INDEX FROM package_versions;
SHOW INDEX FROM affected_package;
SHOW INDEX FROM affected_version;
SHOW INDEX FROM affected_range;
SHOW INDEX FROM range_event;
SHOW INDEX FROM vulnerability_alias;
SHOW INDEX FROM vulnerability_severity;
SHOW INDEX FROM project_dependencies;
SHOW INDEX FROM scans;
SHOW INDEX FROM scan_findings;

-- 4. Main advisory lookup: ecosystem + package name -> matching advisories.
-- Inspect type/key/rows/Extra. uq_package_ecosystem_name should support package lookup.
EXPLAIN
SELECT ap.affected_package_id, v.vulnerability_id, v.summary
FROM ecosystems e
JOIN packages p ON p.ecosystem_id = e.ecosystem_id
JOIN affected_package ap ON ap.package_id = p.package_id
JOIN vulnerabilities v ON v.vulnerability_id = ap.vulnerability_id
WHERE e.name = 'PyPI'
  AND p.name = 'requests'
  AND v.withdrawn_at IS NULL;

-- 5. Ordered event lookup. Subquery avoids assuming a hard-coded range ID exists.
EXPLAIN
SELECT re.event_order, re.event_type, re.event_value
FROM range_event re
WHERE re.range_id = (SELECT MIN(ar.range_id) FROM affected_range ar)
ORDER BY re.event_order;

-- 6. Findings for the synthetic demo scan; this scan exists after seed.sql.
EXPLAIN
SELECT sf.finding_id, sf.dependency_id, sf.vulnerability_id
FROM scan_findings sf
WHERE sf.scan_id = 9101
ORDER BY sf.finding_id;

-- 7. Alias lookup (the literal can return zero rows; the plan still shows index use).
EXPLAIN
SELECT va.vulnerability_id
FROM vulnerability_alias va
WHERE va.alias_value = 'CVE-2023-0000';

-- 8. Project scan history: test the project/date composite index.
EXPLAIN
SELECT s.scan_id, s.status, s.started_at, s.completed_at
FROM scans s
WHERE s.project_id = 9001
ORDER BY s.started_at DESC;

-- 9. Project manifest -> versions path used to report dependencies.
EXPLAIN
SELECT pd.dependency_id, pv.version, p.name, e.name AS ecosystem
FROM project_dependencies pd
JOIN package_versions pv ON pv.package_version_id = pd.package_version_id
JOIN packages p ON p.package_id = pv.package_id
JOIN ecosystems e ON e.ecosystem_id = p.ecosystem_id
WHERE pd.project_id = 9001;

-- Index policy: do not add indexes solely because a column appears in a JOIN.
-- Record key/rows/Extra from these plans; then compare measured timings before/after
-- a proposed index. Every additional index has storage and ingestion-write costs.
