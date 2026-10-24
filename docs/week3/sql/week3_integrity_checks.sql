-- CodeLedger Week 3 / Member B: read-only referential and consistency checks.
-- Expected: every violation_count below is 0 on a clean seeded + ingested database.
USE codeledger_final;

SELECT 'target_database' AS check_name, DATABASE() AS result;

-- Exact row counts for the final relational schema.
SELECT 'ecosystems' AS table_name, COUNT(*) AS row_count FROM ecosystems
UNION ALL SELECT 'packages', COUNT(*) FROM packages
UNION ALL SELECT 'package_versions', COUNT(*) FROM package_versions
UNION ALL SELECT 'vulnerabilities', COUNT(*) FROM vulnerabilities
UNION ALL SELECT 'vulnerability_alias', COUNT(*) FROM vulnerability_alias
UNION ALL SELECT 'vulnerability_severity', COUNT(*) FROM vulnerability_severity
UNION ALL SELECT 'vulnerability_reference', COUNT(*) FROM vulnerability_reference
UNION ALL SELECT 'affected_package', COUNT(*) FROM affected_package
UNION ALL SELECT 'affected_package_severity', COUNT(*) FROM affected_package_severity
UNION ALL SELECT 'affected_version', COUNT(*) FROM affected_version
UNION ALL SELECT 'affected_range', COUNT(*) FROM affected_range
UNION ALL SELECT 'range_event', COUNT(*) FROM range_event
UNION ALL SELECT 'projects', COUNT(*) FROM projects
UNION ALL SELECT 'project_dependencies', COUNT(*) FROM project_dependencies
UNION ALL SELECT 'scans', COUNT(*) FROM scans
UNION ALL SELECT 'scan_findings', COUNT(*) FROM scan_findings
UNION ALL SELECT 'kev_entries', COUNT(*) FROM kev_entries
UNION ALL SELECT 'kev_cwe', COUNT(*) FROM kev_cwe
UNION ALL SELECT 'kev_entry_cwe', COUNT(*) FROM kev_entry_cwe
UNION ALL SELECT 'vulnerability_kev', COUNT(*) FROM vulnerability_kev
ORDER BY table_name;

-- Foreign-key orphan checks. A non-zero count indicates integrity damage.
SELECT 'packages_without_ecosystem' AS check_name, COUNT(*) AS violation_count
FROM packages p LEFT JOIN ecosystems e ON e.ecosystem_id = p.ecosystem_id WHERE e.ecosystem_id IS NULL
UNION ALL SELECT 'versions_without_package', COUNT(*)
FROM package_versions pv LEFT JOIN packages p ON p.package_id = pv.package_id WHERE p.package_id IS NULL
UNION ALL SELECT 'aliases_without_vulnerability', COUNT(*)
FROM vulnerability_alias va LEFT JOIN vulnerabilities v ON v.vulnerability_id = va.vulnerability_id WHERE v.vulnerability_id IS NULL
UNION ALL SELECT 'severities_without_vulnerability', COUNT(*)
FROM vulnerability_severity vs LEFT JOIN vulnerabilities v ON v.vulnerability_id = vs.vulnerability_id WHERE v.vulnerability_id IS NULL
UNION ALL SELECT 'references_without_vulnerability', COUNT(*)
FROM vulnerability_reference vr LEFT JOIN vulnerabilities v ON v.vulnerability_id = vr.vulnerability_id WHERE v.vulnerability_id IS NULL
UNION ALL SELECT 'affected_package_without_vulnerability', COUNT(*)
FROM affected_package ap LEFT JOIN vulnerabilities v ON v.vulnerability_id = ap.vulnerability_id WHERE v.vulnerability_id IS NULL
UNION ALL SELECT 'affected_package_without_package', COUNT(*)
FROM affected_package ap LEFT JOIN packages p ON p.package_id = ap.package_id WHERE p.package_id IS NULL
UNION ALL SELECT 'affected_severity_without_parent', COUNT(*)
FROM affected_package_severity aps LEFT JOIN affected_package ap ON ap.affected_package_id = aps.affected_package_id WHERE ap.affected_package_id IS NULL
UNION ALL SELECT 'affected_version_without_parent', COUNT(*)
FROM affected_version av LEFT JOIN affected_package ap ON ap.affected_package_id = av.affected_package_id WHERE ap.affected_package_id IS NULL
UNION ALL SELECT 'affected_range_without_parent', COUNT(*)
FROM affected_range ar LEFT JOIN affected_package ap ON ap.affected_package_id = ar.affected_package_id WHERE ap.affected_package_id IS NULL
UNION ALL SELECT 'range_event_without_range', COUNT(*)
FROM range_event re LEFT JOIN affected_range ar ON ar.range_id = re.range_id WHERE ar.range_id IS NULL
UNION ALL SELECT 'dependency_without_project', COUNT(*)
FROM project_dependencies pd LEFT JOIN projects p ON p.project_id = pd.project_id WHERE p.project_id IS NULL
UNION ALL SELECT 'dependency_without_version', COUNT(*)
FROM project_dependencies pd LEFT JOIN package_versions pv ON pv.package_version_id = pd.package_version_id WHERE pv.package_version_id IS NULL
UNION ALL SELECT 'scan_without_project', COUNT(*)
FROM scans s LEFT JOIN projects p ON p.project_id = s.project_id WHERE p.project_id IS NULL
UNION ALL SELECT 'finding_without_scan', COUNT(*)
FROM scan_findings sf LEFT JOIN scans s ON s.scan_id = sf.scan_id WHERE s.scan_id IS NULL
UNION ALL SELECT 'finding_without_dependency', COUNT(*)
FROM scan_findings sf LEFT JOIN project_dependencies pd ON pd.dependency_id = sf.dependency_id WHERE pd.dependency_id IS NULL
UNION ALL SELECT 'finding_without_vulnerability', COUNT(*)
FROM scan_findings sf LEFT JOIN vulnerabilities v ON v.vulnerability_id = sf.vulnerability_id WHERE v.vulnerability_id IS NULL
UNION ALL SELECT 'finding_without_matched_range', COUNT(*)
FROM scan_findings sf LEFT JOIN affected_range ar ON ar.range_id = sf.matched_range_id
WHERE sf.matched_range_id IS NOT NULL AND ar.range_id IS NULL
UNION ALL SELECT 'kev_cwe_without_entry', COUNT(*)
FROM kev_entry_cwe kec LEFT JOIN kev_entries ke ON ke.cve_id = kec.cve_id WHERE ke.cve_id IS NULL
UNION ALL SELECT 'kev_cwe_without_cwe', COUNT(*)
FROM kev_entry_cwe kec LEFT JOIN kev_cwe kc ON kc.cwe_id = kec.cwe_id WHERE kc.cwe_id IS NULL
UNION ALL SELECT 'vulnerability_kev_without_advisory', COUNT(*)
FROM vulnerability_kev vk LEFT JOIN vulnerabilities v ON v.vulnerability_id = vk.vulnerability_id WHERE v.vulnerability_id IS NULL
UNION ALL SELECT 'vulnerability_kev_without_kev_entry', COUNT(*)
FROM vulnerability_kev vk LEFT JOIN kev_entries ke ON ke.cve_id = vk.cve_id WHERE ke.cve_id IS NULL;

-- Business consistency checks not guaranteed by individual foreign keys.
SELECT 'scan_dependency_project_mismatch' AS check_name, COUNT(*) AS violation_count
FROM scan_findings sf
JOIN scans s ON s.scan_id = sf.scan_id
JOIN project_dependencies pd ON pd.dependency_id = sf.dependency_id
WHERE s.project_id <> pd.project_id
UNION ALL
SELECT 'finding_range_vulnerability_or_package_mismatch', COUNT(*)
FROM scan_findings sf
JOIN affected_range ar ON ar.range_id = sf.matched_range_id
JOIN affected_package ap ON ap.affected_package_id = ar.affected_package_id
JOIN project_dependencies pd ON pd.dependency_id = sf.dependency_id
JOIN package_versions pv ON pv.package_version_id = pd.package_version_id
WHERE sf.matched_range_id IS NOT NULL
  AND (sf.vulnerability_id <> ap.vulnerability_id OR pv.package_id <> ap.package_id);

-- Review the actual ON DELETE rules rather than relying on assumptions.
SELECT table_name, constraint_name, referenced_table_name, delete_rule, update_rule
FROM information_schema.referential_constraints
WHERE constraint_schema = DATABASE()
ORDER BY table_name, constraint_name;

-- Duplicate probes for the business keys that should be unique; expected 0 rows each.
SELECT 'duplicate_package_identity' AS check_name, COUNT(*) AS duplicate_groups
FROM (SELECT ecosystem_id, name FROM packages GROUP BY ecosystem_id, name HAVING COUNT(*) > 1) d
UNION ALL SELECT 'duplicate_package_version', COUNT(*)
FROM (SELECT package_id, version FROM package_versions GROUP BY package_id, version HAVING COUNT(*) > 1) d
UNION ALL SELECT 'duplicate_alias', COUNT(*)
FROM (SELECT vulnerability_id, alias_value FROM vulnerability_alias GROUP BY vulnerability_id, alias_value HAVING COUNT(*) > 1) d
UNION ALL SELECT 'duplicate_affected_package', COUNT(*)
FROM (SELECT vulnerability_id, package_id FROM affected_package GROUP BY vulnerability_id, package_id HAVING COUNT(*) > 1) d
UNION ALL SELECT 'duplicate_range_event_order', COUNT(*)
FROM (SELECT range_id, event_order FROM range_event GROUP BY range_id, event_order HAVING COUNT(*) > 1) d
UNION ALL SELECT 'duplicate_scan_finding', COUNT(*)
FROM (SELECT scan_id, dependency_id, vulnerability_id FROM scan_findings GROUP BY scan_id, dependency_id, vulnerability_id HAVING COUNT(*) > 1) d;
