
USE codeledger;

-- Choose the project and scan to report on.
-- These IDs refer to the synthetic demo seed data.
SET @project_id = 9001;
SET @scan_id = 9101;

SELECT
    p.project_id,
    p.name AS project_name,
    s.scan_id,
    s.status AS scan_status,
    s.source_filename,

    pd.dependency_id,
    eco.name AS ecosystem,
    pkg.name AS package_name,
    pv.version AS installed_version,

    sf.vulnerability_id,
    v.summary AS vulnerability_summary,
    sf.match_basis,
    sf.matched_range_id,

    -- Prefer a package-specific score when one exists.
    COALESCE(
        package_severity.max_base_score,
        advisory_severity.max_base_score
    ) AS effective_base_score,

    CASE
        WHEN COALESCE(
            package_severity.max_base_score,
            advisory_severity.max_base_score
        ) IS NULL THEN 'Unknown'

        WHEN COALESCE(
            package_severity.max_base_score,
            advisory_severity.max_base_score
        ) >= 9.0 THEN 'Critical'

        WHEN COALESCE(
            package_severity.max_base_score,
            advisory_severity.max_base_score
        ) >= 7.0 THEN 'High'

        WHEN COALESCE(
            package_severity.max_base_score,
            advisory_severity.max_base_score
        ) >= 4.0 THEN 'Medium'

        ELSE 'Low'
    END AS severity_label,

    aliases.alias_values,
    kev.kev_cves,
    sf.detected_at

FROM projects p

JOIN scans s
    ON s.project_id = p.project_id

JOIN scan_findings sf
    ON sf.scan_id = s.scan_id

JOIN project_dependencies pd
    ON pd.dependency_id = sf.dependency_id
   AND pd.project_id = p.project_id

JOIN package_versions pv
    ON pv.package_version_id = pd.package_version_id

JOIN packages pkg
    ON pkg.package_id = pv.package_id

JOIN ecosystems eco
    ON eco.ecosystem_id = pkg.ecosystem_id

JOIN vulnerabilities v
    ON v.vulnerability_id = sf.vulnerability_id

LEFT JOIN (
    SELECT
        vulnerability_id,
        MAX(base_score) AS max_base_score
    FROM vulnerability_severity
    GROUP BY vulnerability_id
) advisory_severity
    ON advisory_severity.vulnerability_id = sf.vulnerability_id

LEFT JOIN (
    SELECT
        ap.vulnerability_id,
        ap.package_id,
        MAX(aps.base_score) AS max_base_score
    FROM affected_package ap
    JOIN affected_package_severity aps
        ON aps.affected_package_id = ap.affected_package_id
    GROUP BY
        ap.vulnerability_id,
        ap.package_id
) package_severity
    ON package_severity.vulnerability_id = sf.vulnerability_id
   AND package_severity.package_id = pkg.package_id

LEFT JOIN (
    SELECT
        vulnerability_id,
        GROUP_CONCAT(
            DISTINCT alias_value
            ORDER BY alias_value
            SEPARATOR ', '
        ) AS alias_values
    FROM vulnerability_alias
    GROUP BY vulnerability_id
) aliases
    ON aliases.vulnerability_id = sf.vulnerability_id

LEFT JOIN (
    SELECT
        vk.vulnerability_id,
        GROUP_CONCAT(
            DISTINCT ke.cve_id
            ORDER BY ke.cve_id
            SEPARATOR ', '
        ) AS kev_cves
    FROM vulnerability_kev vk
    JOIN kev_entries ke
        ON ke.cve_id = vk.cve_id
    GROUP BY vk.vulnerability_id
) kev
    ON kev.vulnerability_id = sf.vulnerability_id

WHERE p.project_id = @project_id
  AND s.scan_id = @scan_id

ORDER BY
    effective_base_score DESC,
    pkg.name,
    sf.vulnerability_id;

-- Summarize findings by severity for one project scan.

SELECT
    CASE
        WHEN COALESCE(
            ps.max_base_score,
            adv.max_base_score
        ) IS NULL THEN 'Unknown'
        WHEN COALESCE(
            ps.max_base_score,
            adv.max_base_score
        ) >= 9.0 THEN 'Critical'
        WHEN COALESCE(
            ps.max_base_score,
            adv.max_base_score
        ) >= 7.0 THEN 'High'
        WHEN COALESCE(
            ps.max_base_score,
            adv.max_base_score
        ) >= 4.0 THEN 'Medium'
        ELSE 'Low'
    END AS severity_label,

    COUNT(*) AS finding_count,
    COUNT(DISTINCT sf.dependency_id) AS affected_dependencies,
    COUNT(DISTINCT sf.vulnerability_id) AS distinct_vulnerabilities

FROM scans s

JOIN scan_findings sf
    ON sf.scan_id = s.scan_id

JOIN projects p
    ON p.project_id = s.project_id

JOIN project_dependencies pd
    ON pd.dependency_id = sf.dependency_id
   AND pd.project_id = p.project_id

JOIN package_versions pv
    ON pv.package_version_id = pd.package_version_id

JOIN packages pkg
    ON pkg.package_id = pv.package_id

LEFT JOIN (
    SELECT
        ap.vulnerability_id,
        ap.package_id,
        MAX(aps.base_score) AS max_base_score
    FROM affected_package ap
    JOIN affected_package_severity aps
        ON aps.affected_package_id = ap.affected_package_id
    GROUP BY ap.vulnerability_id, ap.package_id
) ps
    ON ps.vulnerability_id = sf.vulnerability_id
   AND ps.package_id = pkg.package_id

LEFT JOIN (
    SELECT
        vulnerability_id,
        MAX(base_score) AS max_base_score
    FROM vulnerability_severity
    GROUP BY vulnerability_id
) adv
    ON adv.vulnerability_id = sf.vulnerability_id

WHERE p.project_id = 9001
  AND s.scan_id = 9101

GROUP BY severity_label

ORDER BY MAX(
    COALESCE(ps.max_base_score, adv.max_base_score)
) DESC;

-- Reusable summary of every project scan.

CREATE OR REPLACE VIEW project_scan_summary AS
SELECT
    p.project_id,
    p.name AS project_name,
    s.scan_id,
    s.status AS scan_status,
    s.source_filename,
    s.started_at,
    s.completed_at,

    COUNT(sf.finding_id) AS finding_count,
    COUNT(DISTINCT sf.dependency_id) AS affected_dependencies,
    COUNT(DISTINCT sf.vulnerability_id) AS distinct_vulnerabilities

FROM projects p

JOIN scans s
    ON s.project_id = p.project_id

LEFT JOIN scan_findings sf
    ON sf.scan_id = s.scan_id

GROUP BY
    p.project_id,
    p.name,
    s.scan_id,
    s.status,
    s.source_filename,
    s.started_at,
    s.completed_at;


-- Return a summary of all scans belonging to a project.

DELIMITER //

DROP PROCEDURE IF EXISTS get_project_summary//

CREATE PROCEDURE get_project_summary(
    IN p_project_id BIGINT UNSIGNED
)
BEGIN
    SELECT
        p.project_id,
        p.name AS project_name,

        COUNT(DISTINCT s.scan_id) AS total_scans,

        COUNT(DISTINCT CASE
            WHEN s.status = 'COMPLETED'
            THEN s.scan_id
        END) AS completed_scans,

        COUNT(DISTINCT CASE
            WHEN s.status = 'FAILED'
            THEN s.scan_id
        END) AS failed_scans,

        COUNT(DISTINCT sf.finding_id) AS total_findings,

        COUNT(DISTINCT sf.dependency_id)
            AS affected_dependencies,

        COUNT(DISTINCT sf.vulnerability_id)
            AS distinct_vulnerabilities

    FROM projects p

    LEFT JOIN scans s
        ON s.project_id = p.project_id

    LEFT JOIN scan_findings sf
        ON sf.scan_id = s.scan_id

    WHERE p.project_id = p_project_id

    GROUP BY
        p.project_id,
        p.name;
END//

DELIMITER ;


-- Inspect the recorded OSV range events for a scan's findings.

SELECT
    p.name AS project_name,
    s.scan_id,
    pkg.name AS package_name,
    pv.version AS installed_version,
    sf.vulnerability_id,
    sf.match_basis,

    ar.range_id,
    ar.range_type,

    re.event_order,
    re.event_type,
    re.event_value

FROM scans s

JOIN projects p
    ON p.project_id = s.project_id

JOIN scan_findings sf
    ON sf.scan_id = s.scan_id

JOIN project_dependencies pd
    ON pd.dependency_id = sf.dependency_id
   AND pd.project_id = p.project_id

JOIN package_versions pv
    ON pv.package_version_id = pd.package_version_id

JOIN packages pkg
    ON pkg.package_id = pv.package_id

LEFT JOIN affected_range ar
    ON ar.range_id = sf.matched_range_id

LEFT JOIN range_event re
    ON re.range_id = ar.range_id

WHERE p.project_id = 9001
  AND s.scan_id = 9101

ORDER BY
    pkg.name,
    sf.vulnerability_id,
    re.event_order;
