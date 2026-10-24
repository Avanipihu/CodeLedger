-- CodeLedger Week 3 / Member B: transactional deletion/cascade test.
-- Safe to run on codeledger_final. It ends with ROLLBACK so the seed project is restored.
-- Expected: the four counts in the middle result are 0; after ROLLBACK the demo project
-- and its dependencies/scans/findings should be present again.
USE codeledger_final;

SELECT 'before_delete' AS phase,
       (SELECT COUNT(*) FROM projects WHERE project_id = 9001) AS project_rows,
       (SELECT COUNT(*) FROM project_dependencies WHERE project_id = 9001) AS dependency_rows,
       (SELECT COUNT(*) FROM scans WHERE project_id = 9001) AS scan_rows,
       (SELECT COUNT(*) FROM scan_findings sf JOIN scans s ON s.scan_id = sf.scan_id WHERE s.project_id = 9001) AS finding_rows,
       (SELECT COUNT(*) FROM packages) AS shared_package_rows,
       (SELECT COUNT(*) FROM package_versions) AS shared_version_rows,
       (SELECT COUNT(*) FROM vulnerabilities) AS shared_vulnerability_rows;

START TRANSACTION;
DELETE FROM projects WHERE project_id = 9001;

SELECT 'inside_transaction_after_delete' AS phase,
       (SELECT COUNT(*) FROM projects WHERE project_id = 9001) AS project_rows,
       (SELECT COUNT(*) FROM project_dependencies WHERE project_id = 9001) AS dependency_rows,
       (SELECT COUNT(*) FROM scans WHERE project_id = 9001) AS scan_rows,
       (SELECT COUNT(*) FROM scan_findings sf JOIN scans s ON s.scan_id = sf.scan_id WHERE s.project_id = 9001) AS finding_rows,
       (SELECT COUNT(*) FROM packages) AS shared_package_rows,
       (SELECT COUNT(*) FROM package_versions) AS shared_version_rows,
       (SELECT COUNT(*) FROM vulnerabilities) AS shared_vulnerability_rows;

ROLLBACK;

SELECT 'after_rollback' AS phase,
       (SELECT COUNT(*) FROM projects WHERE project_id = 9001) AS project_rows,
       (SELECT COUNT(*) FROM project_dependencies WHERE project_id = 9001) AS dependency_rows,
       (SELECT COUNT(*) FROM scans WHERE project_id = 9001) AS scan_rows,
       (SELECT COUNT(*) FROM scan_findings sf JOIN scans s ON s.scan_id = sf.scan_id WHERE s.project_id = 9001) AS finding_rows,
       (SELECT COUNT(*) FROM packages) AS shared_package_rows,
       (SELECT COUNT(*) FROM package_versions) AS shared_version_rows,
       (SELECT COUNT(*) FROM vulnerabilities) AS shared_vulnerability_rows;

-- Expected design behavior: deleting a project cascades to its dependencies/scans/findings.
-- Shared package/version/advisory rows are not deleted with the project.
-- Deleting a referenced package version or vulnerability should be RESTRICTed by the FKs.
