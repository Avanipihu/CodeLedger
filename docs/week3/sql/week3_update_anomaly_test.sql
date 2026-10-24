-- CodeLedger Week 3 / Member B: transactional update-anomaly sanity test.
-- Updates a project's single authoritative row, verifies its dependency links remain intact,
-- then rolls back. No persistent data is changed.
USE codeledger_final;

SELECT 'before_update' AS phase,
       COUNT(*) AS project_rows,
       (SELECT COUNT(*) FROM project_dependencies WHERE project_id = 9001) AS dependency_rows
FROM projects
WHERE project_id = 9001;

START TRANSACTION;
UPDATE projects
SET description = CONCAT(COALESCE(description, ''), ' [TEMP WEEK3 UPDATE TEST]')
WHERE project_id = 9001;

SELECT 'inside_transaction_after_update' AS phase,
       COUNT(*) AS project_rows,
       MAX(description LIKE '%[TEMP WEEK3 UPDATE TEST]%') AS temporary_description_visible,
       (SELECT COUNT(*) FROM project_dependencies WHERE project_id = 9001) AS dependency_rows
FROM projects
WHERE project_id = 9001;

ROLLBACK;

SELECT 'after_rollback' AS phase,
       COUNT(*) AS project_rows,
       MAX(description LIKE '%[TEMP WEEK3 UPDATE TEST]%') AS temporary_description_remains,
       (SELECT COUNT(*) FROM project_dependencies WHERE project_id = 9001) AS dependency_rows
FROM projects
WHERE project_id = 9001;

-- Expected: one project row throughout; dependency_rows unchanged; temporary_description_remains = 0.
-- This is a behavioral sanity check, not a substitute for the written 1NF-3NF justification.
