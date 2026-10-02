CREATE DATABASE IF NOT EXISTS codeledger;
USE codeledger;


-- 1. ECOSYSTEM
CREATE TABLE IF NOT EXISTS ecosystems (
    ecosystem_id BIGINT UNSIGNED AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,

    PRIMARY KEY (ecosystem_id),
    UNIQUE KEY uq_ecosystem_name (name)
) ENGINE = InnoDB;


-- 2. PACKAGE
CREATE TABLE IF NOT EXISTS packages (
    package_id BIGINT UNSIGNED AUTO_INCREMENT,
    ecosystem_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(255) NOT NULL,
    purl VARCHAR(512),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (package_id),

    UNIQUE KEY uq_package_ecosystem_name
        (ecosystem_id, name),

    CONSTRAINT fk_package_ecosystem
        FOREIGN KEY (ecosystem_id)
        REFERENCES ecosystems(ecosystem_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 3. PACKAGE_VERSION
CREATE TABLE IF NOT EXISTS package_versions (
    package_version_id BIGINT UNSIGNED AUTO_INCREMENT,
    package_id BIGINT UNSIGNED NOT NULL,
    version VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (package_version_id),

    UNIQUE KEY uq_package_version
        (package_id, version),

    CONSTRAINT fk_package_version_package
        FOREIGN KEY (package_id)
        REFERENCES packages(package_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 4. VULNERABILITY
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id VARCHAR(100) NOT NULL,
    schema_version VARCHAR(30),
    summary TEXT,
    details MEDIUMTEXT,
    published_at DATETIME,
    modified_at DATETIME,
    withdrawn_at DATETIME,
    imported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (vulnerability_id)
) ENGINE = InnoDB;

-- 5. VULNERABILITY_ALIAS
CREATE TABLE IF NOT EXISTS vulnerability_alias (
    alias_id BIGINT UNSIGNED AUTO_INCREMENT,
    vulnerability_id VARCHAR(100) NOT NULL,
    alias_value VARCHAR(100) NOT NULL,

    PRIMARY KEY (alias_id),

    UNIQUE KEY uq_vulnerability_alias
        (vulnerability_id, alias_value),

    CONSTRAINT fk_alias_vulnerability
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 6. VULNERABILITY_SEVERITY
CREATE TABLE IF NOT EXISTS vulnerability_severity (
    severity_id BIGINT UNSIGNED AUTO_INCREMENT,
    vulnerability_id VARCHAR(100) NOT NULL,
    severity_type VARCHAR(30) NOT NULL,
    score_value VARCHAR(255) NOT NULL,
    base_score DECIMAL(4,2),
    source VARCHAR(512),

    PRIMARY KEY (severity_id),

    CONSTRAINT chk_vuln_base_score
        CHECK (
            base_score IS NULL
            OR base_score BETWEEN 0 AND 10
        ),

    CONSTRAINT fk_severity_vulnerability
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 7. VULNERABILITY_REFERENCE
CREATE TABLE IF NOT EXISTS vulnerability_reference (
    reference_id BIGINT UNSIGNED AUTO_INCREMENT,
    vulnerability_id VARCHAR(100) NOT NULL,
    reference_type VARCHAR(40) NOT NULL,
    url VARCHAR(2048) NOT NULL,

    PRIMARY KEY (reference_id),

    KEY idx_reference_vulnerability
        (vulnerability_id),

    CONSTRAINT fk_reference_vulnerability
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 8. AFFECTED_PACKAGE
CREATE TABLE IF NOT EXISTS affected_package (
    affected_package_id BIGINT UNSIGNED AUTO_INCREMENT,
    vulnerability_id VARCHAR(100) NOT NULL,
    package_id BIGINT UNSIGNED NOT NULL,

    PRIMARY KEY (affected_package_id),

    UNIQUE KEY uq_vulnerability_package
        (vulnerability_id, package_id),

    CONSTRAINT fk_affected_vulnerability
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_affected_package
        FOREIGN KEY (package_id)
        REFERENCES packages(package_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 9. AFFECTED_PACKAGE_SEVERITY
CREATE TABLE IF NOT EXISTS affected_package_severity (
    affected_package_severity_id BIGINT UNSIGNED AUTO_INCREMENT,
    affected_package_id BIGINT UNSIGNED NOT NULL,
    severity_type VARCHAR(30) NOT NULL,
    score_value VARCHAR(255) NOT NULL,
    base_score DECIMAL(4,2),
    source VARCHAR(512),

    PRIMARY KEY (affected_package_severity_id),

    CONSTRAINT chk_affected_base_score
        CHECK (
            base_score IS NULL
            OR base_score BETWEEN 0 AND 10
        ),

    CONSTRAINT fk_aps_affected_package
        FOREIGN KEY (affected_package_id)
        REFERENCES affected_package(affected_package_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 10. AFFECTED_VERSION
CREATE TABLE IF NOT EXISTS affected_version (
    affected_version_id BIGINT UNSIGNED AUTO_INCREMENT,
    affected_package_id BIGINT UNSIGNED NOT NULL,
    version VARCHAR(255) NOT NULL,

    PRIMARY KEY (affected_version_id),

    UNIQUE KEY uq_affected_version
        (affected_package_id, version),

    CONSTRAINT fk_version_affected_package
        FOREIGN KEY (affected_package_id)
        REFERENCES affected_package(affected_package_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 11. AFFECTED_RANGE
CREATE TABLE IF NOT EXISTS affected_range (
    range_id BIGINT UNSIGNED AUTO_INCREMENT,
    affected_package_id BIGINT UNSIGNED NOT NULL,
    range_ordinal INT UNSIGNED NOT NULL,
    range_type VARCHAR(30) NOT NULL,
    repo VARCHAR(512),

    PRIMARY KEY (range_id),

    UNIQUE KEY uq_affected_range_ordinal
        (affected_package_id, range_ordinal),

    CONSTRAINT fk_range_affected_package
        FOREIGN KEY (affected_package_id)
        REFERENCES affected_package(affected_package_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 12. RANGE_EVENT
CREATE TABLE IF NOT EXISTS range_event (
    event_id BIGINT UNSIGNED AUTO_INCREMENT,
    range_id BIGINT UNSIGNED NOT NULL,
    event_order INT UNSIGNED NOT NULL,
    event_type ENUM(
        'introduced',
        'fixed',
        'last_affected',
        'limit'
    ) NOT NULL,
    event_value VARCHAR(255) NOT NULL,

    PRIMARY KEY (event_id),

    UNIQUE KEY uq_range_event_order
        (range_id, event_order),

    CONSTRAINT fk_event_range
        FOREIGN KEY (range_id)
        REFERENCES affected_range(range_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;

-- 13. PROJECT
CREATE TABLE IF NOT EXISTS projects (
    project_id BIGINT UNSIGNED AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (project_id)
) ENGINE = InnoDB;


-- 14. PROJECT_DEPENDENCY
CREATE TABLE IF NOT EXISTS project_dependencies (
    dependency_id BIGINT UNSIGNED AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    package_version_id BIGINT UNSIGNED NOT NULL,
    dependency_scope VARCHAR(30) NOT NULL DEFAULT 'MANIFEST_ENTRY',
    source_file VARCHAR(255),
    line_number INT UNSIGNED,
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (dependency_id),

    KEY idx_dependency_project (project_id),
    KEY idx_dependency_version (package_version_id),

    CONSTRAINT fk_dependency_project
        FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_dependency_package_version
        FOREIGN KEY (package_version_id)
        REFERENCES package_versions(package_version_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 15. SCAN
CREATE TABLE IF NOT EXISTS scans (
    scan_id BIGINT UNSIGNED AUTO_INCREMENT,
    project_id BIGINT UNSIGNED NOT NULL,
    source_filename VARCHAR(255) NOT NULL,
    file_sha256 CHAR(64),
    status ENUM(
        'PENDING',
        'RUNNING',
        'COMPLETED',
        'FAILED'
    ) NOT NULL DEFAULT 'PENDING',
    started_at DATETIME,
    completed_at DATETIME,
    error_message TEXT,

    PRIMARY KEY (scan_id),

    KEY idx_scan_project_date (project_id, started_at),

    CONSTRAINT chk_scan_time_order
        CHECK (
            completed_at IS NULL
            OR started_at IS NULL
            OR completed_at >= started_at
        ),

    CONSTRAINT fk_scan_project
        FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 16. SCAN_FINDING
CREATE TABLE IF NOT EXISTS scan_findings (
    finding_id BIGINT UNSIGNED AUTO_INCREMENT,
    scan_id BIGINT UNSIGNED NOT NULL,
    dependency_id BIGINT UNSIGNED NOT NULL,
    vulnerability_id VARCHAR(100) NOT NULL,
    matched_range_id BIGINT UNSIGNED,
    match_basis ENUM(
        'EXPLICIT_VERSION',
        'RANGE',
        'BOTH'
    ) NOT NULL,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (finding_id),

    UNIQUE KEY uq_scan_dependency_vulnerability
        (scan_id, dependency_id, vulnerability_id),

    KEY idx_finding_vulnerability (vulnerability_id),

    CONSTRAINT fk_finding_scan
        FOREIGN KEY (scan_id)
        REFERENCES scans(scan_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_finding_dependency
        FOREIGN KEY (dependency_id)
        REFERENCES project_dependencies(dependency_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_finding_vulnerability
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE,

    CONSTRAINT fk_finding_range
        FOREIGN KEY (matched_range_id)
        REFERENCES affected_range(range_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE = InnoDB;

-- 17. KEV_ENTRY
CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id VARCHAR(100) NOT NULL,
    vendor_project VARCHAR(255) NOT NULL,
    product VARCHAR(255) NOT NULL,
    vulnerability_name VARCHAR(512),
    short_description TEXT,
    date_added DATE,
    required_action TEXT,
    due_date DATE,
    known_ransomware_campaign_use VARCHAR(30),
    notes TEXT,
    imported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (cve_id),

    KEY idx_kev_date_added (date_added)
) ENGINE = InnoDB;


-- 18. KEV_CWE
CREATE TABLE IF NOT EXISTS kev_cwe (
    cwe_id VARCHAR(30) NOT NULL,
    name VARCHAR(255),

    PRIMARY KEY (cwe_id)
) ENGINE = InnoDB;


-- 19. KEV_ENTRY_CWE
CREATE TABLE IF NOT EXISTS kev_entry_cwe (
    kev_entry_cwe_id BIGINT UNSIGNED AUTO_INCREMENT,
    cve_id VARCHAR(100) NOT NULL,
    cwe_id VARCHAR(30) NOT NULL,

    PRIMARY KEY (kev_entry_cwe_id),

    UNIQUE KEY uq_kev_entry_cwe (cve_id, cwe_id),

    CONSTRAINT fk_kec_entry
        FOREIGN KEY (cve_id)
        REFERENCES kev_entries(cve_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_kec_cwe
        FOREIGN KEY (cwe_id)
        REFERENCES kev_cwe(cwe_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE = InnoDB;


-- 20. VULNERABILITY_KEV
CREATE TABLE IF NOT EXISTS vulnerability_kev (
    vulnerability_kev_id BIGINT UNSIGNED AUTO_INCREMENT,
    vulnerability_id VARCHAR(100) NOT NULL,
    cve_id VARCHAR(100) NOT NULL,
    match_method VARCHAR(30) NOT NULL DEFAULT 'CVE_ALIAS',
    matched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (vulnerability_kev_id),

    UNIQUE KEY uq_vulnerability_kev
        (vulnerability_id, cve_id),

    CONSTRAINT fk_vulnerability_kev_advisory
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_vulnerability_kev_entry
        FOREIGN KEY (cve_id)
        REFERENCES kev_entries(cve_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE = InnoDB;
