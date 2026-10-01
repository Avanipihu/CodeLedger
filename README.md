# CodeLedger

## Database-Driven Software Dependency Vulnerability Management System

SecureDep is a database-driven cybersecurity application designed to identify and manage known vulnerabilities in software dependencies. The system allows developers to provide a dependency manifest containing package names and exact versions. SecureDep matches these dependencies against locally stored vulnerability intelligence and generates findings containing relevant security information.

The project focuses on software dependency vulnerability management and demonstrates how relational databases, document databases, Python programming, and dependency version matching can be combined to build a practical security application.

## 1. Problem Statement

Modern software applications rely heavily on third-party packages and libraries. A vulnerability in a particular version of a dependency can therefore affect an application even when the vulnerability does not originate from the application's own source code.

Developers need a structured way to determine:

* Which dependencies are affected by known vulnerabilities
* Which versions are vulnerable
* Whether a fixed version is available
* The published severity of a vulnerability
* Related CVE, GHSA, or other vulnerability identifiers
* Supporting security references
* Whether the vulnerability appears in the CISA Known Exploited Vulnerabilities catalog

SecureDep addresses this problem by connecting project dependencies with structured vulnerability intelligence through a database-centered architecture.

## 2. Project Objective

The main objective of SecureDep is to build a database-centric dependency vulnerability management system that can:

1. Store software projects and their dependencies.
2. Store package and package-version information.
3. Maintain structured vulnerability information.
4. Match dependency versions against affected vulnerability ranges.
5. Generate vulnerability findings for a project.
6. Preserve original vulnerability advisory documents.
7. Enrich findings with severity, aliases, references, and optional KEV information.
8. Maintain scan history.
9. Provide database-backed filtering and reporting.
10. Demonstrate relational and NoSQL database concepts required by the DCDS course.

## 3. Project Scope

SecureDep is an academic-scale implementation inspired by real Software Composition Analysis workflows.

The project is:

* A vulnerability information management system.
* A dependency-to-vulnerability matching system.
* A relational data modelling and querying application.
* A MySQL and MongoDB based system.
* A Python and Flask application.
* A system for investigating known vulnerability information.

The project is not:

* An antivirus or malware detector.
* A browser-extension warning system.
* A machine learning model that predicts whether a package is vulnerable.
* An enterprise replacement for GitHub Dependabot or Snyk.
* An automatic patching system.
* A system that considers absence from the database as proof that software is safe.

SecureDep reports known vulnerability information contained in its available data sources. Final remediation decisions remain the responsibility of the developer or security professional.

## 4. Technology Stack

### Backend and Application

* Python
* Flask
* PyMongo
* Python packaging and version utilities

### Relational Database

* MySQL 8.x

MySQL stores the normalized relational core of the system, including projects, packages, package versions, vulnerabilities, affected ranges, scan records, findings, aliases, references, and related entities.

### Document Database

* MongoDB

MongoDB stores the original nested OSV vulnerability advisory documents. This preserves arrays, nested objects, affected package information, ranges, events, severity information, and references in their source-oriented structure.

### Data Sources

* OSV Open Source Vulnerabilities
* CISA Known Exploited Vulnerabilities data

## 5. Database Architecture

SecureDep uses two database models because the vulnerability information has both relational and document-oriented characteristics.

### MySQL

MySQL is the primary relational database.

It is responsible for:

* Maintaining normalized entities.
* Maintaining primary and foreign key relationships.
* Enforcing data integrity.
* Managing project dependencies.
* Storing package and version relationships.
* Storing vulnerability relationships.
* Storing scan history and findings.
* Supporting complex SQL queries.
* Supporting views, procedures, functions, triggers, filtering, grouping, and joins.

The relational structure allows the system to represent relationships such as:

Project -> Dependency -> Package -> Package Version -> Vulnerability

### MongoDB

MongoDB is used to preserve the original nested vulnerability advisory documents.

An OSV record can contain:

* Vulnerability identifiers
* Aliases
* Summary
* Severity information
* Affected packages
* Version ranges
* Range events
* References

These structures are naturally represented as nested MongoDB documents.

MongoDB is therefore used for source-faithful advisory storage rather than duplicating the MySQL relational tables.

## 6. Data Sources

### OSV

OSV, or Open Source Vulnerabilities, is the primary vulnerability data source.

The project uses OSV vulnerability records to obtain information about:

* Vulnerability identifiers
* Affected packages
* Affected versions
* Version ranges
* Fixed versions
* Severity
* Aliases
* References

The initial implementation focuses on the PyPI ecosystem because OSV provides a dedicated PyPI dataset and the project uses Python-based dependency files.

### CISA KEV

The CISA Known Exploited Vulnerabilities catalog is an optional enrichment source.

If a vulnerability has a CVE alias that matches an entry in the KEV catalog, SecureDep can provide additional exploitation context.

A missing KEV entry is not treated as evidence that a vulnerability is safe.

## 7. Supported Input

The primary input for the MVP is a pinned Python dependency file such as:

```text
requirements.txt
```

The file should contain package names and resolved versions.

Example:

```text
package_name==1.2.3
another_package==4.5.6
```

The system parses the file and extracts the package and version information.

The following formats are considered possible future extensions:

* poetry.lock
* uv.lock
* pdm.lock
* package-lock.json
* Other ecosystem-specific dependency formats

Full transitive dependency resolution is outside the MVP scope.

## 8. System Workflow

The main SecureDep workflow is:

```text
Dependency File
       |
       v
Manifest Parser
       |
       v
Package and Version Extraction
       |
       v
MySQL Package/Version Lookup
       |
       v
Vulnerability Lookup
       |
       v
Affected Version Range Matching
       |
       v
Finding Creation
       |
       v
Severity/Alias/Reference Enrichment
       |
       v
Optional KEV Enrichment
       |
       v
Scan History and Findings
       |
       v
Security Report
```

### Step 1: Upload

The user uploads a supported dependency file containing pinned package versions.

### Step 2: Parse

SecureDep extracts package names and versions from the dependency file.

### Step 3: Resolve

The application identifies the corresponding package and package-version records in MySQL.

### Step 4: Match

The matching engine retrieves vulnerabilities associated with the package and evaluates whether the specified version falls within an affected version range.

### Step 5: Create Findings

When a vulnerability matches the dependency version, a scan finding is created.

### Step 6: Enrich

The finding can be enriched with:

* Severity
* Vulnerability aliases
* References
* Fixed version information
* CISA KEV context

### Step 7: Store

The scan and its findings are stored in the relational database.

The original vulnerability advisory is preserved in MongoDB.

### Step 8: Report

The application presents the findings to the user in a human-readable format.

## 9. Main Features

### Project Management

Users can create and manage software project records and associate dependency information with each project.

### Dependency Import

The system accepts a pinned Python dependency file and extracts package/version information.

### Vulnerability Matching

Dependency versions are checked against known vulnerability ranges.

Affected versions generate findings, while versions outside the relevant affected ranges do not generate those findings.

### Vulnerability Details

Each finding can contain:

* Vulnerability ID
* Severity
* Affected version range
* Fixed version where available
* Vulnerability aliases
* References
* KEV information where applicable

### Scan History

SecureDep stores scan information including:

* Project
* Scan date
* Scan status
* Findings associated with the scan

This allows findings to be examined over time.

### Filtering

Findings can be filtered using database-backed queries based on:

* Severity
* Package
* Ecosystem
* Resolution status
* KEV match

### Vulnerability Explorer

The application can provide a search interface for the internal vulnerability knowledge base.

Users can search using:

* Vulnerability ID
* Package
* Alias
* Ecosystem

### Reporting

The system can generate a summary containing vulnerability counts and detailed findings.

## 10. Core Database Entities

The main relational entities include:

### ECOSYSTEM

Identifies the software package ecosystem.

### PACKAGE

Stores the canonical package identity within an ecosystem.

### PACKAGE_VERSION

Stores a specific version of a package.

### PROJECT

Represents a software project being monitored.

### PROJECT_DEPENDENCY

Connects a project with the exact package version used by the project.

### VULNERABILITY

Stores the core vulnerability or advisory record.

### AFFECTED_PACKAGE

Connects vulnerabilities with packages affected by them.

### AFFECTED_RANGE

Stores vulnerability affected-version range definitions.

### RANGE_EVENT

Stores version range events such as introduced, fixed, and last affected versions.

### VULN_SEVERITY

Stores vulnerability severity assessments.

### VULN_ALIAS

Stores alternative vulnerability identifiers such as CVE, GHSA, and PYSEC identifiers.

### VULN_REFERENCE

Stores references associated with a vulnerability.

### SCAN

Represents a scan performed against a project.

### SCAN_FINDING

Stores the result of a vulnerability match produced during a scan.

### KEV_ENTRY

Stores optional CISA Known Exploited Vulnerabilities information.

## 11. Database Normalization

The relational database is designed using normalization principles.

A flat vulnerability table containing repeated packages, aliases, references, and version information could result in:

* Data redundancy
* Update anomalies
* Insertion anomalies
* Deletion anomalies

SecureDep separates these entities into related tables.

The design demonstrates:

* First Normal Form
* Second Normal Form
* Third Normal Form

Associative tables are used where many-to-many relationships exist.

For example:

```text
Vulnerability <-> Package
```

is represented through:

```text
AFFECTED_PACKAGE
```

Similarly, project dependencies are represented through:

```text
PROJECT_DEPENDENCY
```

## 12. MongoDB Document Model

The MongoDB collection used for source advisory documents is:

```text
vulnerability_documents
```

Each OSV vulnerability record is stored as one MongoDB document.

A document can contain nested structures such as:

```text
Vulnerability
├── aliases
├── summary
├── severity
├── affected
│   ├── package
│   └── ranges
│       └── events
└── references
```

MongoDB demonstrations include:

* Create
* Read
* Update
* Delete
* Aggregation
* Indexing
* Python connectivity

## 13. Dependency Matching Engine

The matching engine is responsible for connecting dependency information with vulnerability information.

The matching process is:

1. Identify the ecosystem.
2. Parse package names and versions.
3. Resolve the package and version in the relational database.
4. Retrieve vulnerabilities associated with the package.
5. Retrieve relevant affected version ranges.
6. Compare the dependency version with the affected range.
7. Create a scan finding when a match occurs.
8. Add severity, aliases, references, and optional KEV information.
9. Present the finding for human review.

The MVP uses pinned versions so that the matching process remains deterministic.

## 14. SQL and Database Demonstrations

SecureDep is designed to demonstrate several database concepts required by the DCDS course.

These include:

* SELECT queries
* INSERT, UPDATE, and DELETE operations
* Multi-table JOINs
* LEFT JOINs
* GROUP BY
* HAVING
* Subqueries
* Correlated queries
* Date filtering
* Views
* Stored procedures
* SQL functions
* Triggers
* Indexing
* Primary keys
* Foreign keys
* Constraints
* Normalization

An example complex query is:

```text
List all dependencies in a selected project that are affected by a
high or critical vulnerability for which a fixed version is known,
and indicate whether a matching CVE is present in KEV.
```

This query demonstrates how multiple relational entities and KEV enrichment can be combined.

## 15. Application Screens

The application is designed around the following major screens.

### Projects

Displays monitored software projects.

### Add/Import Project

Allows a project to be registered and a dependency file to be uploaded.

### Scan Results

Displays vulnerability findings and provides filtering options.

### Finding Detail

Displays detailed information about a selected vulnerability.

### Vulnerability Explorer

Allows users to search the internal vulnerability database.

### Scan History

Allows users to view previous scans and compare findings over time.

### Admin/Data Status

An optional screen for displaying dataset snapshot and import information.

## 16. Project Structure

The proposed repository structure is:

```text
securedep/
├── app/
│   ├── routes/
│   ├── services/
│   ├── templates/
│   └── static/
├── ingestion/
│   ├── osv/
│   └── kev/
├── db/
│   ├── mysql/
│   │   ├── schema.sql
│   │   ├── views.sql
│   │   ├── procedures.sql
│   │   └── seed.sql
│   └── mongo/
├── matcher/
├── tests/
├── data/
│   ├── raw/
│   └── sample/
├── docs/
│   └── project_source_of_truth.docx
├── requirements.txt
└── README.md
```

## 17. Testing

Testing covers the major components of the system.

### Parser Testing

Tests include:

* Valid pinned requirements
* Comments
* Blank lines
* Malformed specifications
* Duplicate packages

### Version Matching Testing

Tests include:

* Version at the lower boundary
* Version inside an affected range
* Version at a fixed boundary
* Version outside an affected range
* Multiple disjoint ranges

### Database Testing

Tests include:

* Foreign-key integrity
* Unique constraints
* Missing packages
* Duplicate vulnerability aliases
* Orphan prevention

### MongoDB Testing

Tests include:

* CRUD operations
* Aggregation
* Index existence
* Representative queries

### Scan Testing

Tests include:

* Known vulnerable dependency
* Known unaffected dependency
* Multiple vulnerabilities affecting one dependency

### Security Testing

The application should:

* Use parameterized SQL queries.
* Never execute uploaded dependency files.
* Validate uploaded file type and size.
* Sanitize UI output.
* Use least-privilege database credentials.

## 18. Security Considerations

SecureDep itself is designed with basic security practices in mind.

Uploaded dependency files are treated as plain text and are not executed.

Database operations should use parameterized queries to reduce SQL injection risks.

Input validation is required for dependency files and application forms.

Database credentials should use appropriate privileges rather than unrestricted accounts.

The application should also clearly distinguish between:

```text
No known vulnerability match
```

and:

```text
Safe
```

The absence of a vulnerability in the available database does not prove that a package is completely secure.

## 19. Reproducibility

The project uses a local vulnerability dataset for the main demonstration.

The data ingestion process records:

* Data source
* Dataset snapshot date
* Record count
* Import status
* Error count

This allows the project to be reproduced using a known dataset version.

The final ESE demonstration is intended to work without depending on a live vulnerability API.

## 20. Limitations

The current project has several defined limitations.

The MVP focuses on the Python/PyPI ecosystem.

The system primarily works with explicitly pinned dependency versions.

Full direct and transitive dependency resolution is outside the MVP scope.

The system does not automatically patch vulnerable packages.

The system does not claim that a package is safe when no vulnerability is found.

CISA KEV is treated as exploitation context rather than a universal risk score.

SecureDep does not attempt to reproduce the scale or infrastructure of enterprise Software Composition Analysis platforms.

## 21. Optional AI Extension

AI is considered an optional final-stage enhancement rather than the foundation of the project.

Possible extensions include:

### Finding Explanation

Generate a plain-language explanation of an already identified vulnerability using existing advisory information.

### Natural-Language Query

Convert controlled natural-language requests into predefined SQL queries.

AI does not replace the database-based vulnerability detection process.

## 22. Course Outcome Alignment

SecureDep demonstrates the major DCDS course outcomes.

### CO1: DBMS Principles

Demonstrated through:

* ER modelling
* Schema design
* Primary and foreign keys
* Constraints
* Relational architecture

### CO2: SQL

Demonstrated through:

* DDL
* DML
* Joins
* Subqueries
* Aggregation
* Views
* Functions
* Procedures
* Triggers

### CO3: Normalization

Demonstrated through:

* Entity decomposition
* Functional dependencies
* 1NF
* 2NF
* 3NF
* Reduction of redundancy and anomalies

### CO4: NoSQL

Demonstrated through MongoDB:

* Document storage
* CRUD
* Aggregation
* Indexing
* Python connectivity

## 23. Example Demo Workflow

A typical demonstration follows this sequence:

```text
1. Create or select a software project.
2. Upload a pinned requirements.txt file.
3. Parse package names and versions.
4. Resolve package/version records.
5. Query associated vulnerability information.
6. Evaluate affected version ranges.
7. Create scan findings.
8. Enrich findings with severity, aliases, references and KEV information.
9. Store the scan and findings.
10. Display the security report.
11. Open a detailed vulnerability finding.
12. Demonstrate an advanced SQL query.
13. Demonstrate a MongoDB aggregation or indexed lookup.
```

The final result provides evidence for developers or security professionals to investigate known dependency vulnerabilities and decide on appropriate remediation.

## 24. Real-World Context

The project is inspired by dependency security and Software Composition Analysis workflows used in industry.

GitHub Dependabot demonstrates dependency vulnerability alerts and dependency graph-based security workflows.

Snyk provides Software Composition Analysis capabilities for identifying and managing vulnerabilities in open-source dependencies.

CISA maintains the Known Exploited Vulnerabilities catalog, which can provide additional exploitation context.

SecureDep does not attempt to reproduce these platforms. It provides an academic-scale implementation focused on database design, dependency matching, vulnerability information management, and DCDS course concepts.

## 25. Project Success Criteria

The project is considered successful when:

* A real public vulnerability dataset is ingested reproducibly.
* The relational database is normalized and constrained.
* Vulnerability relationships can be queried using SQL.
* MongoDB provides a meaningful document-oriented representation.
* A dependency file can be parsed and matched against vulnerability information.
* The application produces understandable vulnerability findings.
* SQL and MongoDB concepts required by the course can be demonstrated.
* The system maintains scan history.
* The application can operate using a local dataset for the final demonstration.
* The team can clearly explain the system's scope and limitations.

## 26. Important Terminology

SecureDep uses evidence-based security terminology.

Preferred terms include:

* Known vulnerability
* Affected version
* Fixed version
* Published severity
* Vulnerability finding
* Matching KEV entry
* Vulnerability advisory

The application avoids absolute statements such as "safe package" or "unsafe package" because the system only evaluates known vulnerability information available in its data sources.

## 27. References

* OSV: Open Source Vulnerabilities
* GitHub Dependabot and Dependency Graph Documentation
* Snyk Open Source Security Management
* CISA Known Exploited Vulnerabilities Catalog
* OSV-Scanner Documentation

## 28. Conclusion

SecureDep provides a database-centered approach to software dependency vulnerability management. It combines a normalized MySQL relational model with MongoDB document storage, Python-based dependency parsing and version matching, and a Flask application for managing projects and presenting vulnerability findings.

The system demonstrates how database concepts can be applied to a practical cybersecurity problem while maintaining a clear distinction between known vulnerability detection and broader security judgment.
