# CodeLedger

## Database-Driven Software Dependency Vulnerability Management System

CodeLedger is a cybersecurity application designed to identify and manage known vulnerabilities in software dependencies. It analyzes dependency packages and their specific versions against structured vulnerability information and presents relevant security findings for review.

The system uses a database-centric architecture to maintain relationships between software projects, dependencies, packages, package versions, vulnerabilities, affected version ranges, severity information, aliases, references, and scan findings.

## Key Features

* Software project and dependency management
* Dependency file parsing and package-version identification
* Vulnerability detection based on affected version ranges
* Vulnerability severity and advisory information
* Vulnerability aliases and references
* Scan history and findings management
* Filtering of vulnerability findings
* Optional CISA KEV enrichment
* Database-backed vulnerability reporting

## Technology Stack

* **Frontend/Application:** Python, Flask, HTML, CSS
* **Relational Database:** MySQL
* **Document Database:** MongoDB
* **Vulnerability Data:** OSV
* **Additional Security Data:** CISA Known Exploited Vulnerabilities (KEV)

## Database Architecture

MySQL serves as the normalized relational database for storing projects, dependencies, packages, versions, vulnerabilities, affected ranges, scans, and findings. It maintains the relationships and integrity constraints required for dependency and vulnerability management.

MongoDB stores the original nested vulnerability advisory documents from OSV. This allows complex advisory structures such as affected packages, version ranges, severity information, aliases, and references to be preserved in document form.

## Vulnerability Matching

CodeLedger parses dependency information and identifies the corresponding package and version records. The matching engine evaluates those versions against known vulnerability ranges and generates findings when a dependency is affected.

Findings can be enriched with severity, fixed-version information, vulnerability aliases, references, and optional KEV information.

## Data Source

OSV is used as the primary source of open-source vulnerability information. The initial project scope focuses on the PyPI ecosystem and pinned Python dependency versions.

CISA KEV data is used as an optional source of known-exploitation information for vulnerabilities with matching CVE identifiers.

## Application Workflow

The application follows a database-backed workflow consisting of project management, dependency import, package and version resolution, vulnerability matching, finding creation, scan storage, and result presentation.

## Database Concepts

CodeLedger demonstrates core database concepts including:

* Entity-relationship modelling
* Relational schema design
* Primary and foreign keys
* Normalization
* SQL joins and aggregation
* Subqueries
* Views, procedures, functions, and triggers
* MongoDB CRUD operations
* MongoDB aggregation and indexing
* Python database connectivity

## Scope

CodeLedger focuses on known dependency vulnerabilities and provides information for security investigation and remediation planning. It does not automatically patch dependencies, detect malware, or treat the absence of a vulnerability match as proof that a package is completely safe.

## Project Structure

The project is organized into application, data ingestion, database, matching engine, testing, data, and documentation components. This separation supports maintainability, database management, vulnerability processing, and application development.

## Objective

The objective of CodeLedger is to provide a practical database-driven solution for software dependency vulnerability management while demonstrating the application of relational and NoSQL database concepts to a real-world cybersecurity problem.
