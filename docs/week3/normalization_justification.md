# CodeLedger Relational Schema: Normalization Justification

## Scope

The MySQL schema models structured package, advisory, affected-version/range, project, scan, finding, and KEV data. It is a relational representation of the fields CodeLedger needs for matching and reporting. MongoDB is used separately to preserve the original nested OSV documents; storing nested source documents there does not require flattening their entire structure into the relational schema.

The design contains 20 relational tables. It separates entities with independent identities, stores repeating values in child rows, and uses foreign keys and unique constraints to protect important relationships.

## First Normal Form (1NF)

1NF requires each field to store a single value for a row, rather than a list of repeating values. CodeLedger follows this by representing repeated advisory fields as separate rows:

- `vulnerability_alias`: one alias per row.
- `vulnerability_severity` and `affected_package_severity`: severity records at advisory and affected-package scopes, respectively.
- `vulnerability_reference`: one reference URL per row.
- `affected_version`: one explicit affected version per row.
- `affected_range` and `range_event`: ranges are separate rows, and each ordered introduced/fixed/last-affected/limit event is stored separately.
- `kev_entry_cwe` and `vulnerability_kev`: relationships between KEV entries, CWEs, and OSV vulnerabilities are represented as rows instead of delimited lists.

This representation supports filtering, joining, constraints, and indexes on the individual values.

## Second Normal Form (2NF)

2NF requires 1NF and no non-key attribute depending on only part of a candidate key. The schema primarily uses single-column surrogate primary keys. Unique alternate keys express natural business identity and prevent duplicates. Examples include:

- `packages`: `(ecosystem_id, name)`.
- `package_versions`: `(package_id, version)`.
- `vulnerability_alias`: `(vulnerability_id, alias_value)`.
- `affected_package`: `(vulnerability_id, package_id)`.
- `affected_version`: `(affected_package_id, version)`.
- `affected_range`: `(affected_package_id, range_ordinal)`.
- `range_event`: `(range_id, event_order)`.
- `kev_entry_cwe`: `(cve_id, cwe_id)`.
- `vulnerability_kev`: `(vulnerability_id, cve_id)`.

For example, `range_event.event_value` belongs to a particular event position within a range; it is not a property of the range alone. The unique key `(range_id, event_order)` represents that full event identity.

## Third Normal Form (3NF)

3NF requires non-key attributes to depend on the key, the whole key, and nothing but the key. The schema keeps descriptive facts with the entity they describe, rather than copying them across dependent records:

- Ecosystem names are stored in `ecosystems`; packages reference `ecosystem_id`.
- Package names and ecosystem identity are stored in `packages`; version strings live in `package_versions`.
- `project_dependencies` references a package version instead of copying its package name, ecosystem, and version string.
- `scan_findings` references the scan, dependency, and vulnerability; it does not copy the advisory summary, aliases, severity records, or package metadata into each finding.
- `affected_package` represents the advisory-to-package association. Package-specific severity, explicit affected versions, and ranges are stored in their own dependent tables.
- Aliases, references, severity records, range events, and CWE associations are separate because each parent can have multiple related records.

These separations reduce update anomalies. Updating a vulnerability summary requires changing the vulnerability row, not each finding that refers to it. Adding an alias or range creates a child row and does not rewrite a list embedded in a parent row.

## Referential integrity and deletion behavior

Foreign keys prevent rows from referencing absent parent records. The schema uses cascades for dependent records whose lifecycle belongs to the parent, such as aliases, references, affected ranges/events, project dependencies, scans, and findings. It uses `RESTRICT` where deleting a shared package/version or referenced vulnerability could invalidate a relationship. `scan_findings.matched_range_id` uses `SET NULL`, allowing a finding to remain when its matched range is removed while recording that the range link is no longer available.

The deletion test in `week3_deletion_behavior_test.sql` transactionally deletes the seeded demo project, checks the dependent counts, and rolls the transaction back. It should demonstrate cascading deletion of the project's owned scan/dependency records without removing shared package or vulnerability catalogue entries. The rollback preserves the fixture for later demonstrations.

## Integrity limits

Foreign keys alone do not guarantee every cross-table business rule. For example, the base schema's ordinary FKs do not by themselves ensure that a finding's scan and dependency belong to the same project, or that a selected range belongs to the same vulnerability and package represented by the finding. `week3_integrity_checks.sql` reports such mismatches separately. These checks should be zero; if stronger prevention is required, enforce the rules with application validation or explicitly installed database triggers.

## Conclusion

The design applies 1NF by placing repeating values in separate rows, 2NF by defining entity and association keys, and 3NF by keeping each descriptive fact with its owning entity or relationship. Unique constraints and foreign keys protect relational integrity and reduce insertion, update, and deletion anomalies. The accompanying Week 3 SQL files provide measurable integrity, deletion-behavior, and query-plan checks against the clean final database.
