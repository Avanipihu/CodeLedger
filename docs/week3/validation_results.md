# CodeLedger — Week 3 Relational Architect Validation

## Database and ingestion

- Validation database: `codeledger_final`
- MySQL version: 8.0.46
- Schema inventory: all 20 tables defined in `schema.sql` are present.
- OSV PyPI ingestion: 26,236 records loaded; zero failures and zero warnings.
- MongoDB writes were disabled during this ingestion.

## Existing SQL query suite

The repository's existing `queries.sql` ran against `codeledger_final`
through the safe query runner without visible SQL errors.

The output included the seeded CodeLedger Demo scan and synthetic advisories.
These results validate the query suite against the demo fixtures; they do
not represent a scan of a real dependency manifest.

## Performance and indexing

All 11 `ANALYZE TABLE` operations in the performance script returned OK.

For the `vulnerability_alias` lookup by `alias_value`:

- Before the new index, EXPLAIN reported access type `index` and an
  estimated 35,137 index entries.
- After adding `idx_alias_value_vulnerability`, EXPLAIN selected that
  index, reported access type `ref`, and estimated one row.

This supports the index based on the query plan. These figures are optimizer
estimates, not measured execution times.

The index was added to both `codeledger_final` and the repository's
`schema.sql`. The schema diff was checked with `git diff --check`.

## Integrity and consistency

The captured integrity checks reported zero violations for:

- Orphan relationships in the checked tables.
- Scan/dependency project mismatches.
- Finding/range vulnerability or package mismatches.
- Duplicate package identities, package versions, aliases, affected-package
  relationships, range-event orders, and scan findings.

## Update behaviour

The project-description transaction test confirmed that:

- The demo project existed before and during the update.
- Its seven dependencies remained unchanged.
- The temporary description was visible inside the transaction.
- After rollback, the temporary description no longer remained, and all
  seven dependencies were still present.

## Project deletion behaviour

The deletion test confirmed that, inside the transaction, deleting the demo
project cascaded to its project dependencies, scans, and scan findings.

The shared package, package-version, and vulnerability counts remained
unchanged. Rolling back restored the project and its dependent records.

## Remaining review

The normalization justification and ERD are included alongside this report.
Before submission, ensure the normalization explanation reflects the final
schema, and review the exported ERD for its tables, columns, keys, and
relationships.

The captured checks support the tested integrity and deletion behaviour;
they do not constitute a proof of every possible database invariant.
