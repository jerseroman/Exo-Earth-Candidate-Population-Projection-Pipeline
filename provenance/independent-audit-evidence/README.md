# Independent numerical-audit evidence boundary

This directory contains the redistribution-cleared, non-row-level records used
to support the independent audit summarized in
`../INDEPENDENT_NUMERICAL_AUDIT_20260823.json`.

Bundled exact records:

- `control_comparison.json`: one cloud/local control comparison;
- `local_vs_frozen_comparison.json`: all checked local-versus-frozen q50
  summary comparisons;
- both `joint_posterior_*_aggregate_summary.json` files;
- both aggregate checksum manifests and both Galactic checksum manifests; and
- `numerical_environment.txt`, the representative package freeze whose bytes
  matched all 31 retained cloud environment records.

These files contain no catalog rows, manuscript source, PDF, credentials, or
absolute local filesystem paths. Their exact SHA-256 values are recorded in the
machine-readable audit.

The four bundled `SHA256SUMS_*` files are upstream output inventories retained
as provenance records, not package-wide manifests whose every target is
distributed here. Most targets named by those inventories are deliberately
absent. Only the two aggregate summary JSON targets are also present in this
directory; the remaining lines anchor retained-private artifacts by hash.

Not distributed:

- row-level perturbation audits, host tables, posterior chains, and Galactic
  draws, because their redistribution status is unresolved or their size is
  unsuitable for this source release;
- the two posterior correlation CSV files named by the aggregate summaries;
  their hashes are retained in the corresponding upstream inventories;
- the exact Galactic summary JSON files, because they contain absolute private
  execution paths; their numerical checks are represented in the audit and the
  bundled comparison record; and
- private artifact-download logs, because they describe access to private
  Actions artifacts. Their hashes remain in the audit as retained-private
  evidence and are not presented as publicly retrievable objects.

The public package therefore supports integrity and internal-consistency
verification of the committed summaries. A full numerical rerun additionally
requires the locked external inputs listed in `../DATA_LOCKS.json` and a private
execution environment.
