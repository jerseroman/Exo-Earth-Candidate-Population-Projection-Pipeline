# Independent numerical audit - 2026-08-23

## Result

**PASS.** A hybrid cross-environment reconstruction audited the corrected
constant- and zero-completeness branches from scientific production commit
`522f1ed0f1ed041945f32b575e8ec24bf3a0f404` without changing the scientific
configuration, seeds, convergence rules, or acceptance tolerances. It reused
31 checksum-verified cloud shards, reran the one missing constant shard, and
performed the aggregate and Galactic propagation steps locally.

Agreement with the frozen aggregate baseline was evaluated for the recorded
q50 parameter and Galactic quantities. This comparison does not claim that the
full posterior intervals were independently matched.

The audit is a hybrid reconstruction: every successful GitHub Actions shard
was reused byte-for-byte after archive and internal-manifest verification, and
only the missing constant shard 14 was run locally in a version-recorded WSL2
environment with a byte-matched Python package freeze. Both branches were then
aggregated and propagated locally with the workflow's exact arguments.

## Execution evidence

The four runs in this section were executed in the private scientific
production repository, not in the public release repository. Exact
run-to-repository, workflow, commit, conclusion, and step-ceiling mappings are
recorded in [`RUN_PROVENANCE.json`](RUN_PROVENANCE.json).

- Pilot run `32581407634`: success.
- Full host/TAMS run `32581659930`: success.
- Constant run `32582964364`: 15 scientific shards succeeded; shard 14 did not
  start because of a GitHub Actions billing/account infrastructure failure.
- Zero run `32582966433`: all 16 scientific shards succeeded; its aggregate
  runner did not start because of the same infrastructure condition.
- Local constant shard 14: 25/25 realizations converged, zero optimizer
  failures, and its complete SHA-256 manifest passed.
- All 15 retained constant cloud shards and all 16 retained zero cloud shards
  passed their complete internal SHA-256 manifests. Downloaded archives also
  matched the SHA-256 digests reported by the GitHub API.

The control comparison reproduced trial 0 from a retained cloud shard. Its
perturbed catalog and perturbation audit were value-identical after documented
normalization: trial selection, removal of the optional `run_label` column,
sorting by `trial` and `source_row`, and index reset. This is not a byte-level
file-identity claim. Both MCMC runs converged, and the maximum posterior-
quantile displacement was 0.00631 of the combined interval width, below the
unchanged 0.15 control gate. The small optimizer difference (`3.74e-6` maximum
absolute difference) is classified as cross-platform floating-point drift.

## Statistical gates

| Branch | Converged | Optimizer failures | Minimum ESS | Local `Lambda_EE` median | Frozen median | Difference / combined q50 MCSE |
|---|---:|---:|---:|---:|---:|---:|
| Constant | 400/400 | 0 | 1682.3 | 3,216,665 | 3,223,846 | 0.0745 |
| Zero | 400/400 | 0 | 1658.8 | 4,566,813 | 4,572,457 | 0.0366 |

Every checked parameter q50 (`F0`, `alpha`, `beta`, and `gamma`) and Galactic
q50 (`mean_f_HZ`, `mean_f_EE`, `Lambda_HZ`, `Lambda_EE`, and their ratio)
agreed with the frozen baseline within the quadrature-combined recorded outer
q50 MCSE. No q50 comparison failed.

This is statistical reproducibility, not byte identity. MCMC path lengths can
differ after adaptive convergence checks, and floating-point optimizers can
follow slightly different platform paths. The local rounded results are 3.217
and 4.567 million, whereas the frozen values are 3.224 and 4.572 million. The
differences are far below one combined MCSE. The audit therefore validates the
checked q50 and headline-median reproducibility rather than replacing the
immutable frozen v4 baseline; it does not establish agreement of the full
posterior intervals.

## Environment and hashes

The local run used Windows 11 with WSL 2.7.12, Ubuntu 22.04.5 LTS, Python
3.10.12, and the exact scientific package versions present in all 31 retained
cloud environment records. The cloud runners recorded Python 3.10.21; package
versions were otherwise byte-identical.

The machine-readable record
[`INDEPENDENT_NUMERICAL_AUDIT_20260823.json`](INDEPENDENT_NUMERICAL_AUDIT_20260823.json)
contains the exact run IDs, commit, environment, convergence/ESS evidence,
headline comparisons, and artifact/manifests SHA-256 values.

Redistribution-cleared control, comparison, aggregate-summary, checksum, and
representative environment records are bundled under
[`independent-audit-evidence/`](independent-audit-evidence/). The accompanying
README distinguishes those public records from row-level, large, path-bearing,
or private-download evidence retained only by hash.

The numerical audit process itself did not create or modify a GitHub release,
Zenodo record, manuscript, or PDF. Later publication state is governed by the
release metadata and does not change the numerical audit result.
