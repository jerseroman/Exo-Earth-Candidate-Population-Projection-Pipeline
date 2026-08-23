# Phase 2 corrected-posterior numerical freeze

Status: **STATISTICAL GATE PASS**

> Historical phase snapshot. The remaining-gate statements at the end record
> the state when this numerical freeze was created. Host/TAMS, DR25 support,
> sensitivity, and the hybrid cross-environment numerical audit/reconstruction
> are now documented in the
> later frozen validation records and `provenance/INDEPENDENT_NUMERICAL_AUDIT_20260823.json`.

This report freezes the corrected Bryson occurrence-posterior computation before
any v4 manuscript, table, or figure work. The constant- and zero-completeness
branches remain separate model scenarios; their spread is not a confidence
interval.

## Immutable execution record

- Extended adaptive-MCMC pilot: GitHub Actions run `32470830404` (success).
- Initial 400-realization-per-branch production: run `32472776218`.
  The constant branch passed. The zero branch was stopped by the predeclared
  convergence gate because global trials 157, 253, 320, 360, and 365 reached
  the 20,000-step ceiling without two consecutive qualifying tau checks.
- Clean full zero-branch rerun: run `32506666772` (success). It retained the
  original outer and MCMC seeds, the 100-tau length requirement, 5% successive
  tau tolerance, and two-stable-check requirement; only the maximum production
  ceiling changed from 20,000 to 30,000 steps.
- Constant-branch Galactic propagation artifact: run `32527877921` (success).
- Source commit for the final zero rerun: `49a1689f8ef87cd3789f9ad9250dda66d9c39d40`.
- Source commit for the frozen constant propagation: `932726b651aa862e5af0bbe4ddc946b45170c90c`.

No failed realization was discarded and no convergence threshold was relaxed.

## Convergence and Monte Carlo gates

| Quantity | Constant | Zero |
|---|---:|---:|
| Outer realizations | 400 | 400 |
| Adaptive realizations converged | 400 | 400 |
| Optimizer failures | 0 | 0 |
| Production steps, min / median / max | 8,000 / 12,000 / 17,000 | 9,000 / 14,000 / 22,000 |
| Minimum per-realization ESS over all four parameters | 1,682.32 | 1,662.35 |
| Largest outer q50-MCSE / q16--q84 width, parameters | 1.63% | 1.56% |
| Largest inner q50-MCSE / q16--q84 width, parameters | 0.10% | 0.15% |
| Independent MCMC-seed stability | PASS | PASS |

The measurement-error mode is `quantile_matched_two_sided` in every production
realization. Equal outer-realization weights are enforced after retaining 1,024
posterior rows per realization. Outer Monte Carlo error is estimated by
resampling whole reliability/measurement realizations; posterior rows are not
treated as independent outer draws.

## Frozen posterior results

All intervals below are posterior 2.5%, 16%, 50%, 84%, and 97.5% quantiles.
Occurrence quantities are planets per star, not fractions of stars.

| Scenario | Quantity | q2.5 | q16 | q50 | q84 | q97.5 |
|---|---|---:|---:|---:|---:|---:|
| Constant | `F0` | 0.4261 | 0.6552 | 1.1106 | 2.0306 | 3.8321 |
| Constant | mean `f_HZ` | 0.0645 | 0.1601 | 0.3883 | 0.9070 | 1.9967 |
| Constant | mean `f_EE` | 0.00248 | 0.00579 | 0.01226 | 0.02353 | 0.04121 |
| Constant | `Lambda_HZ` | 1.697e7 | 4.210e7 | 1.021e8 | 2.386e8 | 5.252e8 |
| Constant | `Lambda_EE` | 6.520e5 | 1.522e6 | 3.224e6 | 6.189e6 | 1.084e7 |
| Zero | `F0` | 0.5229 | 0.8732 | 1.6174 | 3.2258 | 6.6480 |
| Zero | mean `f_HZ` | 0.0965 | 0.2537 | 0.6591 | 1.6216 | 3.7502 |
| Zero | mean `f_EE` | 0.00338 | 0.00799 | 0.01738 | 0.03388 | 0.06021 |
| Zero | `Lambda_HZ` | 2.539e7 | 6.675e7 | 1.734e8 | 4.266e8 | 9.865e8 |
| Zero | `Lambda_EE` | 8.884e5 | 2.103e6 | 4.572e6 | 8.912e6 | 1.584e7 |

These are conditional on the frozen JJ/PARSEC/TAMS host model and the stated
1-Earth-mass conservative-HZ construction. They do not include JJ
normalization uncertainty, isochrone-family uncertainty, TAMS-selector model
risk, climate-model uncertainty, multiplicity mismatch, or Galactic occurrence
transport uncertainty.

## Evidence hashes

- Constant aggregate summary:
  `8472f8b8a431d3e9a3f8fded5b40b8bab6f1f8e2d2368e44bc6816e716d960b1`
- Constant Galactic summary from run `32527877921`:
  `5ff8de0d86c62c71c10b80cb9356df48abbe21f773a9c84f7ea67fe8a0f12945`
- Zero aggregate summary:
  `37217bf026addf201c3f46354324b55c2bbcb9afb1b28f86197a98fcc79bc85c`
- Zero Galactic summary:
  `86752103927ddb8bccb45c047ee55b1deeed10b7f621255f7756da1786b1f73c`
- Frozen host summary:
  `4cacc8f46636a4249c1740f0faf82291004dd0b2b5c3b903e8a854ce1e20ccb0`
- Frozen raw eligible-host table:
  `a2b6f407c70c236f2be9a9084f53fe9ba461f06aa5f44d6caae11696467e5a28`
- Audit-time machine-readable freeze record, before the later metadata-only
  provenance correction:
  `e37a4add5f0fbbb7363252adb2f85a41b0fbd1f4572761f90dc285ddd2b476eb`
- Current machine-readable freeze record distributed in v4.0.1:
  `a4ce3d7f9f3ad0c35c33df6ae24e9457e5f88d2d90d36c196f7aea253d7ca6ea`

## Remaining scientific gates

The radial-grid sensitivity is numerically accepted. The subsequent host/TAMS
audit passed the canonical-selector checks while rejecting and removing the
invalid archived metallicity-dependent differential from this freeze. A valid
metallicity-dependent low-mass TAMS sensitivity remains **OPEN** as a model
systematic, not as a numerical correction. DR25 support validation remains a
separate gate. This phase therefore still does not authorize manuscript or
figure production.
