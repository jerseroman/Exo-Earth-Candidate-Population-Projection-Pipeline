# V4 statistics phase 1: measurement-error propagation

Date: 2026-08-21

> Historical phase snapshot. Its "NOT STARTED" and "future" statements record
> the gate state on 2026-08-21; they are superseded by the completed frozen
> baseline in `research/v4-validation/frozen-statistical-baseline/` and the
> independent audit in `provenance/INDEPENDENT_NUMERICAL_AUDIT_20260823.json`.

## Repository and scope boundary

- Immutable v3 reference: `archive/exoearth-annulus-v3-20260820` at
  `5a3528aea6d6f28da8e9db4d40f0c84cbb43d501`.
- Isolated statistics worktree, starting this phase at
  `e169dabfb7e5a2d3fec1da618103141a09789826`.
- The archived article source was inspected only as a tree reference and was
  not copied, rebuilt, or edited.
- The existing `main` checkout and its unrelated local changes were not used or
  modified.
- No manuscript, PDF, figure, optimization, or MCMC run belongs to this phase.

## Implemented statistical modes

`legacy_source_mixture` preserves the public Bryson notebook's random-number
consumption, signed-normal perturbations, and omission of the post-perturbation
temperature filter. It exists only as the source-faithful regression reference.

`quantile_matched_two_sided` implements

```text
B ~ Bernoulli(0.5)
U = abs(Z), Z ~ Normal(0, 1)
X = mu - sigma_minus * U, if B = 0
X = mu + sigma_plus  * U, if B = 1
```

and reapplies all source-domain conditions after perturbation:

```text
0.2 <= instellation <= 2.2
0.5 <= radius <= 2.5
3900 <= Teff <= 6300 K
```

The runner records the selected mode in its summary and trial diagnostics. It
also writes a row-level perturbation audit for every reliability-selected
catalog object, including the perturbed values, all domain flags, the active
selection decision, and an explicit audit status.

The aggregator rejects mixed legacy/corrected shards, can require an expected
mode explicitly, verifies diagnostic agreement, and preserves the combined
row-level perturbation audit. Pre-v4 summaries without mode metadata are
explicitly interpreted as legacy rather than silently treated as corrected.

## Automated verification

The measurement-only suite contains 10 tests and passed in full. It covers:

- bitwise identity of the legacy mode against the pre-v4 inline algorithm;
- empirical recovery of the requested corrected quantiles;
- inclusive post-perturbation `Teff` boundaries and corrected rejection outside
  them;
- invalid uncertainty and unknown-mode rejection;
- inferred legacy metadata for pre-v4 shards;
- mixed-mode, expected-mode, and diagnostic-mode aggregation failures;
- preservation of the corrected row-level audit through aggregation.

The test environment was Python 3.12.13, NumPy 2.3.5, and pandas 3.0.1. The
integration test also exposed and fixed an existing pandas-version-sensitive
`groupby.apply` thinning path. The replacement uses an explicit within-trial
row index and therefore retains `global_trial` while selecting the same
every-nth rows.

## Real-catalog measurement-only regression

The read-only regression used the pinned Bryson repository at
`d200f54b6f0df49e0dae530e69983cdce5397bfb`, seed `2026081901`, and these
inputs:

- `PCs_dr25_hab2.csv`, SHA-256
  `5cf4805d8742507ead6916dcd1f7b118b7e5a28966b9ddd5b8d09fc6e181115c`
  for the historical Windows CRLF checkout. The pinned source bytes use LF
  and SHA-256 `c8ae78fcfe4ed27bbe972b1041a3e370031a4f94afea4ad35dd7bd47834c140b`;
  all 2,278 parsed CSV lines are semantically unchanged;
- `dr25_stellar_berger2020_clean_hab2.txt.zip`, SHA-256
  `a5d09eeec307509aa458b5ef6620dfdcfdd144fd0ac35aed1ab4951bc7955041`.

After the stellar merge, the catalog contained 2,277 rows. Both modes made the
same 2,069-row reliability selection for the fixed seed.

| Diagnostic | Legacy | Corrected |
|---|---:|---:|
| Retained by active policy | 41 | 39 |
| Outside instellation domain | 1,987 | 1,985 |
| Outside radius domain | 663 | 671 |
| Outside temperature domain | 55 | 51 |
| Outside any of the three domains | 2,028 | 2,030 |

The legacy retained rows and all three perturbed arrays were bitwise identical
to the pre-v4 implementation. The difference between 41 and 39 is only a
fixed-seed input diagnostic; it is not a posterior estimate and must not be
reported as a scientific result.

## Gate status

Measurement-error implementation and regression gate: **PASS**.

MCMC/convergence/MCSE gate: **NOT STARTED**. A future corrected MCMC command
must explicitly select `quantile_matched_two_sided`, and its aggregator must
explicitly require the same mode. No manuscript or figure work may begin before
the corrected numerical results are frozen and independently audited.
