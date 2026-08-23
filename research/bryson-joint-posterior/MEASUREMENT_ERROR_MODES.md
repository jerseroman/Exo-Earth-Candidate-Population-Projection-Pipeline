# Measurement-error modes for the v4 statistics branch

> Historical phase snapshot (2026-08-21). Statements about a "future"
> corrected run describe the state at that phase. The completed numerical
> baseline and hybrid cross-environment audit/reconstruction are recorded in
> `research/v4-validation/frozen-statistical-baseline/` and
> `provenance/INDEPENDENT_NUMERICAL_AUDIT_20260823.json`.

This directory keeps the public-notebook behavior and the corrected v4
behavior as two explicit, non-interchangeable modes. Neither mode combines the
constant- and zero-completeness branches.

## `legacy_source_mixture`

This is the regression reference. For each variable, the public notebook first
selects the reported lower or upper scale with probability 0.5 and then
multiplies that scale by a signed standard-normal deviate. Since `Z` and `-Z`
have the same distribution, the result is an equal-weight symmetric mixture of
two Gaussian scales, not an asymmetric two-sided error distribution.

The mode intentionally retains the notebook's post-perturbation filters:

- `0.2 <= instellation <= 2.2`;
- `0.5 <= radius <= 2.5`;
- the optional orbital-period cutoff, when requested.

It intentionally does not reapply `3900 <= Teff <= 6300 K`. The audit output
marks every such row as outside the temperature source domain but not filtered
in legacy mode.

## `quantile_matched_two_sided`

The corrected construction is

```text
B ~ Bernoulli(0.5)
U = abs(Z), Z ~ Normal(0, 1)
X = mu - sigma_minus * U, if B = 0
X = mu + sigma_plus  * U, if B = 1
```

It has the requested quantiles

```text
Q_0.158655 = mu - sigma_minus
Q_0.5      = mu
Q_0.841345 = mu + sigma_plus
```

After perturbation, it reapplies all three source-domain filters:

- `0.2 <= instellation <= 2.2`;
- `0.5 <= radius <= 2.5`;
- `3900 <= Teff <= 6300 K`.

Every reliability-selected catalog row is written to the perturbation-audit
CSV with its perturbed values, domain flags, active-policy decision, and an
explicit inclusion or exclusion reason.

## Regression and execution boundary

Run the measurement-only tests with:

```text
python research/bryson-joint-posterior/test_measurement_error.py
```

The runner defaults to `legacy_source_mixture` so existing source-faithful
commands cannot silently change interpretation. A future corrected MCMC run
must explicitly pass:

```text
--measurement-error-mode quantile_matched_two_sided
```

The aggregator can be locked against accidental shard mixing with:

```text
--expected-measurement-error-mode quantile_matched_two_sided
```

No MCMC result is produced or accepted by the measurement-only test suite.
