# V4 corrected joint-posterior protocol

## Target distribution

For each reliability and catalog-measurement realization `r`, the runner samples
the conditional Bryson Model 1 posterior

`p(theta | D_r, C_b) proportional to L(D_r | theta, C_b) p(theta)`,

where `theta = (F0, beta_inst, alpha_radius, gamma)` in source-code order and
`C_b` is either the constant- or zero-completeness branch. The two completeness
branches are separate model scenarios. They are never pooled into a credible
interval or assigned implicit model probabilities.

The v4 primary analysis uses `quantile_matched_two_sided` catalog perturbations.
`legacy_source_mixture` remains available only for source-faithful regression.

## Random streams

Each outer realization has a recorded reliability/measurement seed. The MCMC
stream has a separately recorded seed obtained with `--mcmc-seed-offset`. Two
pilot families use identical outer realizations and different MCMC offsets, so
their difference diagnoses the sampler rather than a change in catalog draws.

## Production convergence gates

- 16 ensemble walkers for four dimensions.
- 1,000 discarded burn-in steps.
- At least 3,000 post-burn production steps.
- Autocorrelation time checked every 1,000 production steps.
- Every parameter must satisfy `N_steps >= 100 tau`.
- The largest relative change in successive `tau` estimates must be at most 5%.
- Both the length and stability conditions must pass at two consecutive checks.
- The constant-production safety ceiling is 20,000 post-burn steps per
  realization. The clean zero-completeness rerun uses an audited 30,000-step
  ceiling with identical seeds and unchanged convergence criteria.
- Aggregation fails unless every realization passes the adaptive gate and has a
  finite four-parameter autocorrelation estimate.

Because the length gate is applied per parameter and per realization, it implies
an ensemble effective sample size of at least `16 * 100 = 1,600` for the slowest
parameter in every accepted realization. The numerical-freeze audit also
enforces `ESS >= 1,000` as a separate, weaker sanity gate on the serialized
diagnostics. It does not replace or relax the online `N_steps >= 100 tau`
adaptive condition; it catches missing or inconsistent ESS evidence.

## Outer-realization mixture

There are 400 reliability/measurement realizations per completeness branch.
Adaptive chains have different raw lengths, so the aggregator selects 1,024
deterministic, evenly spaced post-burn rows from each realization. This gives
every outer realization exactly the same mixture weight and prevents long chains
from acquiring greater scientific weight merely because they mixed more slowly.

## Monte Carlo error

Posterior quantiles are accompanied by two distinct diagnostics:

1. **Outer-realization Monte Carlo standard error.** A cluster bootstrap resamples
   all rows of an outer realization as a single cluster. It never treats pooled
   posterior rows as independent reliability/measurement draws.
2. **Inner-chain Monte Carlo standard error.** Matched contiguous post-burn blocks
   retain every outer realization and quantify residual within-chain variation.

The freeze gate requires the median (`q50`) MCSE from each component to be below
10% (outer) and 5% (inner) of the corresponding posterior `q16`--`q84` width.

## Interpretation

The pooled result approximates an equal mixture of conditional posteriors over
the implemented reliability and catalog-measurement mechanism. It is not the
missing historical Bryson chain, and its intervals do not include JJ Galactic
population uncertainty, isochrone-family uncertainty, TAMS transport
uncertainty, climate-model uncertainty, or between-branch model uncertainty.
