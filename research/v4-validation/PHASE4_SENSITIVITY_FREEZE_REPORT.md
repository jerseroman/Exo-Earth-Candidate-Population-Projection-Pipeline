# Phase 4 audited sensitivity freeze

Status: **SENSITIVITY REGISTER FROZEN; CONDITIONAL MODEL PROJECTION ONLY**

This register separates posterior scenarios, numerical convergence tests,
model alternatives, climate-boundary perturbations, alternative estimands,
categorical validation failures, and unparameterized systematic risks. These
entries are not exchangeable random errors and are not combined into a single
uncertainty interval.

## Provenance gate

The canonical JJ sensitivity artifact from GitHub Actions run `31358271145`
in `jerseroman/are-we-alone-in-the-universe`, workflow
`.github/workflows/jj-g-host-export.yml`, commit
`f9cbe74bfd791ebfb26dc48ff39d54f37dea263d`, was downloaded and checked
against its complete internal SHA-256 manifest. This is a host/TAMS workflow,
so no MCMC step ceiling applies. The exact run URL and repository mapping are
also recorded in `provenance/RUN_PROVENANCE.json`. The three inputs used here
match their declared hashes:

- Bryson model-form sensitivity:
  `3f0d3de2fda3b40aca508ba855babf976f55141ff90527a9e3b7d2acaf371f21`;
- HZ and planet-mass sensitivity:
  `c4b6bf5229f6940a88a650ef2bc4223c93adb49e3a216354623f134f7698357e`;
- branch and spatial-domain matrix:
  `6748765e049d49be19f82b363771d56f9cde9bcedbaaeb6c4b1fb819402d9c1b`.

Their canonical plug-in anchors reproduce 263,061,992.37 hosts and
`Lambda_EE = 3,376,462.67` before any comparison is accepted.

## Posterior-level scenario and implementation sensitivities

| Comparison | Basis | Median `Lambda_EE` change | Interpretation |
|---|---|---:|---|
| Legacy versus corrected measurement propagation | Constant posterior | +0.0263% | Negligible at the median; corrected propagation remains primary |
| Zero versus constant completeness | Separate posterior q50 values | +41.8324% | Alternative model scenario, not a credible-interval component |
| Legacy fixed-`logg` versus TAMS host selector, constant | Posterior q50 | -28.5832% | Material host-model sensitivity |
| Legacy fixed-`logg` versus TAMS host selector, zero | Posterior q50 | -29.5784% | Material host-model sensitivity |

The corrected constant and zero medians are 3,223,845.60 and 4,572,456.81.
The completeness branches remain separate throughout v4.

## Numerical and weighting checks

| Check | Plug-in change in `Lambda_EE` | Status |
|---|---:|---|
| Native solar TAMS curve without the 5200 K anchor | 0.0000% | PASS |
| Radial grid 0.5 to 0.25 kpc | +0.2312% | PASS, below 1% gate |
| JJ-weighted versus uniform 5300--6000 K average | +0.3798% | Small weighting diagnostic |

The +0.2312% sensitivity uses the canonical 0.5-kpc result as the denominator,
`(fine - coarse) / coarse`. The radial-convergence report's +0.2307% uses the
fine-grid denominator, `(fine - coarse) / fine`; both describe the same pair of
computed L2 values.

These checks do not dominate the scientific uncertainty.

## Occurrence-model and climate sensitivities

| Comparison | Plug-in change in `Lambda_EE` | Evidence role |
|---|---:|---|
| Bryson Model 2 versus Model 1 | +3.2962% | Published point estimates only; no Model-2 posterior |
| Runaway-greenhouse flux boundary x0.99 | -3.6652% | Numerical boundary perturbation |
| Runaway-greenhouse flux boundary x1.01 | +2.7116% | Numerical boundary perturbation |
| Runaway-greenhouse flux boundary x0.95 | -24.8424% | Numerical boundary perturbation |
| Runaway-greenhouse flux boundary x1.05 | +7.1521% | Numerical boundary perturbation |
| Kopparapu 0.1-Earth-mass runaway prescription | -57.2801% | Alternative published climate prescription |
| Kopparapu 5-Earth-mass runaway prescription | +7.1521% | Alternative published climate prescription |
| Optimistic versus conservative HZ | +7.1521% | Different HZ estimand |

The asymmetric response occurs because the 0.9--1.1 instellation box is
intersected with the temperature-dependent HZ boundary. The planet-mass rows
change the runaway-greenhouse prescription; they do not model the unknown
planet-mass distribution inside the radius interval.

The Model-2 point-estimate comparison is not evidence that arbitrary
functional forms are controlled. This limitation is especially important
because the exact target contains no nominal DR25 candidates.

## Alternative spatial estimands

Changing the radial integration domain changes the question being asked. At
the constant-completeness plug-in, 6--10 kpc yields +102.10% and the full JJ
4--14 kpc disk yields +358.43% relative to the 7--9 kpc annulus. These values
must not be interpreted as error bars on the annulus result.

## Categorical failures and open systematics

- Direct local DR25 target support: **FAIL**. There are zero nominal candidates,
  and more than 95% of corrected realizations contain zero target candidates.
- Archived metallicity-dependent TAMS sensitivity: **FAIL AND EXCLUDED**.
  No replacement quantitative value is available.
- JJ normalization and parameter uncertainty: **OPEN**.
- Isochrone-family dependence: **OPEN**.
- Radial migration and birth-radius interpretation: **OPEN**.
- Kepler-to-Galaxy occurrence transport across age, metallicity,
  alpha-enhancement, multiplicity, and environment: **OPEN**.

No defensible probability distributions have been specified for these open
risks, so quadrature, envelope, or ad hoc percentage combination would create
a false uncertainty statement.

## Manuscript decision

The numerical posterior can proceed to literature comparison and manuscript
preparation only as a **conditional parametric model projection**. V4 must
foreground the zero local DR25 support result, present the completeness
branches separately, show major sensitivities outside the posterior interval,
and avoid claims of a direct local candidate-supported Galactic measurement.

Machine-readable evidence is frozen in
`frozen-sensitivities/V4_SENSITIVITY_FREEZE.json` with SHA-256
`a38129519d4f4b8c58fe63a5c21b880e8764c6957144d10af1b3c4d90a3ce1fd`.
