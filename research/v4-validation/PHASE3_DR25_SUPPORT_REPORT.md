# Phase 3 DR25 target-support validation

Status: **GEOMETRIC SUPPORT PASS; LOCAL EMPIRICAL SUPPORT FAIL**

The v4 Earth-analog target is the intersection of 0.9--1.1 Earth radii,
0.9--1.1 Earth instellation, the 1-Earth-mass Kopparapu conservative habitable
zone, and 5300--6000 K. This audit asks two distinct questions: whether that
target lies inside the fitted Bryson/DR25 coordinate domain, and whether DR25
contains planet candidates locally inside the target.

## Source-domain containment

The target is wholly inside the fitted rectangular domain of 0.5--2.5 Earth
radii, 0.2--2.2 Earth instellation, and 3900--6300 K. Geometric containment is
therefore **PASS**. This means the integration does not cross the declared
coordinate limits of the fitted model; it does not establish direct empirical
support.

The exact source population contains 2,277 DR25 planet-candidate rows with a
summed `totalReliability` of 2,091.50. Before perturbation, 54 candidates
(reliability sum 42.23) lie inside the complete source fit domain.

## Nominal local support

| Constraint | Candidate rows | Sum of `totalReliability` |
|---|---:|---:|
| 5300--6000 K only | 1,071 | 992.27 |
| Temperature and 0.9--1.1 Earth radii | 54 | 51.69 |
| Temperature and conservative-HZ-intersected instellation | 3 | 2.17 |
| 0.9--1.1 Earth radii and 0.9--1.1 instellation | 0 | 0.00 |
| Full rectangular target | 0 | 0.00 |
| Exact Earth-analog target | 0 | 0.00 |

Thus the nominal catalog contains **no direct target-domain candidate**. The
absence occurs at the joint radius--instellation constraint, not because the
temperature range is globally unsupported.

## Corrected measurement-error realizations

Each branch contains 400 whole reliability-resampling and asymmetric
measurement-perturbation realizations. The fit retains a median of 41
candidates per realization in the broad source domain. Direct target counts
remain sparse:

| Branch | Target count q2.5 / q16 / q50 / q84 / q97.5 | Min--max | Zero-count trials |
|---|---:|---:|---:|
| Constant completeness | 0 / 0 / 0 / 0 / 1 | 0--1 | 95.75% |
| Zero completeness | 0 / 0 / 0 / 0 / 1 | 0--1 | 96.75% |

Across all trials, only 17 constant-branch and 13 zero-branch candidate
realizations enter the target. They arise from a very small number of source
rows. Row identifiers and row-level measurements are intentionally excluded
from this public report under the conservative redistribution policy. The
aggregate branch counts are sufficient for the local-support conclusion.

The branch difference is a consequence of their independent declared outer
seeds, not a completeness-model effect on individual planet measurements.

## Scientific decision

Local empirical support is **FAIL**. The frozen `Lambda_EE` posterior is a
projection of the fitted separable power-law occurrence model into a locally
data-empty region. It is not a direct count-based or locally candidate-supported
DR25 measurement. The posterior intervals include the fitted parameter and
declared measurement/reliability uncertainty, but they do not include the
additional uncertainty from the assumed functional form in this empty target
region.

The numerical posterior remains reproducible and geometrically in-domain. For
v4 it may be retained only if:

1. all claims use explicit model-projection language;
2. no interval is described as direct local DR25 support;
3. model-form sensitivity is frozen and shown separately; and
4. the zero local-candidate result is stated as a central limitation.

Machine-readable evidence is frozen in
`frozen-dr25-support/dr25_support_audit.json` with SHA-256
`9c45b08c0142e2e92bf595e70cd5c7742d2d78078ac4d8cdb1cd67bbe3ab1938`
for the file distributed in v4.0.1.
