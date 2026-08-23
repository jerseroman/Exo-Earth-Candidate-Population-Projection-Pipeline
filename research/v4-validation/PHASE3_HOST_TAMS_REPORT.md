# Phase 3 host and TAMS validation

Status: **PASS WITH INVALID METALLICITY TEST EXCLUDED**

This gate validates the frozen JJ 7--9 kpc host measure and the canonical
solar-composition PARSEC-TAMS selector. It does not validate a
metallicity-dependent TAMS surface, Galactic radial migration, or a transport
of Kepler occurrence rates to all Galactic stellar populations.

## Weighted host-selection closure

The audit reconstructs the composite-trapezoid radial measure from the
row-level JJ parent table. The parent population decomposes exactly into the
canonical main-sequence population, TAMS-radius rejections, and the compact
remnant veto:

| Component | Integrated stars | Fraction of parent |
|---|---:|---:|
| JJ parent population | 298,770,017.37 | 100.0000% |
| Canonical TAMS-selected hosts | 263,061,992.37 | 88.0473% |
| Rejected above the TAMS radius | 33,856,748.22 | 11.3320% |
| Rejected by the `logg >= 7` compact veto | 1,851,276.79 | 0.6196% |

The relative decomposition closure error is zero at stored precision. The
canonical plug-in values reproduce `Lambda_HZ = 105,716,685.08` and
`Lambda_EE = 3,376,462.67`.

## Native solar PARSEC validation

Nine genuine low-mass phase-7 nodes with masses 0.75--1.15 solar masses span
5151.34--6060.24 K. The seven nodes within the public generator's `<20 Gyr`
validation subset reproduce the immutable Berger/Huber reference from
5390.13944 to 6060.24246 K with a maximum temperature difference of
`4.73e-6 K` and a maximum relative radius difference of `2.76e-6`.

The native 0.75 and 0.80 solar-mass nodes bracket the manuscript's 5300 K lower
boundary without using the special 5200 K / 1.15 solar-radius table anchor.
Replacing the frozen curve by the native low-mass curve changes the selected
host count, plug-in `Lambda_HZ`, and plug-in `Lambda_EE` by exactly 0.0 at
stored precision. The canonical selector therefore passes the low-temperature
anchor-dependence gate.

Removing the entire 5300--5390.13944 K domain would instead reduce the host
count by 11.2781%, plug-in `Lambda_HZ` by 10.2929%, and plug-in `Lambda_EE` by
8.5010%. This is a domain-truncation stress test, not evidence of a selector
error.

## Legacy selector sensitivity

The former fixed-gravity selector (`4.3 < logg < 7`) contains
196,679,892.58 hosts, 25.2344% fewer than the canonical TAMS selector. After
propagating the same frozen occurrence posterior through that alternative host
measure:

| Scenario | Canonical median `Lambda_EE` | Legacy median `Lambda_EE` | Change |
|---|---:|---:|---:|
| Constant completeness | 3,223,845.60 | 2,302,367.50 | -28.5832% |
| Zero completeness | 4,572,456.81 | 3,219,999.08 | -29.5784% |

The corresponding median mean-`f_EE` changes are -4.4791% and -5.8101%.
This is a model-selector sensitivity and must not be folded into the posterior
credible interval.

## Stellar-radius diagnostic

The weighted canonical JJ radius distribution has mean 1.03468, median
0.99863, and 16th--84th percentiles 0.86350--1.23682 solar radii. Its weighted
fraction above 1.35 solar radii is 6.8222%. The unweighted Berger DR25 Hab2
stellar table restricted to 5300--6000 K has 37,612 rows, mean 1.02706, median
1.00182, and 2.7731% above 1.35 solar radii.

Like-for-like mean and median radius ratios imply -0.7368% and +0.3191%
linear-width diagnostics, respectively. The previously suggested ratio near
1.028 mixed a Kepler mean with a JJ median and is not a valid correction.

## Rejected metallicity-dependent TAMS experiment

The archived differential surface fails scientific validation. It contains 42
phase-7 anchors with either mass above 2 solar masses or radius at least 10
solar radii; the extrema reach 155.288 solar masses and 2311.56 solar radii.
After those giant/supergiant contaminants are removed, the `Z = 0.001` through
`Z = 0.010` low-mass curves do not cover the full 5300--6000 K domain without
extrapolation.

The formerly reported `+1.5902%` metallicity-TAMS change in `Lambda_EE` is
therefore retracted. It is excluded from the numerical freeze and from v4. A
valid metallicity-dependent TAMS classification remains an open epistemic
systematic requiring a continuous low-mass evolutionary grid and an explicit
composition-transport assumption.

## Decision and remaining limitations

- Engineering and numerical host/TAMS gate: **PASS**.
- Canonical solar TAMS selector: **PASS**.
- Archived metallicity-dependent TAMS sensitivity: **FAIL, EXCLUDED**.
- Metallicity-dependent TAMS model uncertainty: **OPEN**.
- Birth-radius interpretation and radial-migration correction: **OPEN**.
- DR25 occurrence-domain support: not assessed by this report.

Machine-readable evidence is frozen in
`frozen-host-tams/host_tams_audit.json` with SHA-256
`f7187f206e1b13fc3b6ca90ac9c5bb58062adf1c4ed949db936f32c0b407e66c`.
