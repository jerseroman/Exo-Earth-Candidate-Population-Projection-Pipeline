# Phase 4 primary-literature comparison

Status: **PASS ESTIMAND-AWARE COMPARISON; NOT AN INDEPENDENT VALIDATION**

This gate compares the frozen v4 occurrence result with traceable primary
occurrence-rate studies and tests its source-to-target assumptions against
primary Galactic age, kinematic, and radial-migration studies. It does not pool
unlike definitions or treat the spread among publications as a statistical
uncertainty interval.

## Frozen v4 occurrence estimand

The v4 quantity is the mean number of planets per star in `0.9--1.1 R_earth`
and `0.9--1.1 I_earth`, intersected with the conservative Kopparapu habitable
zone, averaged over the JJ-weighted `5300--6000 K` host population. The
Galactic count then applies this occurrence to the `7--9 kpc` TAMS-selected
host measure.

| Completeness branch | mean `f_EE`, q50 (planets/star) | 68% posterior interval | `Lambda_EE`, q50 | 68% posterior interval |
|---|---:|---:|---:|---:|
| Constant | 0.01226 | 0.00579--0.02353 | 3.224 million | 1.522--6.189 million |
| Zero | 0.01738 | 0.00799--0.03388 | 4.572 million | 2.103--8.912 million |

These intervals propagate the fitted occurrence posterior and host-temperature
mixture. They do not include occurrence-model-form uncertainty, the absence of
direct local support, or the open Galactic-population systematics.

## Source-model fidelity check

Table 5 of Bryson et al. (2021) reports the temperature-matched 5300--6000 K
G-star Model-1 conservative-HZ values of 0.38 planets per star for the
constant-extrapolation low bound and 0.63 for the zero-extrapolation high
bound. The reconstructed v4 broad-HZ medians are 0.388 and 0.659. This close
agreement is a source-model fidelity check, not independent validation: v4
reconstructs and integrates the Bryson DR25 occurrence model. The broader
4800--6300 K eta-Earth values of 0.37 and 0.60 remain contextual rather than
the primary benchmark.

Within the same posterior draws, the v4 narrow box contains a median 3.119% of
the broad-HZ count in the constant branch and 2.606% in the zero branch. This
explains why the integrated v4 occurrence is numerically below broad-HZ
literature values without implying a scientific conflict.

## Primary-study comparison

| Primary study | Reported quantity | Why it is not a like-for-like test |
|---|---|---|
| Bryson et al. (2021), doi:10.3847/1538-3881/abc418 | Table 5 G-star Model 1 over `0.5--1.5 R_earth`, conservative HZ, `5300--6000 K`: 0.38 constant and 0.63 zero | Temperature-matched source model; radius and HZ domains remain broader; not independent |
| Kunimoto & Matthews (2020), doi:10.3847/1538-3881/ab88b0 | 84.1% upper limit below 0.18 planets per G star for `0.75--1.5 R_earth`, `0.99--1.70 au` | Semimajor axis rather than instellation, broader radius, different host definition |
| Burke et al. (2015), doi:10.1088/0004-637X/809/1/8 | `zeta_1.0` about 0.1, with an allowed 0.01--2 range | Period replaces instellation, Q1--Q16 rather than DR25, large systematic range |
| Pascucci et al. (2019), doi:10.3847/2041-8213/ab3dac | Preferred broad-HZ extrapolation around 5--10% | Different domain and model; mainly demonstrates model-form sensitivity in sparse extrapolation |
| Bergsten et al. (2022), doi:10.3847/1538-3881/ac8fea | `Gamma_Earth = 15% (+6%,-4%)` | Differential density per log-period/log-radius area, not an integrated occurrence for the v4 box |
| Dai et al. (2021), doi:10.3847/1538-3881/ac00ad | Lower close-in 1--4 `R_earth` occurrence for high-velocity than low-velocity Kepler stars; correction-dependent separation about 1.55--2.55 sigma | Close-in, broad-radius kinematic comparison; no HZ correction follows |
| Bashi & Zucker (2022), doi:10.1093/mnras/stab3596 | More close-in super-Earths in the younger thin-disk than older thick-disk sample | Age, chemistry, and kinematics covary; thick-disk and halo planet samples are sparse |
| Sayeed et al. (2025), doi:10.3847/1538-3881/ada8a1 | No significant overall DR25 occurrence--age trend for 1.5--8 Gyr FGK stars | Short-period, very broad-radius sample; provides an empirical counterweight rather than proof of age invariance in the HZ |
| Frankel et al. (2020), doi:10.3847/1538-4357/ab910c | Radial angular-momentum redistribution dominates heating in the low-alpha disk | Not an occurrence estimate; shows that present 7--9 kpc is not a stellar birth-annulus selection |

No listed primary result simultaneously matches the v4 radius, instellation,
climate intersection, host-temperature range, and catalog/model definition.
Point-estimate differences therefore cannot establish inconsistency.

## Scientific interpretation gate

The exact nominal DR25 target contains zero candidates and zero summed
reliability. Accordingly, the frozen v4 number must be described as a
**conditional separable-power-law model projection** into a locally empty
target region. It is not a direct candidate-supported occurrence measurement.

The literature comparison strengthens the following manuscript requirements:

- state that Bryson et al. (2021) is the source model, not independent
  corroboration;
- keep occurrence-model form and long-period/local-support uncertainty outside
  the reported posterior interval and identify them as material epistemic
  limitations;
- do not convert close-in age or kinematic trends into an HZ correction factor;
- define 7--9 kpc as the present-day spatial estimand, not a sharply bounded
  birth environment.

Machine-readable source definitions, results, comparison roles, and prohibited
inferences are frozen in `frozen-literature/primary_literature_comparison.json`.
The primary-source search cutoff is 2026-08-22.
