# PARSEC-TAMS host-selection method note

The canonical JJ host provider defines the main-sequence condition with the public Berger/Huber PARSEC terminal-age main-sequence (TAMS) boundary rather than the former fixed `logg > 4.3` proxy. For each JJ stellar-assembly row, the stellar radius is reconstructed as

`Rstar/Rsun = sqrt[(Mf/Msun) * 10^(logg_sun - logg)]`,

with `logg_sun = 4.438`, and the row is retained when `Rstar <= R_TAMS(Teff)`. A separate `logg < 7` condition is retained only as a compact-remnant veto because the one-sided TAMS upper-radius boundary would otherwise admit very compact synthetic remnants. An independent luminosity-temperature radius reconstruction,

`Rstar/Rsun = 10^(logL/2) * (5772/Teff)^2`,

is used as a consistency diagnostic.

## TAMS source and interpolation

The frozen one-dimensional boundary is the public `tams_parsec.txt` table from `danxhuber/evolstate`. A verbatim repository copy is stored under `reference-data/tams_parsec_danxhuber.txt` and is protected by SHA-256 `d2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac`. The upstream table is based on PARSEC v1.2S solar-composition tracks (`Z=0.017`, `Y=0.279`). The associated public generator identifies TAMS from the first `PHASE == 7` point of each evolutionary track and reconstructs radius from luminosity and effective temperature.

Within the project G-star interval, interpolation is linear in `Teff` and `log10(R_TAMS/Rsun)`. Extrapolation outside the reference table is forbidden. The published low-temperature table anchor `(5200 K, 1.15 Rsun)` is retained as part of the frozen Berger/Huber boundary. Direct regeneration from the checksum-locked PARSEC track archive recorded in `provenance/DATA_LOCKS.json` on 2026-08-22 reproduces the physical reference points from 5390.13944 through 6060.24246 K to better than `5e-6 K` in temperature and `3e-6` in relative radius; the special 5200-K boundary anchor is not produced by the phase-7 track set in that locked archive under the generator's `<20 Gyr` condition.

## Metallicity-transfer limitation and rejected sensitivity test

The canonical Berger/Huber TAMS boundary is a one-dimensional relation `R_TAMS(Teff)` and has no explicit `[Fe/H]` coordinate. It is intentionally retained as the primary selector because it most closely matches the evolutionary-state selection inherited by the Bryson/Kepler occurrence-rate calibration. This is an approximation, not a claim that the TAMS radius is metallicity-independent.

JJ stellar-assembly tables carry a row-level `FeH` value assigned from the model age-metallicity relation. In the canonical 7-9 kpc sample, 19.8939% of the integrated one-dimensional-TAMS host weight is assigned to the thick disk. A metallicity-dependent boundary is therefore a relevant model systematic, but the archived differential experiment does not provide a valid quantitative estimate of it.

The rejected experiment attempted to avoid replacing the empirically inherited Berger/Huber absolute boundary by using the differential construction

`R_TAMS,2D(T,Z) = R_TAMS,Huber(T) * R_TAMS,PARSEC(T,Z) / R_TAMS,PARSEC(T,Z_solar)`.

That algebra is sound, but the required interpolated surface was not. The archived anchor table contains 42 phase-7 points with either `M > 2 Msun` or `R >= 10 Rsun`; its most extreme entries reach 155.288 Msun and 2311.56 Rsun. These giant/supergiant points contaminated an interpolation intended to represent low-mass G-star TAMS radii. After restricting the anchors to finite low-mass (`M <= 2 Msun`) and compact (`R < 10 Rsun`) phase-7 points, several metallicity tracks no longer span the complete 5300-6000 K analysis domain without extrapolation.

Consequently, the formerly reported `+1.5902%` change in `Lambda_earth10` and all associated metallicity-dependent host-count deltas are **retracted and excluded from manuscript v4**. They are neither sensitivity intervals nor corrections to the primary result. The canonical solar-composition one-dimensional selector remains the reproducible inherited baseline, while metallicity-dependent TAMS classification is retained as an open systematic that requires a purpose-built, continuous low-mass evolutionary grid before it can be quantified.

If a valid surface becomes available, JJ `FeH` would still need an explicit transport assumption (for example, scaled-solar `[M/H]` versus an alpha-enhanced composition), and the result would require a separate sensitivity analysis rather than a post-fit correction.

No absolute `P_metals` multiplier is introduced. The TAMS metallicity test concerns stellar evolutionary-state classification only. Any metallicity dependence of planet occurrence would require a separate occurrence-rate transport model.

## Reproducibility diagnostics

For the dR = 0.5 kpc validation run, the legacy `4.3 < logg < 7` selection is a strict subset of the canonical TAMS selection. The TAMS provider adds late-main-sequence G stars that the fixed-gravity threshold removed. The resulting canonical 7-9 kpc host count is `263061992.37` and the canonical L2 plug-in baseline is `3376462.67`.

A separate final radial-convergence experiment fully regenerated the final TAMS model at dR = 1.0, 0.5, and 0.25 kpc. Using the convergence diagnostic's fine-grid denominator, `(fine - coarse) / fine`, the 0.5-to-0.25-kpc changes are +0.1752% in `N_G`, +0.1997% in L1, and +0.2307% in L2, all below the predeclared 1% publication tolerance. The sensitivity register reports +0.2312% for the same L2 pair because it uses the canonical coarse grid as the denominator, `(fine - coarse) / coarse`; this is a convention difference, not a numerical disagreement. The production grid therefore remains dR = 0.5 kpc.
