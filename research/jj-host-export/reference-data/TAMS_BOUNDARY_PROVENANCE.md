# PARSEC-TAMS boundary provenance

## Role in this project

This file documents the immutable reference table used by the canonical JJ/PARSEC host provider to operationalize the main-sequence condition for the G-dwarf estimand.

Canonical selector:

```text
5300 <= Teff <= 6000 K
age >= 4.57 Gyr
thin + thick JJ disk
Rstar <= R_TAMS(Teff)
logg < 7  # compact-remnant veto only
```

The source table is stored verbatim as:

```text
reference-data/tams_parsec_danxhuber.txt
```

## Upstream source

Repository: `danxhuber/evolstate`

Upstream file: `tams_parsec.txt`

Pinned historical commit containing the same table:

```text
5e904afad81805c4e3ac4c3f78510a2a1df33d14
```

Git blob SHA reported by GitHub for the source table:

```text
b01dfa162bb2c24b0e8cbe71de9c17a89334c1d4
```

As checked on 2026-08-22, the upstream default branch had the same Git blob SHA as the pinned 2018 file, so the reference values were unchanged across those revisions.

Upstream repository license: MIT.

The upstream README describes `evolstate` as a simple evolutionary-state classifier based on physically motivated boundaries from solar-metallicity interior models, citing Huber et al. and Berger et al.

## How the upstream PARSEC table was generated

The upstream repository also supplies `parsec.py`, added in commit:

```text
e50113d0e6e4a5f74a49052bba5ba53850f1fb23
```

That script states that it generates the TAMS and RGB boundary files from PARSEC models located under:

```text
https://people.sissa.it/~sbressan/CAF09_V1.2S_M36_LT/
```

and selects the solar-metallicity directory:

```text
Z0.017Y0.279/
```

For each input track the script reconstructs stellar radius from luminosity and effective temperature,

```text
R/Rsun = sqrt( L/Lsun * (Teff/5777 K)^(-4) )
```

then identifies the first model point satisfying:

```text
PHASE == 7
age < 20 Gyr
```

and writes `(Teff, R/Rsun)` to `tams_parsec.txt`.

Therefore the adopted boundary is specifically a solar-metallicity PARSEC/CAF09_V1.2S-based TAMS relation inherited from the Berger/Huber evolutionary-state implementation. It is not a metallicity-dependent Galactic TAMS surface.

## Table checksum

The verbatim UTF-8 project copy (including its terminal newline) has SHA-256:

```text
d2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac
```

Number of rows:

```text
49
```

## Interpolation used in this work

For the present G-dwarf estimand only the source-table segment spanning

```text
5200.00000 K <= Teff <= 6060.24246 K
```

is required. This segment contains the first eight table rows and is strictly monotonic in `Teff`.

The canonical interpolation is:

1. linear in `Teff`,
2. linear in `log10(R_TAMS/Rsun)`,
3. transformed back to radius after interpolation.

Mathematically,

```text
log10 R_TAMS(T) = linear_interpolation[T_i, log10(R_i)]
R_TAMS(T)       = 10^(log10 R_TAMS(T)).
```

No extrapolation is permitted. The implementation raises an error if a requested temperature lies outside the validated monotonic reference segment.

The scientific host interval,

```text
5300 <= Teff <= 6000 K,
```

lies entirely inside the validated reference segment, so no edge extrapolation or endpoint clamping occurs in the canonical calculation.

## Important limitation

The boundary is a one-dimensional function of effective temperature and has no `[Fe/H]` coordinate. Applying it to the JJ thick disk is therefore an explicit transport approximation. The metallicity dependence of the TAMS selector is treated separately as a systematic uncertainty; no absolute `P_metals` factor is introduced.
