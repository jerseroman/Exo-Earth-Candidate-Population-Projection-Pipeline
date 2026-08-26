# Exo-Earth Candidate Population Projection Pipeline

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22070762.svg)](https://doi.org/10.5281/zenodo.22070762)

Reproducible astrophysical analysis, validation, and archival pipeline for
reconstructing and propagating Kepler DR25 exoplanet-occurrence posteriors,
including corrected asymmetric measurement-error propagation and a legacy
source-faithful mode, catalog-reliability resampling, adaptive ensemble MCMC
with convergence, autocorrelation-time, ESS and MCSE diagnostics,
JJ/PARSEC/TAMS thin- and thick-disk host-star population synthesis and
main-sequence selection, Kopparapu habitable-zone modelling and climate
clipping, Galactic radial integration and narrow-domain exo-Earth candidate
population projections, direct DR25 local empirical-support analysis,
host-selector, TAMS, radial-grid, occurrence-model, climate, habitable-zone and
spatial sensitivity tests, frozen posterior and derived population outputs,
scientific figure-generation scripts, cryptographically locked external-data
and source dependencies, SHA-256 manifests, provenance and migration records,
mixed-license documentation, unit and regression tests, CI workflows,
verification utilities, and reproducible public-release tooling.

This is the license-cleared public software and reproducibility source tree for
the Exo-Earth Candidate Population Projection Pipeline. Numerical production
history is maintained separately; this tree contains audited source, frozen
derived summaries, provenance records, and the verification suite.

## What this public tree verifies

With Python 3.10 and the declared compatible requirements installed, the following command
checks the software-only boundary, path-level licenses, cryptographic data-lock
schema, frozen manifests, unit tests, and the repository manifest:

```bash
python -m pip install -r requirements.txt
make verify
```

This works in an ordinary directory unpacked from the public ZIP; no `.git`
directory or Git initialization is required.

The public tree verifies the cryptographic integrity and internal consistency
of the committed frozen summaries, runs the unit tests, inspects every
distributed source path, and reproduces analytical and aggregate checks that
use cleared committed inputs. It does not reconstruct excluded row-level
catalogs or large posterior chains from the public ZIP alone.

## Full numerical production

Full posterior and JJ host-production runs also require large externally
licensed or fetch-only inputs. `provenance/DATA_LOCKS.json` records their data
and download locks: available URLs or derivation records, source versions, byte
sizes, SHA-256 digests, licenses or unresolved redistribution status, and
citation requirements. Source-code repository commits are recorded separately
in `provenance/SOURCE_LOCKS.json`.

List or fetch an input without adding it to Git:

```bash
python scripts/fetch_locked_inputs.py --list
python scripts/fetch_locked_inputs.py --id completeness_constant
```

The PARSEC/PADOVA archive requires acknowledgement of its official CC BY 4.0
terms and citation requirements:

```bash
python scripts/fetch_locked_inputs.py \
  --id jj_padova_multiband_archive \
  --accept-terms jj_padova_multiband_archive
```

Downloads are stored under ignored `local-artifacts/locked-inputs/` and are
accepted only when both their byte size and SHA-256 match the lock. Public
GitHub production jobs are intentionally disabled because they acquire
third-party catalogs. A full rerun is performed locally or in a private
production environment after obtaining those inputs under their applicable
terms.

## Licensing

This is a mixed-license collection. Roman-authored paths explicitly identified
as MIT in `provenance/LICENSE_MATRIX.csv` and
`provenance/ROMAN_MIT_PATHS.txt` are offered under MIT. The Bryson-derived
component is conservatively conveyed under GPL-2.0-only. Daniel Huber's
redistributed TAMS table retains his MIT notice.
The PARSEC/PADOVA archive is fetch-only under CC BY 4.0 and is not included in
this source tree. Catalog and completeness files with no confirmed
redistribution grant are likewise fetch-only and excluded.

The authoritative assignment for every distributed path is
`provenance/LICENSE_MATRIX.csv`. See `LICENSE_POLICY.md`,
`THIRD_PARTY_NOTICES.md`, and `LICENSES/` before redistribution.

Roman Jerše is the creator of this assembled software and reproducibility
release and of the paths explicitly attributed to him. This resource-level
creator attribution does not claim authorship or copyright in third-party
components. His ORCID iD is
[`0009-0001-5003-5354`](https://orcid.org/0009-0001-5003-5354).

## Scientific status

The frozen baseline contains 400 accepted constant-completeness and 400
accepted zero-completeness realizations, with conditional 7--9 kpc medians of
3.224 million and 4.572 million narrow-domain candidates. The exact nominal
DR25 target contains zero candidates, so these are separable model projections
without direct local empirical support.

## Citation and release

The version-specific archival record for version 4.0.2 uses DOI
[`10.5281/zenodo.22070762`](https://doi.org/10.5281/zenodo.22070762). The
corresponding source tag and release are
[`v4.0.2`](https://github.com/jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline/releases/tag/v4.0.2).
