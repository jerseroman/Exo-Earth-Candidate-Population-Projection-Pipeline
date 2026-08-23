# Third-party notices

## Bryson DR25 occurrence implementation

The source-faithful runner is based on
`stevepur/DR25-occurrence-public`, commit
`d200f54b6f0df49e0dae530e69983cdce5397bfb`, especially
`insolation/computeOccurrencefixedTeff_uncertainty.ipynb` and
`insolation/rateModels3D.py`. The upstream repository provides GNU GPL version
2. The closely adapted files identified in the matrix are therefore
distributed conservatively under `GPL-2.0-only`.

Roman Jerše's modifications include deterministic seed control, explicit
parameter-order metadata, corrected two-sided measurement-error propagation,
post-perturbation domain auditing, adaptive convergence/ESS gates, clustered
MCSE checks, and reproducible output manifests. These modification notices do
not replace or weaken the upstream GPL terms.

The DR25 catalogs and completeness contours are not part of Roman's MIT grant.
They are fetched for private production and are excluded from the public source
package and public CI artifacts.

## Daniel Huber `evolstate`

This repository contains the exact file
`research/jj-host-export/reference-data/tams_parsec_danxhuber.txt` from
`danxhuber/evolstate` commit
`5e904afad81805c4e3ac4c3f78510a2a1df33d14`. It is distributed under Daniel
Huber's MIT License in `LICENSES/MIT-Daniel-Huber-evolstate.txt`.

Expected SHA-256:
`d2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac`.

## JJModel

The workflows fetch `askenja/jjmodel` commit
`2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54`. JJModel is not vendored here and
remains under Dr. Kseniia Sysoliatina's MIT License, preserved in
`LICENSES/MIT-jjmodel.txt`.

## PARSEC/Padova and completeness inputs

Large PARSEC/Padova archives and Bryson completeness contours are fetch-only.
They are not included in the public ZIP. Their scientific citation and
download provenance do not constitute a new redistribution license.

The official JJModel PARSEC/PADOVA multiband archive is
`multiband_padova.zip`, DOI `10.11588/DATA/ZCXHOE/7XCJQP`, part of Sysoliatina
(2022), *JJ-model isochrone set: PARSEC, MIST, and BaSTI stellar evolution*,
heiDATA, V1. The archive is licensed CC BY 4.0 and its official terms require
dataset and applicable stellar-evolution citations. It is checksum-locked but
not redistributed here. The official record reports MD5
`c89b82279db57e05705b8795186d3372`; the locally verified SHA-256 is recorded in
`provenance/DATA_LOCKS.json`.

Completeness contours and DR25 catalogs remain `NOASSERTION` for
redistribution. Their hashes authorize only reproducible local acquisition and
verification, not republication.

## Python dependencies

Dependencies are installed from their upstream distributions and are not
vendored. The version-constrained direct requirements use NumPy (BSD), SciPy (BSD), pandas
(BSD-3-Clause), Astropy (BSD-3-Clause), emcee (MIT), Matplotlib (PSF),
fast-histogram (BSD), Requests (Apache-2.0), and setuptools (MIT). Each retains
its upstream license and notices.
