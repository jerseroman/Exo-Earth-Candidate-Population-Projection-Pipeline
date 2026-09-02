# Differential metallicity-dependent PARSEC-TAMS coverage audit

JJ runtime process parallelism is fixed at `nprocess=2` for the hosted runner; this does not alter the scientific configuration.

The frozen Berger/Huber R_TAMS(Teff) curve is retained as the absolute Z-solar baseline. Only finite phase-7 anchors with M<=2 Msun and R<10 Rsun are admissible.

The fresh locked-archive audit records `FAIL_NOT_PUBLISHABLE` because at least one required metallicity curve does not cover 5300-6000 K without extrapolation. No metallicity-dependent TAMS correction is computed, emitted, authorized, or used in manuscript v4.

The validation-only solar Z=0.017 node table is retained solely as cross-check evidence for the canonical host-selector audit. No planet-occurrence, HZ, age, spatial, GHZ, or canonical host-selection factor is changed in this coverage audit.

The report binds the exact JJ parent CSV by filename, SHA-256, byte size, row count, and finite FeH domain. Its required, successful, and failed PARSEC lock identifiers form a disjoint exhaustive partition; the solar lock must be successful. All nine validation-only solar nodes are checked against values regenerated from the locked Z=0.017 archive.

The 0.75 and 0.80 Msun low-temperature bracketing nodes have formal phase-7 ages of about 27.20 and 21.07 Gyr. They are numerical boundary evidence only, not physically attainable present-day Galactic stellar ages and not a metallicity correction.
