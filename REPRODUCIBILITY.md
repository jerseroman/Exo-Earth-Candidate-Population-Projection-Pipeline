# Reproducibility protocol

## Acceptance boundary

The committed frozen records are an imported, checksum-verified v4 baseline.
A hybrid cross-environment audit completed on 2026-08-23 and passed the
artifact, convergence, ESS, and MCSE-based q50 comparison gates. It reused 31
checksum-verified cloud shards, reran the one missing constant shard, and ran
aggregation and Galactic propagation locally. The audit validates the checked
headline medians and other recorded q50 values but does not relabel or replace
the imported baseline. It does not claim agreement of the full posterior
intervals.

No workflow may change the model, seeds, priors, likelihood, measurement-error
mode, convergence criteria, outer-realization weighting, or host selector while
claiming to reproduce this baseline.

## Workflow order

Import the exact `v4.0.2` tag, or its exact release commit, into a private
repository and dispatch the following manual workflows from that immutable
ref, not from a moving `main`. Their production jobs are guarded by
`github.event.repository.private == true`; they intentionally skip in the
public release repository because they fetch or process excluded inputs.

1. `JJ G-host dR=0.5 + TAMS validation`.
2. `Bryson v4 corrected adaptive-MCMC pilot`.
3. `Bryson v4 corrected constant production posterior`, supplying the
   successful host-export run ID from step 1.
4. `Bryson v4 corrected zero extended posterior`, supplying the same host run
   ID. This branch retains the unchanged convergence criteria and the audited
   30,000-step ceiling.
5. Optional independent radial-convergence check.
6. The differential metallicity-TAMS workflow is retained only to reproduce
   the rejected coverage diagnostic. Its result is not a valid sensitivity
   correction and must not be promoted into the baseline.

The constant and zero production workflows download cross-run artifacts only
from `${{ github.repository }}`. They verify the pinned host hashes before
propagation.

## Numerical freeze gate

A replacement baseline is accepted only when:

- exactly 400 constant and 400 zero outer realizations are selected;
- every selected realization passes the adaptive convergence gate;
- no optimizer failure is recorded;
- every parameter has minimum per-realization ESS at least 1000;
- seed-family shifts and cluster-level MCSE remain below their declared gates;
- the host, posterior, and Galactic artifacts pass their internal SHA-256
  manifests; and
- the recomputed `Lambda_EE` medians agree with the artifact medians and with
  the stated rounded values.

If a rerun fails any item, the imported baseline remains frozen and the failed
run is retained as evidence rather than silently replaced.

## Hybrid cross-environment audit (2026-08-23)

GitHub Actions supplied 15 successful constant shards and all 16 successful
zero-completeness shards from production runs `32582964364` and `32582966433`.
The only missing scientific shard, constant shard 14, was completed locally in
WSL2 using the unchanged production commit, seeds, numerical package freeze,
and workflow arguments. The cloud workflow failures were billing/account
runner-start failures; they were classified as infrastructure failures, not
scientific convergence failures.

After every archive digest and internal `SHA256SUMS_complete.txt` manifest
passed, the 400 constant and 400 zero realizations were aggregated and
propagated locally against the verified full host artifact from run
`32581659930`. All 800 realizations converged, no optimizer failure was
recorded, and each parameter's minimum per-realization ESS exceeded 1000.

The reconstructed medians were 3.217 million (constant) and 4.567 million
(zero).
They differ from the frozen 3.224 and 4.572 million values by only 0.0745 and
0.0366 of the quadrature-combined recorded outer q50 MCSE, respectively. Every
other checked parameter and Galactic q50 value also remained within recorded
Monte Carlo precision. This comparison is limited to the recorded q50 values;
the frozen baseline remains unchanged.

Exact run identifiers, environment versions, hashes, ESS values, comparison
rule, and numerical evidence are in
`provenance/INDEPENDENT_NUMERICAL_AUDIT_20260823.json`.
The authoritative mapping from every cited Actions run to its source
repository, workflow, commit, conclusion, and MCMC step ceiling is in
`provenance/RUN_PROVENANCE.json`.

The cleared control, comparison, aggregate-summary, manifest, and representative
environment records distributed with the public package are documented in
`provenance/independent-audit-evidence/README.md`. Private Actions URLs may not
resolve for public readers; the evidence boundary explicitly distinguishes
bundled records from checksum-only retained-private records.

## Local checks

`make verify` checks the software-only boundary, every committed frozen
manifest, all numerical regression suites, the primary-literature and source
guards, and the deterministic repository manifest. The suite includes
non-directional TAMS-wording and fail-closed data-lock regression guards.
