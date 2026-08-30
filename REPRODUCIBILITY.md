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

## v4.0.4 full requalification candidate

Version 4.0.4 starts from the v4.0.3 scientific model but requires a complete
fresh production calculation. The primary occurrence formula, priors,
likelihood, model domains, locked data, seed schedules, host selector and
integration rule remain scientifically unchanged. The evidentiary boundary is
stronger: raw-chain diagnostics, source-catalog perturbations, JJ SSP inputs,
host artifacts, radial grids and local execution provenance must be independently
rederived or cryptographically qualified before a result can be frozen.

No v4.0.3 headline value is used as a v4.0.4 computational input. Old frozen
values may be compared only as explicitly labelled regression evidence. The
v4.0.4 reported values must come from the newly accepted constant, zero and
legacy-sensitivity aggregates and their fresh Galactic propagations.
Final publication is valid only from the exact `v4.0.4` tag whose commit passes
the release-acceptance, repository-manifest, license, and public-package gates.

### Hash-locked Python environment

`requirements.in` is the human-maintained list of direct runtime, audit,
installer, and build dependencies for the legacy source-faithful Python 3.10
environment. Runtime project dependencies remain separately declared in
`pyproject.toml`; audit-only and environment-management packages are not
published as runtime requirements. `requirements.txt` is the generated lock: it
fixes every direct and transitive dependency, including the active `pip`, and
records the permitted distribution SHA-256 hashes. Regenerate it only with the
exact `pip-compile` command recorded in its header and review the complete diff.

All CI and reproduction installs use:

```console
python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
python -m pip check
```

An unhashed distribution, a source distribution with undeclared build
dependencies, an undeclared dependency, a dependency conflict, or
drift between `requirements.in`, `requirements.txt`, and the direct project
dependencies is a verification failure. `make dependencies` applies the static
lock checks and `pip check`; `make verify` includes that gate. The lock controls
Python packages only. A production record must still capture the exact active
Python and `pip`, operating-system runner, and numerical-library configuration.

The four comment lines at the start of `requirements.txt` are a
policy-normalized generation record: they identify the audited Python and
`pip-tools` policy and the approved resolution command, but are not claimed to
be an untouched copy of terminal output. The verifier binds the complete
normalized lock file by SHA-256.

The three JJ workflows install the checked-out local package only with
`--no-deps --no-build-isolation -e .`; this forces the already hash-locked
`flit-core` package and its `flit_core.buildapi` backend to be used instead of
creating an unverified build environment.

### Candidate status and aggregate acceptance

An individual runner can emit only `pilot_only` or the preliminary status
`production_candidate`. Omitting `--run-status` fails safe to `pilot_only`, and
the human-readable run label never assigns production status.

`production_candidate` is not an accepted result. Acceptance exists only in a
successful aggregate summary whose `production_acceptance_gate.accepted` value
is `true`. Release propagation additionally requires the explicit
`v4.0.4-production` profile, or the branch-limited
`v4.0.4-zero-extended` profile. The separately labelled constant-branch
`v4.0.4-legacy-measurement-sensitivity` profile uses the same scale, seed
schedule and quality gates as the primary constant profile but requires
`legacy_source_mixture`. These profiles fix the shard/trial/walker
scale, burn-in, minimum and maximum production lengths, thinning, adaptive-tau
policy, seed schedule, equalized sample count, MCSE settings, and propagation
stride; a custom quality-gate result cannot cross the release verifier. With
`--require-all-converged`, the aggregator fails closed unless it
receives the exact expected shard and trial sets with matching chain, summary,
diagnostic, unique seed, branch, measurement-error-mode, and source-provenance
records. The production command supplies the locked SHA-256 of
`insolation/rateModels3D.py`; every shard must prove those exact source bytes.
The runner also checks the branch-specific stellar catalog, planet-candidate
catalog, and completeness contour before loading and rehashes all three before
writing the summary.
Every production runner also writes its complete unthinned post-burn chain to a
separate private directory. The aggregate gate requires all 400 raw-chain
identities and stable byte snapshots, independently recomputes the full
checkpoint tau/stability/ESS decision, and verifies that each public shard CSV
is the exact prescribed thinning. The public aggregate retains only a
manifest-bound audit report and audit-helper SHA-256; raw binaries, their
private indexes and their private manifests are excluded.
Each chain must also contain the complete, non-duplicated walker/step grid
implied by its declared completed production length and thinning. The gate then
requires adaptive convergence, successful optimization, valid positive
autocorrelation times, internally consistent ESS of at least 1000 for every
parameter in every realization, and finite outer and inner q50 MCSE fractions
below the configured limits. Propagation must consume only the artifact emitted
after that successful aggregate gate. Before propagation,
`scripts/verify_accepted_aggregate.py` independently checks the aggregate file
manifest and requires `production_acceptance_gate.required=true` and
`accepted=true`, the canonical ESS/MCSE limits, all locked scientific-input
hashes, the common numerical-environment hash, verified Bryson source bytes,
the exact release profile and seed schedule, and 204800 finite propagation rows
with equal 512-row representation of all 400 outer realizations.
It also requires the locked planet-candidate and stellar catalogs. A
stable-snapshot copy of the independent catalog verifier replays all 400
reliability and asymmetric-measurement realizations and binds the aggregate
audit, diagnostics, `DATA_LOCKS.json`, verifier source, counts and seeds before
propagation is permitted.

### Cross-workflow provenance inputs

Every workflow that imports an artifact from another Actions run requires both
the numeric run ID and its independently recorded 40-hex source commit SHA. The
consumer queries the run in the same repository and verifies that it completed
successfully, was started by `workflow_dispatch`, came from the expected
workflow path, and has the supplied `head_sha` before downloading the named
artifact. Inputs are passed through environment variables and validated before
use rather than interpolated directly into shell commands.

The standalone constant-propagation workflow additionally requires an
independently recorded 64-hex SHA-256 of
`SHA256SUMS_constant_aggregate.txt`. It verifies that manifest digest before
using the manifest to verify the posterior files. The run SHA proves which code
produced an artifact; the independent manifest SHA-256 binds the exact artifact
contents. Neither value substitutes for the other.

### Public/private licensing boundary

Workflows that acquire or process excluded third-party scientific inputs retain
the job guard `github.event.repository.private == true`. Dispatching one of
those workflows in the public repository intentionally produces skipped jobs:
this is a licensing no-op, not a successful reproduction and not scientific
evidence. Run those workflows only from an authorized private copy at an exact
immutable ref. The public `verify` workflow remains the software-only
verification path for the license-cleared release contents.

### Deferred Python and SciPy migration

The source-faithful environment remains on Python 3.10 and SciPy 1.10.1 for this
hardening release because the Bryson reconstruction still uses the legacy
`scipy.interpolate.interp2d` convention. Python 3.10 reaches end of upstream
support in October 2026, and SciPy removed `interp2d` in 1.14. Migration is an
explicit v4.1 parity task, not part of v4.0.4.

Before supporting a newer Python/SciPy stack, a candidate regular-grid
interpolator must be compared with the legacy implementation on non-square
synthetic grids, descending flux coordinates, boundaries and extrapolation,
both locked completeness contours, fixed likelihood evaluations, and frozen
end-to-end regression cases. Any numerical difference that exceeds the
declared parity tolerance or changes downstream results beyond their accepted
Monte Carlo error is a scientific change and requires a new rerun and result
version; it must not be hidden inside a maintenance release.

## Workflow order

Synchronize the exact reviewed v4.0.4 candidate commit and Git tree into the
private production repository, record exact `git archive HEAD` bytes for both
repositories, and execute from that immutable ref, not from a moving `main`.
Production workflow jobs are guarded by
`github.event.repository.private == true`; they intentionally skip in the
public release repository because they fetch or process excluded inputs.

1. `JJ G-host dR=0.5 + TAMS validation`.
2. `Bryson v4 corrected adaptive-MCMC pilot`.
3. `Bryson v4 corrected constant production posterior`, supplying the
   successful host-export run ID and exact run commit SHA from step 1.
4. `Bryson v4 corrected zero extended posterior`, supplying the same host run
   ID and SHA. This branch retains the unchanged convergence criteria and the
   audited 30,000-step ceiling.
5. Run the constant-branch `legacy_source_mixture` sensitivity with the exact
   `v4.0.4-legacy-measurement-sensitivity` profile and the same 16 by 25 seed
   schedule and acceptance thresholds as the primary constant calculation.
6. Run the independently qualified radial-convergence triplets.
7. The differential metallicity-TAMS workflow is retained only to reproduce
   the rejected coverage diagnostic. Its result is not a valid sensitivity
   correction and must not be promoted into the baseline.

The constant and zero production workflows download cross-run artifacts only
from `${{ github.repository }}`. They verify the producing workflow, successful
conclusion, exact run commit SHA, and pinned host hashes before propagation.

## Numerical freeze gate

A replacement baseline is accepted only when:

- exactly 400 corrected-constant, 400 corrected-zero and 400 legacy-constant
  outer realizations are selected into their separately labelled aggregates;
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

`make verify` checks the dependency lock and installed environment, workflow
security invariants, software-only boundary, every committed frozen manifest,
all numerical regression suites, the primary-literature and source guards, and
the deterministic repository manifest. The suite includes non-directional
TAMS-wording and fail-closed data-lock regression guards.
