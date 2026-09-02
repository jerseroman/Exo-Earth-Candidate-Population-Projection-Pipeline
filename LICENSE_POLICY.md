# License policy

## Scope

This is a mixed-license repository. A repository-level badge or a citation
metadata field must not be interpreted as relicensing every file under one
license. The authoritative assignment is the exact path row in
`provenance/LICENSE_MATRIX.csv`.

## Roman Jerše original material

Roman Jerše offers his original software, workflow definitions, tests,
documentation, configuration, provenance records, and original generated
summary structures in this repository under the MIT License in
`LICENSES/MIT-Roman-Jerse.txt`.

The exact audited Roman-authored path allowlist is
`provenance/ROMAN_MIT_PATHS.txt`. Any new or unrecognized path defaults to
`NOASSERTION`, `REVIEW/BLOCK`, and exclusion from the public ZIP until an
explicit origin and license decision is recorded.

This grant does not apply to third-party material or to material governed by a
copyleft license because it is copied from or adapted from that material.
Earlier copies published under another license retain their historical grants;
the path-level matrix governs files as conveyed in this repository version.

## Creator metadata

Roman Jerše is the creator of the assembled software and reproducibility
release and of the paths explicitly attributed to him. His ORCID iD is
`https://orcid.org/0009-0001-5003-5354`. Resource-level creator metadata in
`CITATION.cff`, GitHub, or Zenodo does not transfer or claim authorship,
copyright, or licensing authority over third-party components. Those rights
remain with the holders identified by the path-level matrix and notices.

## Bryson-derived component

The files listed as `GPL-2.0-only` in the matrix are copied from or closely
adapted from the likelihood and measurement-error implementation in
`stevepur/DR25-occurrence-public` at commit
`d200f54b6f0df49e0dae530e69983cdce5397bfb`. They are conveyed under GNU GPL
version 2 only. Roman's modifications remain part of that GPL-covered component
when conveyed in this repository.

Roman-authored MIT helpers may be used by the GPL-covered runner. Their
individual MIT grant remains available. Copying, modifying, or distributing
the GPL-covered files, and any combined or derivative work to the extent it is
governed by those files, must follow the applicable GPL-2.0-only conditions.
Merely running the software is not presented here as a distribution event.

## Daniel Huber PARSEC-TAMS table

`research/jj-host-export/reference-data/tams_parsec_danxhuber.txt` is a
verbatim copy of `danxhuber/evolstate` commit
`5e904afad81805c4e3ac4c3f78510a2a1df33d14:tams_parsec.txt`. It remains under
Daniel Huber's MIT License. The copyright and permission notice must accompany
every redistributed copy.

## Fetched software and data

JJModel, the Bryson DR25 repository, PARSEC/Padova archives, completeness
contours, and Python dependencies are fetched from commit-pinned,
version-constrained, or checksum-locked upstream locations.
Fetching or citing them does not transfer ownership and does not relicense
them. They must not be copied into a public release artifact unless the matrix
explicitly records a verified redistribution license and required notice.

Production GitHub Actions jobs that may temporarily acquire or process
third-party catalogs are guarded so they run only while the repository is
private. Public verification jobs install the declared Python dependencies but
do not fetch the excluded scientific catalogs, contours, or archives.

## Scientific outputs

Purely Roman-authored aggregate summaries and validation structures are offered
under MIT. This does not grant rights in any
third-party source rows embedded in an output. Row-level catalog extracts and
mixed-origin archives are excluded from the public package unless separately
cleared.

The source-package path decision above and the separately built v4.0.4 results
archive have distinct boundaries. The signed local qualification tree retains
exactly 88 files for internal verification. The canonical policy in
`provenance/PUBLIC_RESULTS_POLICY_v4_0_4.json` projects that tree to exactly 70
public result paths: 18 row-level DR25 or serialized MCMC-trajectory files are
excluded, five directory-scoped manifests are deterministically rewritten, and
63 signed files pass through byte-for-byte. The public report and root manifest
are also regenerated to describe only that 70-file projection.

The policy explicitly classifies 13 retained generated-derived products:
aggregate correlation tables, occurrence-posterior samples prepared for
Galactic propagation, Galactic derived draws, and likelihood-grid parameter
points. None is a third-party row table or a complete serialized MCMC
trajectory, and none includes the chain log-probability column. The two
likelihood-grid selected-point tables deliberately retain limited selection
provenance (`posterior_row_number`, `global_trial`, `production_step`, and
`walker`) for independently reproducing the grid audit; they do not expose the
full chains from which those points were selected. Their presence in the
separate results archive does not assert that they are members of the older
source-release audit bundle described elsewhere in the repository.

## Public package and Zenodo

Only paths with `included_in_public_package=yes` and a redistribution status of
`CLEAR` or `CLEAR_WITH_NOTICE` may enter the deterministic public ZIP. The
license gate fails closed for missing paths, `NOASSERTION`, or `REVIEW/BLOCK`.
The excluded paths and reasons are also recorded in
`provenance/PUBLIC_EXCLUSIONS.csv`. The package builder emits a filtered matrix
and manifest so the sanitized archive remains independently verifiable.
For the separate results ZIP, the source-tree license gate is supplemented by
the exact runtime projection policy described above; a results path not in its
70-path set is rejected.

Because excluded material exists in the **private production repository's Git
history**, that private repository must not be made public by changing its
visibility. A clean public repository is initialized from the audited ZIP.
The ZIP uses the audited root README and omits the private maintainer checklist;
it is therefore not subject to the private-history prohibition.

Zenodo metadata must declare the mixed MIT and GPL-2.0-only licensing. The ZIP
itself contains the path-level matrix and all applicable license texts. Because
a single CFF license field does not express the path-specific mapping
unambiguously, `CITATION.cff` uses `license-url` to point to this policy instead
of attempting to encode the repository as one blanket license list.

## No warranty

Each component carries the warranty disclaimer of its applicable license.
Nothing in this policy supplies permissions that an identified copyright or
data-rights holder has not granted.
