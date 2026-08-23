# Authorship and license audit

Date: 2026-08-23

## Conclusion

PASS. Roman Jerše may be identified as creator of the assembled ExoEarth
Annulus v4 software and reproducibility release and of the paths explicitly
attributed to him. This does not identify him as author or copyright holder of
every included component.

The audited v4.0.2 public tree contains 135 paths: 127 Roman-authored MIT paths, one
Roman-authored mixed-license root notice, three Bryson-derived GPL-2.0-only
Python files, the corresponding GPL text, Daniel Huber's MIT-licensed TAMS
table and notice, and the MIT notice for the fetch-only JJModel dependency.
Three unresolved row-level DR25 paths remain recorded as excluded.

## Evidence

- `provenance/LICENSE_MATRIX.csv` assigns origin, copyright holder, license,
  redistribution status, and public-package inclusion to every path.
- `provenance/ROMAN_MIT_PATHS.txt` is the exact allowlist for Roman-authored
  MIT material. Unknown paths fail closed.
- All three Bryson-derived files carry GPL-2.0-only SPDX identifiers, identify
  the pinned upstream commit, and point to the dated modification record.
- The distributed GPL, Daniel Huber MIT, and JJModel MIT notices are byte-equal
  to the corresponding pinned upstream files.
- The bundled TAMS table is byte-verified against its pinned upstream source.
- The deterministic public-package gate excludes paths without a verified
  redistribution basis.

Machine-readable hashes and counts are recorded in
`provenance/AUTHORSHIP_LICENSE_AUDIT_20260823.json`.

## Interpretation boundary

Software-release authorship, copyright ownership, and license permission are
separate concepts. The release-level creator entry and ORCID iD identify the
person responsible for the assembled research software object. Each included
third-party component retains its original authorship, copyright, and license.
This audit is a conservative technical compliance record, not individualized
legal advice.
