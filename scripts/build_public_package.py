#!/usr/bin/env python3
"""Build and verify a deterministic license-cleared public source archive."""

from __future__ import annotations

import csv
import hashlib
import io
import re
import zipfile
from pathlib import Path, PurePosixPath

import verify_license_policy


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
# Versioned reproducibility timestamp, not the wall-clock build time. Keeping
# every ZIP member at the release date makes independent builds byte-identical.
SOURCE_DATE_UTC = (2026, 8, 29, 0, 0, 0)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    if not match:
        raise SystemExit("Cannot determine project version")
    return match.group(1)


def render_filtered_matrix(rows: list[dict[str, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=verify_license_policy.build_license_matrix.FIELDNAMES,
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        if row["included_in_public_package"] == "yes":
            writer.writerow(row)
    return output.getvalue().encode("utf-8")


def public_sources(rows: list[dict[str, str]]) -> list[tuple[dict[str, str], bytes]]:
    selected: list[tuple[dict[str, str], bytes]] = []
    filtered_matrix = render_filtered_matrix(rows)
    for row in rows:
        if row["included_in_public_package"] != "yes":
            continue
        relative = PurePosixPath(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"Unsafe public path: {row['path']}")
        source = ROOT.joinpath(*relative.parts)
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"Public path is missing, not a file, or a symlink: {row['path']}")
        if row["path"] == "provenance/LICENSE_MATRIX.csv":
            data = filtered_matrix
        elif row["path"] == "MANIFEST.sha256":
            data = b""
        else:
            data = source.read_bytes()
        selected.append((row, data))
    selected.sort(key=lambda item: item[0]["path"])
    manifest = "".join(
        f"{sha256_bytes(data)}  {row['path']}\n"
        for row, data in selected
        if row["path"] != "MANIFEST.sha256"
    ).encode("utf-8")
    return [
        (row, manifest if row["path"] == "MANIFEST.sha256" else data)
        for row, data in selected
    ]


def build_zip(files: list[tuple[dict[str, str], bytes]]) -> bytes:
    archive_files = [(row["path"], data) for row, data in files]

    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name, data in archive_files:
            info = zipfile.ZipInfo(name, date_time=SOURCE_DATE_UTC)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def verify_zip(
    archive_bytes: bytes,
    files: list[tuple[dict[str, str], bytes]],
) -> None:
    expected = {row["path"]: data for row, data in files}
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        names = archive.namelist()
        if names != sorted(expected):
            raise SystemExit("Public ZIP inventory/order mismatch")
        if len(names) != len(set(names)):
            raise SystemExit("Duplicate path in public ZIP")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise SystemExit(f"Unsafe ZIP member: {name}")
            if archive.read(name) != expected[name]:
                raise SystemExit(f"ZIP byte mismatch: {name}")


def inventory_csv(
    files: list[tuple[dict[str, str], bytes]],
) -> str:
    output = io.StringIO(newline="")
    fields = ("path", "sha256", "license", "origin")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row, data in files:
        writer.writerow(
            {
                "path": row["path"],
                "sha256": sha256_bytes(data),
                "license": row["license"],
                "origin": row["origin"],
            }
        )
    return output.getvalue()


def main() -> None:
    rows = verify_license_policy.verify()
    files = public_sources(rows)
    first = build_zip(files)
    second = build_zip(files)
    if first != second:
        raise SystemExit("Deterministic rebuild mismatch")
    verify_zip(first, files)

    DIST.mkdir(parents=True, exist_ok=True)
    archive_name = (
        "exo-earth-candidate-population-projection-pipeline-"
        f"{project_version()}-source.zip"
    )
    archive_path = DIST / archive_name
    archive_path.write_bytes(first)
    inventory = inventory_csv(files)
    (DIST / "PUBLIC_RELEASE_FILE_INVENTORY.csv").write_text(
        inventory, encoding="utf-8", newline="\n"
    )
    digest = sha256_bytes(first)
    (DIST / "PUBLIC_SHA256SUMS").write_text(
        f"{digest}  {archive_name}\n", encoding="utf-8", newline="\n"
    )
    print(
        f"PASS deterministic public package: {archive_name} "
        f"({len(files)} files, sha256={digest})"
    )


if __name__ == "__main__":
    main()
