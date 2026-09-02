#!/usr/bin/env python3
"""Verify a public ZIP and reproduce it byte-for-byte without Git metadata."""

from __future__ import annotations

import os as _bootstrap_os
import sys as _bootstrap_sys


if __name__ == "__main__" and not _bootstrap_sys.flags.isolated:
    _flags = ["-I", "-B"]
    if _bootstrap_sys.flags.optimize:
        _flags.append("-" + "O" * _bootstrap_sys.flags.optimize)
    _bootstrap_os.execv(
        _bootstrap_sys.executable,
        [
            _bootstrap_sys.executable,
            *_flags,
            _bootstrap_os.path.abspath(__file__),
            *_bootstrap_sys.argv[1:],
        ],
    )

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator, Mapping


ROOT = Path(__file__).resolve().parents[1]
RESULTS_ARCHIVE_NAME = (
    "Exo-Earth-Candidate-Population-Projection-Pipeline-v4.0.4-results.zip"
)
RESULTS_CHECKSUM_NAME = RESULTS_ARCHIVE_NAME + ".sha256"
SOURCE_ARCHIVE_NAME = (
    "exo-earth-candidate-population-projection-pipeline-4.0.4-source.zip"
)
SOURCE_CHECKSUM_NAME = "PUBLIC_SHA256SUMS"
RELEASE_TAG = "v4.0.4"
REPOSITORY = "jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline"
SHA256_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)\n$")


REPARSE_POINT = 0x400


def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def is_link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & REPARSE_POINT
    )


def plain_input_path(value: Path, label: str) -> Path:
    """Inspect the lexical path before any operation that could follow a link."""

    candidate = Path(os.path.abspath(value))
    chain = [candidate]
    while chain[-1] != chain[-1].parent:
        chain.append(chain[-1].parent)
    for path in reversed(chain):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise SystemExit(f"Cannot inspect {label}: {error}")
        if is_link_or_reparse(metadata):
            raise SystemExit(f"Unsafe link/reparse point in {label}: {path}")
        if path == candidate:
            if not stat.S_ISREG(metadata.st_mode):
                raise SystemExit(f"Missing or unsafe {label}: {candidate}")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Non-directory ancestor in {label}: {path}")
    return candidate


@contextmanager
def open_stable(path: Path, label: str) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    candidate = plain_input_path(path, label)
    before = candidate.lstat()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    ancestor_descriptors: list[int] = []
    try:
        if os.name == "posix" and getattr(os, "O_DIRECTORY", 0):
            directory_flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            parent_descriptor = os.open(candidate.anchor, directory_flags)
            ancestor_descriptors.append(parent_descriptor)
            parts = candidate.parts[1:]
            for part in parts[:-1]:
                parent_descriptor = os.open(
                    part, directory_flags, dir_fd=parent_descriptor
                )
                ancestor_descriptors.append(parent_descriptor)
            descriptor = os.open(parts[-1], flags, dir_fd=parent_descriptor)
        else:
            descriptor = os.open(candidate, flags)
    except OSError as error:
        for ancestor in reversed(ancestor_descriptors):
            os.close(ancestor)
        raise SystemExit(f"Cannot open bound {label}: {error}")
    try:
        opened = os.fstat(descriptor)
        if identity(opened) != identity(before):
            raise SystemExit(f"{label} changed while opened")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            yield handle, opened
            after_fd = os.fstat(descriptor)
        after = candidate.lstat()
        if (
            identity(after_fd) != identity(opened)
            or identity(after) != identity(opened)
            or is_link_or_reparse(after)
        ):
            raise SystemExit(f"{label} changed while consumed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for ancestor in reversed(ancestor_descriptors):
            os.close(ancestor)


def read_stable(path: Path, label: str) -> bytes:
    with open_stable(path, label) as (handle, opened):
        data = handle.read()
        if len(data) != opened.st_size:
            raise SystemExit(f"{label} changed while read")
        return data


def sha256(path: Path, label: str = "file") -> str:
    digest = hashlib.sha256()
    with open_stable(path, label) as (handle, opened):
        size = 0
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        if size != opened.st_size:
            raise SystemExit(f"{label} changed while hashed")
    return digest.hexdigest()


def copy_stable(source: Path, destination: Path, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    with open_stable(source, label) as (input_handle, opened):
        descriptor = os.open(destination, flags, 0o600)
        try:
            size = 0
            while True:
                block = input_handle.read(1024 * 1024)
                if not block:
                    break
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SystemExit(f"Cannot copy {label}")
                    view = view[written:]
                size += len(block)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if size != opened.st_size:
            raise SystemExit(f"{label} changed while copied")


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    for info in archive.infolist():
        relative = PurePosixPath(info.filename)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"Unsafe public ZIP path: {info.filename}")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise SystemExit(f"Symlink is not allowed in public ZIP: {info.filename}")
    archive.extractall(destination)


def run_gh(gh: str, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            [gh, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
    except OSError as error:
        raise SystemExit(f"Cannot run GitHub CLI: {error}")
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"GitHub CLI release operation failed: {message}")
    return completed


@dataclass(frozen=True)
class ReleaseAsset:
    asset_id: int
    size_bytes: int
    digest: str


@dataclass(frozen=True)
class ReleaseState:
    release_id: int
    target_commitish: str
    assets: dict[str, ReleaseAsset]


def release_asset_state(gh: str) -> ReleaseState:
    completed = run_gh(
        gh,
        [
            "release",
            "view",
            RELEASE_TAG,
            "--repo",
            REPOSITORY,
            "--json",
            "tagName,isDraft,databaseId,targetCommitish,assets",
        ],
    )
    try:
        document = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"Cannot parse GitHub release evidence: {error}")
    if (
        not isinstance(document, dict)
        or set(document)
        != {"tagName", "isDraft", "databaseId", "targetCommitish", "assets"}
        or document["tagName"] != RELEASE_TAG
        or document["isDraft"] is not False
        or type(document["databaseId"]) is not int
        or document["databaseId"] <= 0
        or not isinstance(document["targetCommitish"], str)
        or not document["targetCommitish"]
        or not isinstance(document["assets"], list)
    ):
        raise SystemExit("GitHub release is not the exact published v4.0.4 release")
    assets: dict[str, ReleaseAsset] = {}
    for index, item in enumerate(document["assets"]):
        api_url = item.get("apiUrl") if isinstance(item, dict) else None
        api_match = (
            re.fullmatch(
                r"https://api\.github\.com/repos/"
                + re.escape(REPOSITORY)
                + r"/releases/assets/([1-9][0-9]*)",
                api_url,
            )
            if isinstance(api_url, str)
            else None
        )
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or not isinstance(item.get("id"), str)
            or not item["id"].startswith("RA_")
            or api_match is None
            or type(item.get("size")) is not int
            or item["size"] < 0
            or item.get("state") != "uploaded"
            or not isinstance(item.get("digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is None
        ):
            raise SystemExit(
                f"GitHub release asset {index} lacks exact name/id/size/digest evidence"
            )
        asset_id = int(api_match.group(1))
        if item["name"] in assets or asset_id in {
            asset.asset_id for asset in assets.values()
        }:
            raise SystemExit("GitHub release contains duplicate asset names or IDs")
        assets[item["name"]] = ReleaseAsset(
            asset_id=asset_id,
            size_bytes=item["size"],
            digest=item["digest"],
        )
    return ReleaseState(
        release_id=document["databaseId"],
        target_commitish=document["targetCommitish"],
        assets=assets,
    )


def release_asset_names(gh: str) -> list[str]:
    """Compatibility view used by policy tests and diagnostics."""

    return list(release_asset_state(gh).assets)


def exact_event_tag_commit(gh: str) -> str:
    if os.environ.get("GITHUB_EVENT_NAME") != "push":
        raise SystemExit("Release publication requires the exact push event")
    if os.environ.get("GITHUB_REF") != f"refs/tags/{RELEASE_TAG}":
        raise SystemExit("Release publication requires the exact v4.0.4 tag ref")
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        raise SystemExit("Release publication ref type is not tag")
    if os.environ.get("GITHUB_REF_NAME") != RELEASE_TAG:
        raise SystemExit("Release publication ref name is not v4.0.4")
    event_sha = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", event_sha) is None:
        raise SystemExit("Release publication GITHUB_SHA is not an exact commit")
    completed = run_gh(
        gh,
        [
            "api",
            f"repos/{REPOSITORY}/commits/{RELEASE_TAG}",
            "--jq",
            ".sha",
        ],
    )
    try:
        tag_sha = completed.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise SystemExit(f"GitHub tag commit is not ASCII: {error}")
    if tag_sha != event_sha:
        raise SystemExit("Release tag target commit differs from GITHUB_SHA")
    return event_sha


def require_same_release_target(
    observed: ReleaseState, baseline: ReleaseState, event_sha: str
) -> None:
    if (
        observed.release_id != baseline.release_id
        or observed.target_commitish != baseline.target_commitish
    ):
        raise SystemExit("GitHub release identity/target changed during publication")
    # GitHub records releases created from the canonical branch with the
    # literal targetCommitish ``main`` even when the release is attached to an
    # already-existing tag.  The immutable release id and literal target are
    # retained here; exact tag-to-commit authority comes from the independent
    # tag API check in ``exact_event_tag_commit`` before and after publication.
    if observed.target_commitish != "main":
        raise SystemExit("GitHub release targetCommitish is not canonical main")
    for name in (RESULTS_ARCHIVE_NAME, RESULTS_CHECKSUM_NAME):
        if observed.assets.get(name) != baseline.assets.get(name):
            raise SystemExit("Accepted results asset API evidence changed during publication")


def accepted_results_api_evidence(source_bytes: bytes) -> dict[str, tuple[int, str]]:
    """Derive exact results-asset API locks from source acceptance bytes."""

    try:
        with zipfile.ZipFile(io.BytesIO(source_bytes), mode="r") as archive:
            acceptance_bytes = archive.read(
                "provenance/V4_0_4_RELEASE_ACCEPTANCE.json"
            )
        acceptance = json.loads(acceptance_bytes.decode("utf-8", errors="strict"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Cannot derive accepted results API evidence: {error}")
    if not isinstance(acceptance, dict) or acceptance.get("release_version") != "4.0.4":
        raise SystemExit("Source acceptance release identity changed")
    lock = acceptance.get("results_archive")
    if not isinstance(lock, dict):
        raise SystemExit("Source acceptance lacks results archive lock")
    digest = lock.get("sha256")
    size = lock.get("size_bytes")
    if (
        lock.get("filename") != RESULTS_ARCHIVE_NAME
        or lock.get("sha256_sidecar_filename") != RESULTS_CHECKSUM_NAME
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or type(size) is not int
        or size <= 0
    ):
        raise SystemExit("Source acceptance results archive lock is malformed")
    checksum_bytes = f"{digest}  {RESULTS_ARCHIVE_NAME}\n".encode("ascii")
    return {
        RESULTS_ARCHIVE_NAME: (size, "sha256:" + digest),
        RESULTS_CHECKSUM_NAME: (
            len(checksum_bytes),
            "sha256:" + hashlib.sha256(checksum_bytes).hexdigest(),
        ),
    }


def require_accepted_results_assets(
    state: ReleaseState, expected: Mapping[str, tuple[int, str]]
) -> None:
    for name, (size, digest) in expected.items():
        asset = state.assets.get(name)
        if asset is None or asset.size_bytes != size or asset.digest != digest:
            raise SystemExit(f"GitHub results asset differs from source acceptance: {name}")


def require_exact_asset_names(state: ReleaseState, expected: set[str]) -> None:
    if set(state.assets) != expected:
        raise SystemExit("GitHub release asset inventory changed during publication")


@dataclass(frozen=True)
class StagedAsset:
    path: Path
    expected: bytes
    identity: tuple[int, int, int, int, int]
    directory_identity: tuple[int, int, int, int, int]


@contextmanager
def immutable_upload_stage(
    source_bytes: bytes, checksum_bytes: bytes
) -> Iterator[tuple[StagedAsset, StagedAsset]]:
    """Create private O_EXCL staging paths and retain their exact identities."""

    directory = Path(tempfile.mkdtemp(prefix="v404-release-upload-stage-"))
    try:
        directory_metadata = directory.lstat()
        if is_link_or_reparse(directory_metadata) or not stat.S_ISDIR(
            directory_metadata.st_mode
        ):
            raise SystemExit("Release upload staging directory is unsafe")
        pending: list[tuple[Path, bytes, tuple[int, int, int, int, int]]] = []
        for name, data in (
            (SOURCE_ARCHIVE_NAME, source_bytes),
            (SOURCE_CHECKSUM_NAME, checksum_bytes),
        ):
            path = directory / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags, 0o400)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise SystemExit("Cannot write immutable release upload stage")
                    view = view[written:]
                os.fsync(descriptor)
                opened = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if opened.st_size != len(data):
                raise SystemExit("Release upload staging write was incomplete")
            pending.append((path, data, identity(opened)))
        if os.name != "nt":
            os.chmod(directory, 0o500)
        directory_identity = identity(directory.lstat())
        staged = tuple(
            StagedAsset(path, data, file_identity, directory_identity)
            for path, data, file_identity in pending
        )
        recheck_staged_assets(staged)
        yield staged[0], staged[1]
        recheck_staged_assets(staged)
    finally:
        if directory.exists():
            os.chmod(directory, 0o700)
            for child in directory.iterdir():
                os.chmod(child, 0o600)
            shutil.rmtree(directory)


def recheck_staged_assets(
    assets: tuple[StagedAsset, ...],
) -> None:
    if not assets:
        raise SystemExit("Release upload staging set is empty")
    directory = assets[0].path.parent
    directory_identity = assets[0].directory_identity
    current_directory = directory.lstat()
    if (
        is_link_or_reparse(current_directory)
        or identity(current_directory) != directory_identity
    ):
        raise SystemExit("Release upload staging directory changed")
    if {item.name for item in directory.iterdir()} != {asset.path.name for asset in assets}:
        raise SystemExit("Release upload staging inventory changed")
    for asset in assets:
        current = asset.path.lstat()
        if is_link_or_reparse(current) or identity(current) != asset.identity:
            raise SystemExit(f"Release upload staged asset changed: {asset.path.name}")
        if read_stable(asset.path, f"staged {asset.path.name}") != asset.expected:
            raise SystemExit(f"Release upload staged bytes changed: {asset.path.name}")


def rollback_created_assets(
    gh: str, baseline: ReleaseState, created: Mapping[str, int]
) -> None:
    failures: list[str] = []
    for name, asset_id in reversed(tuple(created.items())):
        if name in baseline.assets or asset_id in {
            asset.asset_id for asset in baseline.assets.values()
        }:
            failures.append(f"refused non-new asset {name}:{asset_id}")
            continue
        try:
            run_gh(
                gh,
                [
                    "api",
                    "--method",
                    "DELETE",
                    f"repos/{REPOSITORY}/releases/assets/{asset_id}",
                ],
            )
        except SystemExit as error:
            failures.append(str(error))
    try:
        final = release_asset_state(gh)
    except SystemExit as error:
        failures.append(str(error))
    else:
        if (
            final.release_id != baseline.release_id
            or final.target_commitish != baseline.target_commitish
        ):
            failures.append("release identity/target changed during rollback")
        for result_name in (RESULTS_ARCHIVE_NAME, RESULTS_CHECKSUM_NAME):
            if final.assets.get(result_name) != baseline.assets.get(result_name):
                failures.append(f"accepted results asset changed: {result_name}")
        for name, asset_id in created.items():
            observed = final.assets.get(name)
            if observed is not None and observed.asset_id == asset_id:
                failures.append(f"asset remains after rollback: {name}:{asset_id}")
        if set(final.assets) != set(baseline.assets):
            failures.append("release asset inventory differs from the rollback baseline")
    if failures:
        raise SystemExit("Release asset rollback failed: " + "; ".join(failures))


def recover_attempted_source_uploads(
    gh: str,
    baseline: ReleaseState,
    attempted_names: set[str],
    *,
    confirmed_upload_names: set[str] | None = None,
    maximum_state_queries: int = 3,
) -> None:
    """Find and remove only canonical source assets created after ``baseline``.

    A successful remote upload can be followed by a failed API response.  In
    that state the caller does not yet know the new numeric asset id, so a
    bounded recovery query is required before any deletion is permitted.
    Baseline assets and unexpected concurrent assets are never deleted.
    """

    canonical_source_names = {SOURCE_ARCHIVE_NAME, SOURCE_CHECKSUM_NAME}
    confirmed_names = (
        set() if confirmed_upload_names is None else set(confirmed_upload_names)
    )
    if (
        not attempted_names
        or not attempted_names.issubset(canonical_source_names)
        or not confirmed_names.issubset(attempted_names)
        or type(maximum_state_queries) is not int
        or maximum_state_queries <= 0
    ):
        raise SystemExit(
            "manual-recovery-required: source upload recovery inputs are invalid"
        )

    observed: ReleaseState | None = None
    query_failures: list[str] = []
    for _attempt in range(maximum_state_queries):
        try:
            candidate = release_asset_state(gh)
        except SystemExit as error:
            query_failures.append(str(error))
            continue
        if (
            candidate.release_id != baseline.release_id
            or candidate.target_commitish != baseline.target_commitish
        ):
            raise SystemExit(
                "manual-recovery-required: release identity/target changed during "
                "source upload recovery"
            )
        for name, asset in baseline.assets.items():
            if candidate.assets.get(name) != asset:
                raise SystemExit(
                    "manual-recovery-required: a baseline release asset changed "
                    f"during source upload recovery: {name}"
                )
        allowed_names = set(baseline.assets) | attempted_names
        unexpected_names = set(candidate.assets) - allowed_names
        if unexpected_names:
            raise SystemExit(
                "manual-recovery-required: unexpected release assets appeared during "
                f"source upload recovery: {sorted(unexpected_names)}"
            )
        observed = candidate
        if attempted_names.issubset(candidate.assets):
            break
    if observed is None:
        detail = query_failures[-1] if query_failures else "unknown API state"
        raise SystemExit(
            "manual-recovery-required: cannot determine GitHub release state "
            f"after a source upload attempt: {detail}"
        )

    missing_confirmed = confirmed_names - set(observed.assets)
    if missing_confirmed:
        raise SystemExit(
            "manual-recovery-required: a successful upload is absent from the "
            f"bounded recovery state: {sorted(missing_confirmed)}"
        )

    baseline_ids = {asset.asset_id for asset in baseline.assets.values()}
    created: dict[str, int] = {}
    for name in sorted(attempted_names):
        asset = observed.assets.get(name)
        if asset is None:
            continue
        if name in baseline.assets or asset.asset_id in baseline_ids:
            raise SystemExit(
                "manual-recovery-required: attempted source asset reuses baseline "
                f"identity: {name}:{asset.asset_id}"
            )
        created[name] = asset.asset_id

    if not created:
        if observed.assets != baseline.assets:
            raise SystemExit(
                "manual-recovery-required: release state cannot be reduced to the "
                "exact baseline"
            )
        return
    try:
        rollback_created_assets(gh, baseline, created)
    except SystemExit as error:
        raise SystemExit(
            "manual-recovery-required: source asset rollback could not be "
            f"confirmed: {error}"
        ) from error


def publish_v404_source_assets(
    source: Path, checksum: Path, download_directory: Path
) -> str:
    """Attach two absent assets, then download and compare their exact bytes."""

    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise SystemExit("Refusing to publish outside the canonical GitHub repository")
    if not os.environ.get("GH_TOKEN"):
        raise SystemExit("GH_TOKEN is required for exact release-asset publication")
    source_path = plain_input_path(source, "public source ZIP")
    checksum_path = plain_input_path(checksum, "public source checksum")
    if source_path.name != SOURCE_ARCHIVE_NAME or checksum_path.name != SOURCE_CHECKSUM_NAME:
        raise SystemExit("Source release asset filenames are not canonical")
    source_bytes = read_stable(source_path, "public source ZIP")
    checksum_bytes = read_stable(checksum_path, "public source checksum")
    try:
        checksum_text = checksum_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise SystemExit(f"Public source checksum is not ASCII: {error}")
    match = SHA256_LINE.fullmatch(checksum_text)
    digest = hashlib.sha256(source_bytes).hexdigest()
    if match is None or match.group(1) != digest or match.group(2) != source_path.name:
        raise SystemExit("Public source checksum does not bind the source ZIP")
    accepted_results = accepted_results_api_evidence(source_bytes)
    gh = shutil.which("gh")
    if gh is None:
        raise SystemExit("GitHub CLI is required for release-asset publication")
    event_sha = exact_event_tag_commit(gh)
    before = release_asset_state(gh)
    require_same_release_target(before, before, event_sha)
    require_accepted_results_assets(before, accepted_results)
    required_results = {RESULTS_ARCHIVE_NAME, RESULTS_CHECKSUM_NAME}
    for name in (source_path.name, checksum_path.name):
        if name in before.assets:
            raise SystemExit(f"Refusing to overwrite existing GitHub release asset: {name}")
    require_exact_asset_names(before, required_results)
    attempted_names: set[str] = set()
    confirmed_upload_names: set[str] = set()
    uploaded_ids: dict[str, int] = {}
    try:
        with immutable_upload_stage(source_bytes, checksum_bytes) as staged:
            if exact_event_tag_commit(gh) != event_sha:
                raise SystemExit("Release tag commit changed immediately before upload")
            for index, asset in enumerate(staged):
                recheck_staged_assets(tuple(staged))
                attempted_names.add(asset.path.name)
                run_gh(
                    gh,
                    [
                        "release",
                        "upload",
                        RELEASE_TAG,
                        str(asset.path),
                        "--repo",
                        REPOSITORY,
                    ],
                )
                confirmed_upload_names.add(asset.path.name)
                current = release_asset_state(gh)
                require_same_release_target(current, before, event_sha)
                require_accepted_results_assets(current, accepted_results)
                uploaded = current.assets.get(asset.path.name)
                if uploaded is None or uploaded.asset_id in {
                    item.asset_id for item in before.assets.values()
                }:
                    raise SystemExit(
                        f"Uploaded GitHub release asset is not a unique new ID: {asset.path.name}"
                    )
                expected_digest = "sha256:" + hashlib.sha256(asset.expected).hexdigest()
                if (
                    uploaded.size_bytes != len(asset.expected)
                    or uploaded.digest != expected_digest
                ):
                    raise SystemExit(
                        f"GitHub API digest/size differs for uploaded asset: {asset.path.name}"
                    )
                uploaded_ids[asset.path.name] = uploaded.asset_id
                expected_names = set(before.assets) | {
                    item.path.name for item in staged[: index + 1]
                }
                require_exact_asset_names(current, expected_names)

            download_root = Path(os.path.abspath(download_directory))
            try:
                download_root.lstat()
            except FileNotFoundError:
                parent = download_root.parent
                if not parent.is_dir() or parent.is_symlink():
                    raise SystemExit("Release download-recheck parent is unsafe")
                os.mkdir(download_root, 0o700)
            except OSError as error:
                raise SystemExit(f"Cannot inspect release download-recheck directory: {error}")
            else:
                raise SystemExit("Release download-recheck directory must not pre-exist")
            run_gh(
                gh,
                [
                    "release",
                    "download",
                    RELEASE_TAG,
                    "--repo",
                    REPOSITORY,
                    "--pattern",
                    source_path.name,
                    "--pattern",
                    checksum_path.name,
                    "--dir",
                    str(download_root),
                ],
            )
            observed = {item.name for item in download_root.iterdir()}
            if observed != {source_path.name, checksum_path.name}:
                raise SystemExit("Downloaded release-asset inventory is not exact")
            downloaded_source = read_stable(
                download_root / source_path.name, "downloaded public source ZIP"
            )
            downloaded_checksum = read_stable(
                download_root / checksum_path.name, "downloaded public source checksum"
            )
            if downloaded_source != source_bytes or downloaded_checksum != checksum_bytes:
                raise SystemExit("Downloaded GitHub release assets differ from uploaded bytes")
            final_state = release_asset_state(gh)
            require_same_release_target(final_state, before, event_sha)
            require_accepted_results_assets(final_state, accepted_results)
            require_exact_asset_names(
                final_state,
                set(before.assets) | {item.path.name for item in staged},
            )
            for asset in staged:
                remote = final_state.assets.get(asset.path.name)
                if (
                    remote is None
                    or remote.asset_id != uploaded_ids[asset.path.name]
                    or remote.size_bytes != len(asset.expected)
                    or remote.digest
                    != "sha256:" + hashlib.sha256(asset.expected).hexdigest()
                ):
                    raise SystemExit(
                        f"Final GitHub API evidence differs for {asset.path.name}"
                    )
            recheck_staged_assets(tuple(staged))
            if exact_event_tag_commit(gh) != event_sha:
                raise SystemExit("Release tag commit changed immediately after upload")
    except SystemExit as error:
        if attempted_names:
            try:
                recover_attempted_source_uploads(
                    gh,
                    before,
                    attempted_names,
                    confirmed_upload_names=confirmed_upload_names,
                )
            except SystemExit as rollback_error:
                raise SystemExit(f"{error}; {rollback_error}") from error
        raise
    return digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--results-archive", type=Path)
    parser.add_argument("--results-checksum", type=Path)
    parser.add_argument("--publish-v404-source-assets", action="store_true")
    parser.add_argument("--source-checksum", type=Path)
    parser.add_argument("--download-dir", type=Path)
    args = parser.parse_args()
    if args.publish_v404_source_assets:
        if args.source_checksum is None or args.download_dir is None:
            raise SystemExit(
                "Publishing requires --source-checksum and --download-dir"
            )
        digest = publish_v404_source_assets(
            args.archive, args.source_checksum, args.download_dir
        )
        print(f"PASS GitHub v4.0.4 source assets uploaded and rechecked: {digest}")
        return
    if args.download_dir is not None:
        raise SystemExit("--download-dir requires --publish-v404-source-assets")
    source = plain_input_path(args.archive, "public ZIP")
    source_checksum = plain_input_path(
        args.source_checksum
        if args.source_checksum is not None
        else source.parent / SOURCE_CHECKSUM_NAME,
        "public source checksum",
    )
    source_checksum_bytes = read_stable(source_checksum, "public source checksum")
    make = shutil.which("make")
    if not make:
        raise SystemExit("The round-trip gate requires make")
    results_archive = (
        plain_input_path(args.results_archive, "results archive")
        if args.results_archive is not None
        else source.parent / RESULTS_ARCHIVE_NAME
    )
    results_checksum = (
        plain_input_path(args.results_checksum, "results checksum")
        if args.results_checksum is not None
        else source.parent / RESULTS_CHECKSUM_NAME
    )
    results_archive = plain_input_path(results_archive, "results archive")
    results_checksum = plain_input_path(results_checksum, "results checksum")

    source_bytes = read_stable(source, "public ZIP")
    original = hashlib.sha256(source_bytes).hexdigest()
    expected_source_checksum = f"{original}  {source.name}\n".encode("ascii")
    if source_checksum_bytes != expected_source_checksum:
        raise SystemExit("External public source checksum does not bind the source ZIP")
    with tempfile.TemporaryDirectory(prefix="exoearth-public-no-git-") as raw:
        root = Path(raw)
        with zipfile.ZipFile(io.BytesIO(source_bytes), "r") as archive:
            safe_extract(archive, root)
        if (root / ".git").exists():
            raise SystemExit("Public ZIP unexpectedly contains .git")
        extracted_dist = root / "dist"
        extracted_dist.mkdir()
        copy_stable(
            results_archive,
            extracted_dist / RESULTS_ARCHIVE_NAME,
            "results archive",
        )
        copy_stable(
            results_checksum,
            extracted_dist / RESULTS_CHECKSUM_NAME,
            "results checksum",
        )
        trusted_gate = ROOT / "scripts" / "verify_v404_release_acceptance.py"
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(trusted_gate),
                "--repository-root",
                str(root),
                "--results-archive",
                str(extracted_dist / RESULTS_ARCHIVE_NAME),
                "--results-checksum",
                str(extracted_dist / RESULTS_CHECKSUM_NAME),
                "--trusted-source-archive",
                str(source),
                "--trusted-source-checksum",
                str(source_checksum),
            ],
            cwd=ROOT,
            check=True,
        )
        environment = dict(os.environ)
        environment["V404_TRUSTED_SOURCE_ARCHIVE"] = str(source)
        environment["V404_TRUSTED_SOURCE_CHECKSUM"] = str(source_checksum)
        subprocess.run([make, "verify"], cwd=root, env=environment, check=True)
        subprocess.run(
            [make, "public-package"], cwd=root, env=environment, check=True
        )
        rebuilt = root / "dist" / source.name
        actual = sha256(rebuilt, "rebuilt public ZIP")
        if actual != original:
            raise SystemExit(
                f"Public ZIP round-trip mismatch: expected {original}, got {actual}"
            )
    print(f"PASS no-Git public ZIP round trip: {original}")


if __name__ == "__main__":
    main()
