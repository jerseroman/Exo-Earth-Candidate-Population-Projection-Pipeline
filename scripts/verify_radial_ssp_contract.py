#!/usr/bin/env python3
"""Execute, privately verify, qualify, and publicly bind radial JJ SSP triplets."""

from __future__ import annotations

if __name__ == "__main__":
    import os as _bootstrap_os
    import sys as _bootstrap_sys

    if not _bootstrap_sys.flags.isolated or not _bootstrap_sys.dont_write_bytecode:
        _optimisation = (
            "-" + "O" * _bootstrap_sys.flags.optimize
            if _bootstrap_sys.flags.optimize
            else None
        )
        _argv = [_bootstrap_sys.executable]
        if _optimisation is not None:
            _argv.append(_optimisation)
        _script_path = _bootstrap_os.path.abspath(__file__)
        _argv.extend(
            (
                "-I",
                "-B",
                _script_path,
                *_bootstrap_sys.argv[1:],
            )
        )
        if _bootstrap_os.name == "nt":
            def _quote_windows_argument(value: str) -> str:
                if value and not any(character in " \t\"" for character in value):
                    return value
                rendered = '"'
                backslashes = 0
                for character in value:
                    if character == "\\":
                        backslashes += 1
                    elif character == '"':
                        rendered += "\\" * (2 * backslashes + 1) + '"'
                        backslashes = 0
                    else:
                        rendered += "\\" * backslashes + character
                        backslashes = 0
                return rendered + "\\" * (2 * backslashes) + '"'

            _argv = [_quote_windows_argument(value) for value in _argv]
        _bootstrap_os.execv(_bootstrap_sys.executable, _argv)

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable
import types
import uuid


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RADIAL_SOURCE_DIR = REPOSITORY_ROOT / "research" / "jj-tams-convergence"
JJ_SHA = "2828a2e8bfc379ba9c8ef4b4d0477ab5febe3b54"
PADOVA_SHA256 = "97c8e09ea2669abe4147333f0fa141642e2c56d97b6f44de4e4518974ab7c7e8"
PADOVA_SIZE_BYTES = 327078533
PADOVA_FILENAME = "multiband_padova.zip"
TUTORIAL_PARAMETERS_SHA256 = (
    "e5919225b94e9ce8d8a7ad31553f0932bd437e2ae14f117dc39a37934e78a1c6"
)
TUTORIAL_SFR_SHA256 = (
    "56d25b9ea61f454630a222ce6a6414bd1eaeb13bd165c25e9559ebe5c6b5039b"
)
TAMS_REFERENCE_SHA256 = (
    "d2c47b264a298a599064a9e58f19f309886e7b96f36cc9603c9ca55494f87aac"
)
GENERATOR_RELATIVE = "research/jj-tams-convergence/tams_radial_convergence.py"
CONTROLLER_RELATIVES = (
    "scripts/verify_radial_ssp_contract.py",
    "research/jj-tams-convergence/radial_ssp_rederive.py",
    "scripts/verify_age_cut_sensitivity.py",
    "scripts/verify_age_cut_ssp_contract.py",
    "scripts/verify_host_artifact_contract.py",
)
CONTRACT_ID = "jj-padova-radial-ssp-v4.0.4"
DRS = (1.0, 0.5, 0.25)
START_NAMESPACE = "exoearth-radial-ssp-v4.0.4.start"
COMPLETION_NAMESPACE = "exoearth-radial-ssp-v4.0.4.completion"
TRIPLET_NAMESPACE = "exoearth-radial-ssp-v4.0.4.triplet"
PRIVATE_RUN_FILES = {
    "parameters.original",
    "parameters.runtime",
    "sfrd_peaks_parameters",
    "NUMERICAL_RUNTIME_POLICY.json",
    "RUN_START_CHALLENGE.json",
    "RUN_START_CHALLENGE.sig",
    "RUN_EXECUTION_RECORD.json",
    "RUN_COMPLETION_ATTESTATION.json",
    "RUN_COMPLETION_ATTESTATION.sig",
    "RUN_PRIVATE_PROVENANCE.json",
    "tams_radial.csv",
    "tams_result.json",
    "SSP_SHA256SUMS.txt",
    "ssp",
}
PRIVATE_TRIPLET_FILES = {
    "TRIPLET_ATTESTATION.json",
    "TRIPLET_ATTESTATION.sig",
    "TRIPLET_PRIVATE_PROVENANCE.json",
}
MAX_JSON_BYTES = 8_000_000
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RUN_DIR_NAMES = {1.0: "dr1p0", 0.5: "dr0p5", 0.25: "dr0p25"}
EXPECTED_SELECTOR = (
    "5300<=Teff<=6000 K; age>=4.57 Gyr; thin+thick; "
    "Rstar<=PARSEC-TAMS(Teff); logg<7 remnant veto"
)
EXPECTED_OCCURRENCE = (
    "Bryson Model 1 hab2 constant-completeness + Kopparapu conservative HZ"
)


secure: Any = None
rederive: Any = None


class RadialBootstrapError(RuntimeError):
    """Raised before any local dependency is permitted to execute."""


def _bootstrap_fail(message: str) -> None:
    raise RadialBootstrapError(f"radial source bootstrap failed: {message}")


def _captured_source_bytes(path: Path, description: str) -> bytes:
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except OSError as exc:
        _bootstrap_fail(f"cannot inspect {description}: {exc}")
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(
            getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
        or not stat.S_ISREG(before.st_mode)
    ):
        _bootstrap_fail(f"{description} is not a regular source file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened_before = os.fstat(handle.fileno())
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
        after = candidate.lstat()
    except OSError as exc:
        _bootstrap_fail(f"cannot capture {description}: {exc}")
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, opened_before, opened_after, after)
    }
    if (
        len(identities) != 1
        or not stat.S_ISREG(opened_before.st_mode)
        or len(data) != opened_after.st_size
    ):
        _bootstrap_fail(f"{description} changed during its stable capture")
    if len(data) > 16_000_000:
        _bootstrap_fail(f"{description} exceeds the source bootstrap byte limit")
    return data


def _archive_dependency_bytes(
    archive_path: Path, relatives: tuple[str, ...], description: str
) -> dict[str, bytes]:
    archive_bytes = _captured_source_bytes(archive_path, description)
    expected = set(relatives)
    observed: dict[str, bytes] = {}
    casefolded: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as bundle:
            for member in bundle.getmembers():
                name = member.name.rstrip("/")
                relative = PurePosixPath(name)
                if (
                    "\\" in member.name
                    or "\x00" in member.name
                    or relative.is_absolute()
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                ):
                    _bootstrap_fail(f"{description} contains an unsafe member path")
                normalized = relative.as_posix()
                folded = normalized.casefold()
                if folded in casefolded:
                    _bootstrap_fail(
                        f"{description} contains duplicate or case-colliding members"
                    )
                casefolded.add(folded)
                if normalized not in expected:
                    continue
                if not member.isreg():
                    _bootstrap_fail(
                        f"{description} dependency is not a regular source member: "
                        f"{normalized}"
                    )
                extracted = bundle.extractfile(member)
                if extracted is None:
                    _bootstrap_fail(
                        f"cannot read {description} dependency {normalized}"
                    )
                data = extracted.read()
                if len(data) != member.size:
                    _bootstrap_fail(f"short read for {description} member {normalized}")
                observed[normalized] = data
    except (OSError, tarfile.TarError) as exc:
        _bootstrap_fail(f"cannot inspect {description}: {exc}")
    if set(observed) != expected:
        _bootstrap_fail(f"{description} lacks the exact controller dependency set")
    if _captured_source_bytes(archive_path, description) != archive_bytes:
        _bootstrap_fail(f"{description} changed after its stable capture")
    return observed


def _execute_captured_module(name: str, path: Path, data: bytes) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__cached__ = None
    module.__package__ = ""
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        code = compile(data, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def _load_local_dependencies(
    *, public_source_archive: Path | None = None, private_source_archive: Path | None = None
) -> None:
    """Load only stable `.py` bytes; never delegate to a path/pyc importer."""

    global secure, rederive
    if (secure is None) != (rederive is None):
        _bootstrap_fail("radial dependency state is only partially initialised")
    already_loaded = secure is not None
    paths = {
        "verify_age_cut_ssp_contract": REPOSITORY_ROOT
        / "scripts"
        / "verify_age_cut_ssp_contract.py",
        "verify_host_artifact_contract": REPOSITORY_ROOT
        / "scripts"
        / "verify_host_artifact_contract.py",
        "verify_age_cut_sensitivity": REPOSITORY_ROOT
        / "scripts"
        / "verify_age_cut_sensitivity.py",
        "radial_ssp_rederive": RADIAL_SOURCE_DIR / "radial_ssp_rederive.py",
    }
    captured = {
        name: _captured_source_bytes(path, f"captured radial dependency {name}")
        for name, path in paths.items()
    }
    if (public_source_archive is None) != (private_source_archive is None):
        _bootstrap_fail("public/private archive binding must be supplied together")
    if public_source_archive is not None and private_source_archive is not None:
        relatives = CONTROLLER_RELATIVES
        public_members = _archive_dependency_bytes(
            public_source_archive, relatives, "public production source archive"
        )
        private_members = _archive_dependency_bytes(
            private_source_archive, relatives, "private production source archive"
        )
        for relative in relatives:
            executing = _captured_source_bytes(
                REPOSITORY_ROOT / relative,
                f"executing radial dependency {relative}",
            )
            if public_members[relative] != executing or private_members[relative] != executing:
                _bootstrap_fail(
                    f"executing/public/private source bytes differ for {relative}"
                )
    if already_loaded:
        return

    aliases = (
        "verify_age_cut_ssp_contract",
        "verify_host_artifact_contract",
        "verify_age_cut_sensitivity",
        "radial_ssp_rederive",
    )
    missing = object()
    previous_aliases = {name: sys.modules.get(name, missing) for name in aliases}
    original_path = list(sys.path)
    try:
        secure_module = _execute_captured_module(
            "_v404_radial_secure_io",
            paths["verify_age_cut_ssp_contract"],
            captured["verify_age_cut_ssp_contract"],
        )
        sys.modules["verify_age_cut_ssp_contract"] = secure_module
        host_module = _execute_captured_module(
            "_v404_radial_host_contract",
            paths["verify_host_artifact_contract"],
            captured["verify_host_artifact_contract"],
        )
        sys.modules["verify_host_artifact_contract"] = host_module
        sensitivity_module = _execute_captured_module(
            "_v404_radial_age_sensitivity",
            paths["verify_age_cut_sensitivity"],
            captured["verify_age_cut_sensitivity"],
        )
        sys.modules["verify_age_cut_sensitivity"] = sensitivity_module
        rederive_module = _execute_captured_module(
            "_v404_radial_rederive",
            paths["radial_ssp_rederive"],
            captured["radial_ssp_rederive"],
        )
    finally:
        sys.path[:] = original_path
        for name, previous in previous_aliases.items():
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    if secure_module.__cached__ is not None or rederive_module.__cached__ is not None:
        _bootstrap_fail("captured radial dependencies unexpectedly expose bytecode")
    secure = secure_module
    rederive = rederive_module


class RadialContractError(RuntimeError):
    """Raised when the radial SSP trust boundary fails closed."""


def fail(message: str) -> None:
    raise RadialContractError(message)


def adapt_error(callable_value: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return callable_value(*args, **kwargs)
    except (secure.SSPContractError, rederive.RadialDerivationError) as exc:
        fail(str(exc))


def require_safe_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        fail(f"{description} is not a safe identifier")
    return value


def require_sha(value: Any, length: int, description: str) -> str:
    pattern = r"[0-9a-f]{40}" if length == 40 else r"[0-9a-f]{64}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        fail(f"{description} must be lowercase {length}-hex")
    return value


def exact_keys(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    try:
        return secure.exact_keys(value, keys, description)
    except secure.SSPContractError as exc:
        fail(str(exc))


def canonical_bytes(value: Any) -> bytes:
    return secure.canonical_json_bytes(value)


def strict_json_snapshot(path: Path, description: str) -> tuple[dict[str, Any], secure.FileSnapshot]:
    snapshot = adapt_error(
        secure.read_snapshot, path, description, maximum_bytes=MAX_JSON_BYTES
    )
    document = adapt_error(secure.load_json_bytes, snapshot.data, description)
    if not isinstance(document, dict):
        fail(f"{description} must be a JSON object")
    return document, snapshot


def evidence(snapshot: secure.FileSnapshot) -> dict[str, Any]:
    return secure.evidence(snapshot)


def validate_contract(document: Any) -> dict[str, Any]:
    contract = exact_keys(
        document,
        {"schema_version", "contract_id", "locked_inputs", "qualification_policy", "artifact_sets"},
        "radial SSP contract",
    )
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        fail("radial SSP contract schema_version must be integer 1")
    if contract["contract_id"] != CONTRACT_ID:
        fail("unexpected radial SSP contract id")
    locked = exact_keys(
        contract["locked_inputs"],
        {
            "jj_repository",
            "jj_commit",
            "jj_version_expected",
            "isochrone_family",
            "padova_archive",
            "tutorial_parameters_sha256",
            "tutorial_sfr_sha256",
            "tams_reference_sha256",
        },
        "radial SSP locked inputs",
    )
    expected_locked = {
        "jj_repository": "askenja/jjmodel",
        "jj_commit": JJ_SHA,
        "jj_version_expected": "1.0.1",
        "isochrone_family": "Padova/PARSEC",
        "padova_archive": {
            "data_lock_id": secure.PADOVA_LOCK_ID,
            "filename": PADOVA_FILENAME,
            "sha256": PADOVA_SHA256,
            "size_bytes": PADOVA_SIZE_BYTES,
        },
        "tutorial_parameters_sha256": TUTORIAL_PARAMETERS_SHA256,
        "tutorial_sfr_sha256": TUTORIAL_SFR_SHA256,
        "tams_reference_sha256": TAMS_REFERENCE_SHA256,
    }
    if locked != expected_locked:
        fail("radial SSP locked inputs differ from the release locks")
    policy = exact_keys(
        contract["qualification_policy"],
        {
            "required_distinct_fresh_triplets",
            "required_distinct_signers",
            "radial_spacings_kpc",
            "radial_domain_kpc",
            "expected_ssp_file_counts",
            "generator_relative_path",
            "controller",
            "execution_mode",
            "private_raw_ssp_required",
            "public_qualification_contains_raw_ssp",
            "require_signed_pre_run_challenges",
            "require_exact_git_archives",
            "require_executing_controller_matches_committed_source",
            "require_exact_padova_overlay_before_and_after",
            "require_independent_raw_ssp_rederivation",
            "allowed_execution_environments",
        },
        "radial SSP qualification policy",
    )
    if policy != {
        "required_distinct_fresh_triplets": 2,
        "required_distinct_signers": 2,
        "radial_spacings_kpc": [1.0, 0.5, 0.25],
        "radial_domain_kpc": [4.0, 14.0],
        "expected_ssp_file_counts": {"1.0": 22, "0.5": 42, "0.25": 82},
        "generator_relative_path": GENERATOR_RELATIVE,
        "controller": "verify_radial_ssp_contract.execute_fresh_triplet",
        "execution_mode": "subprocess_no_shell_exact_pinned",
        "private_raw_ssp_required": True,
        "public_qualification_contains_raw_ssp": False,
        "require_signed_pre_run_challenges": True,
        "require_exact_git_archives": True,
        "require_executing_controller_matches_committed_source": True,
        "require_exact_padova_overlay_before_and_after": True,
        "require_independent_raw_ssp_rederivation": True,
        "allowed_execution_environments": list(secure.ALLOWED_ENVIRONMENTS),
    }:
        fail("radial SSP qualification policy changed")
    sets = contract["artifact_sets"]
    if not isinstance(sets, list) or not sets:
        fail("radial SSP artifact_sets must be a non-empty list")
    identifiers: set[str] = set()
    accepted = 0
    for index, raw in enumerate(sets):
        item = exact_keys(
            raw,
            {
                "id",
                "role",
                "production_accepted",
                "qualification_eligible",
                "attestation_signers",
                "qualified_public_evidence_sha256",
                "qualification_report",
                "note",
            },
            f"radial SSP artifact set {index}",
        )
        identifier = require_safe_id(item["id"], "radial artifact-set id")
        if identifier in identifiers:
            fail("duplicate radial artifact-set id")
        identifiers.add(identifier)
        if item["role"] not in {"qualification_candidate", "qualified_candidate"}:
            fail("invalid radial artifact-set role")
        if type(item["production_accepted"]) is not bool or type(
            item["qualification_eligible"]
        ) is not bool:
            fail("radial artifact-set flags must be booleans")
        if not isinstance(item["note"], str) or not item["note"]:
            fail("radial artifact-set note must be non-empty")
        signers = item["attestation_signers"]
        if signers is not None:
            if not isinstance(signers, list) or len(signers) != 2:
                fail("radial candidate must lock exactly two signers")
            signer_ids: set[str] = set()
            public_keys: set[str] = set()
            for signer_raw in signers:
                signer = exact_keys(
                    signer_raw, {"signer_id", "public_key"}, "radial signer"
                )
                signer_ids.add(require_safe_id(signer["signer_id"], "radial signer id"))
                public_key = signer["public_key"]
                if (
                    not isinstance(public_key, str)
                    or not public_key.startswith("ssh-ed25519 ")
                    or "\n" in public_key
                    or "\r" in public_key
                ):
                    fail("radial signer public key is not one OpenSSH Ed25519 line")
                public_keys.add(public_key)
            if len(signer_ids) != 2 or len(public_keys) != 2:
                fail("radial signer ids and public keys must be distinct")
        populated = (
            item["qualified_public_evidence_sha256"] is not None,
            item["qualification_report"] is not None,
        )
        if any(populated) and not all(populated):
            fail("radial qualification fields must be both null or both populated")
        if all(populated):
            require_sha(
                item["qualified_public_evidence_sha256"],
                64,
                "qualified radial public evidence hash",
            )
            report = exact_keys(
                item["qualification_report"], {"path", "sha256"}, "radial report lock"
            )
            if (
                not isinstance(report["path"], str)
                or Path(report["path"]).name != report["path"]
                or "/" in report["path"]
                or "\\" in report["path"]
            ):
                fail("radial qualification report path must be one basename")
            require_sha(report["sha256"], 64, "radial qualification report hash")
        if item["production_accepted"]:
            accepted += 1
            if (
                item["role"] != "qualified_candidate"
                or item["qualification_eligible"] is not True
                or signers is None
                or not all(populated)
            ):
                fail("accepted radial artifact set is not fully qualified")
    if accepted > 1:
        fail("radial contract contains multiple accepted artifact sets")
    return contract


def load_contract(path: Path) -> tuple[dict[str, Any], secure.FileSnapshot]:
    document, snapshot = strict_json_snapshot(path, "radial SSP contract")
    return validate_contract(document), snapshot


def artifact_set(contract: dict[str, Any], identifier: str) -> dict[str, Any]:
    matches = [item for item in contract["artifact_sets"] if item["id"] == identifier]
    if len(matches) != 1:
        fail("unknown or duplicate radial artifact-set id")
    return matches[0]


def candidate_signer(candidate: dict[str, Any], signer_id: str) -> dict[str, str]:
    signers = candidate["attestation_signers"]
    if not isinstance(signers, list) or len(signers) != 2:
        fail("radial candidate does not lock two signers")
    matches = [item for item in signers if item["signer_id"] == signer_id]
    if len(matches) != 1:
        fail("unknown or duplicate radial signer")
    return matches[0]


def document_with_id(body: dict[str, Any], id_field: str) -> dict[str, Any]:
    return {
        id_field: "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest(),
        **body,
    }


def validate_document_id(document: dict[str, Any], id_field: str, description: str) -> None:
    body = dict(document)
    identifier = body.pop(id_field, None)
    expected = "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()
    if identifier != expected:
        fail(f"{description} self-identifier mismatch")


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def parse_utc(value: Any, description: str) -> datetime:
    try:
        return secure.parse_timestamp(value, description)
    except secure.SSPContractError as exc:
        fail(str(exc))


def write_json_exclusive(path: Path, value: Any) -> None:
    adapt_error(secure.write_bytes_exclusive, path, json.dumps(
        value, indent=2, sort_keys=True, allow_nan=False
    ).encode("utf-8") + b"\n")


def sign_document(
    path: Path, key: Path, namespace: str, signature_name: str
) -> Path:
    return adapt_error(
        secure.sign_document,
        path,
        key,
        namespace=namespace,
        destination_name=signature_name,
    )


def verify_signature_bytes(
    document_bytes: bytes,
    signature_bytes: bytes,
    signer: dict[str, str],
    namespace: str,
) -> None:
    document = secure.synthetic_snapshot("document.json", document_bytes)
    signature = secure.synthetic_snapshot("document.sig", signature_bytes)
    adapt_error(
        secure.verify_signature,
        document,
        signature,
        signer,
        namespace=namespace,
    )


def finite_number(value: Any, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{description} must be a JSON number, not a boolean or coercible value")
    number = float(value)
    if not math.isfinite(number):
        fail(f"{description} must be finite")
    return number


def require_nonnegative_int(value: Any, description: str) -> int:
    if type(value) is not int or value < 0:
        fail(f"{description} must be a nonnegative JSON integer")
    return value


def close_number(observed: Any, expected: float, description: str) -> float:
    value = finite_number(observed, description)
    absolute = abs(value - expected)
    relative = absolute / max(abs(expected), 1.0)
    if absolute > 1.0e-5 and relative > 5.0e-12:
        fail(f"{description} differs from the private raw-SSP rederivation")
    return value


def expected_runtime_parameters(original: bytes, dr: float) -> bytes:
    if type(dr) is not float or dr not in DRS:
        fail("unsupported exact radial spacing")
    value = original
    replacements = (
        (rb"(?m)^(Rmin\s+)4(\s+)", rb"\g<1>4.0\g<2>"),
        (rb"(?m)^(Rmax\s+)14(\s+)", rb"\g<1>14.0\g<2>"),
        (
            rb"(?m)^(dR\s+)1(\s+)",
            (rb"\g<1>" + str(dr).encode("ascii") + rb"\g<2>"),
        ),
        (rb"(?m)^(nprocess\s+)4(\s+)", rb"\g<1>2\g<2>"),
    )
    for pattern, replacement in replacements:
        value, count = re.subn(pattern, replacement, value)
        if count != 1:
            fail("tutorial2 parameter substitution did not match exactly once")
    return value


def tracked_program_snapshot(root_path: Path) -> secure.FileSnapshot:
    root = adapt_error(secure.require_directory, root_path, "private production source")
    program = adapt_error(
        secure.read_snapshot,
        root / GENERATOR_RELATIVE,
        "pinned radial generation program",
    )
    try:
        committed = subprocess.check_output(
            ["git", "show", f"HEAD:{GENERATOR_RELATIVE}"], cwd=root
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot read committed radial generation program: {exc}")
    if committed != program.data:
        fail("working radial generation program differs from committed source")
    return program


def tracked_controller_snapshots(root_path: Path) -> dict[str, secure.FileSnapshot]:
    root = adapt_error(secure.require_directory, root_path, "private production source")
    snapshots: dict[str, secure.FileSnapshot] = {}
    for relative in CONTROLLER_RELATIVES:
        private = adapt_error(
            secure.read_snapshot,
            root / relative,
            f"private tracked controller dependency {relative}",
        )
        executing = adapt_error(
            secure.read_snapshot,
            REPOSITORY_ROOT / relative,
            f"executing controller dependency {relative}",
        )
        try:
            committed = subprocess.check_output(
                ["git", "show", f"HEAD:{relative}"], cwd=root
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            fail(f"cannot read committed controller dependency {relative}: {exc}")
        if private.data != committed or executing.data != committed:
            fail(
                f"executing/private controller dependency differs from committed source: {relative}"
            )
        snapshots[relative] = private
    return snapshots


def controller_evidence(
    snapshots: dict[str, secure.FileSnapshot]
) -> dict[str, dict[str, Any]]:
    if set(snapshots) != set(CONTROLLER_RELATIVES):
        fail("controller dependency snapshot set differs")
    return {relative: evidence(snapshots[relative]) for relative in CONTROLLER_RELATIVES}


def validate_controller_evidence(value: Any) -> dict[str, Any]:
    dependencies = exact_keys(
        value, set(CONTROLLER_RELATIVES), "radial controller dependency evidence"
    )
    for relative in CONTROLLER_RELATIVES:
        adapt_error(
            secure.validate_evidence,
            dependencies[relative],
            Path(relative).name,
            f"radial controller dependency {relative}",
        )
    return dependencies


def validate_source_state(value: Any) -> dict[str, Any]:
    state = exact_keys(
        value,
        {
            "jj_source",
            "public_source",
            "private_source",
            "padova_archive",
            "padova_extraction",
        },
        "radial source state",
    )
    jj = adapt_error(secure.validate_source_record, state["jj_source"], "jj_generator")
    public = adapt_error(
        secure.validate_source_record, state["public_source"], "public_release"
    )
    private = adapt_error(
        secure.validate_source_record, state["private_source"], "private_production"
    )
    if jj["repository"] != "askenja/jjmodel" or jj["commit_sha"] != JJ_SHA:
        fail("radial source state does not bind the locked JJ source")
    if public["repository"] == private["repository"]:
        fail("public and private source repositories must be distinct")
    if public["git_tree_sha"] != private["git_tree_sha"]:
        fail("public and private source Git trees differ")
    if state["padova_archive"] != {
        "data_lock_id": secure.PADOVA_LOCK_ID,
        "filename": PADOVA_FILENAME,
        "sha256": PADOVA_SHA256,
        "size_bytes": PADOVA_SIZE_BYTES,
    }:
        fail("radial source state Padova archive differs from the lock")
    adapt_error(secure.validate_padova_extraction_record, state["padova_extraction"])
    return state


def build_source_state(
    *,
    jj_root: Path,
    jj_source_archive: Path,
    padova_archive: secure.FileSnapshot,
    public_source_root: Path,
    public_repository: str,
    public_source_archive: Path,
    private_source_root: Path,
    private_repository: str,
    private_source_archive: Path,
) -> tuple[dict[str, Any], set[str]]:
    padova_paths, padova_extraction = adapt_error(
        secure.exact_padova_extraction, jj_root, padova_archive
    )
    jj = adapt_error(
        secure.source_record,
        "jj_generator",
        "askenja/jjmodel",
        jj_root,
        jj_source_archive,
        allowed_untracked_paths=padova_paths,
    )
    public = adapt_error(
        secure.source_record,
        "public_release",
        public_repository,
        public_source_root,
        public_source_archive,
    )
    private = adapt_error(
        secure.source_record,
        "private_production",
        private_repository,
        private_source_root,
        private_source_archive,
    )
    reject_ignored_untracked(jj_root, padova_paths, "JJ source root")
    reject_ignored_untracked(public_source_root, set(), "public source root")
    reject_ignored_untracked(private_source_root, set(), "private source root")
    state = {
        "jj_source": jj,
        "public_source": public,
        "private_source": private,
        "padova_archive": {
            "data_lock_id": secure.PADOVA_LOCK_ID,
            "filename": PADOVA_FILENAME,
            "sha256": PADOVA_SHA256,
            "size_bytes": PADOVA_SIZE_BYTES,
        },
        "padova_extraction": padova_extraction,
    }
    return validate_source_state(state), padova_paths


def reject_ignored_untracked(
    root_path: Path, allowed_paths: set[str], description: str
) -> None:
    root = adapt_error(secure.require_directory, root_path, description)
    try:
        ignored = subprocess.check_output(
            [
                "git",
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
            cwd=root,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot inspect ignored files in {description}: {exc}")
    observed: set[str] = set()
    for raw in ignored.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeError as exc:
            fail(f"cannot decode ignored path in {description}: {exc}")
        if relative in observed:
            fail(f"duplicate ignored path in {description}")
        observed.add(relative)
    unexpected = observed - allowed_paths
    if unexpected:
        fail(f"{description} contains ignored untracked files outside the locked overlay")


def exact_input_evidence(
    original: secure.FileSnapshot,
    runtime: secure.FileSnapshot,
    sfr: secure.FileSnapshot,
    numerical_runtime: secure.FileSnapshot,
    tams: secure.FileSnapshot,
) -> dict[str, Any]:
    return {
        "parameters_original": evidence(original),
        "parameters_runtime": evidence(runtime),
        "sfr_peaks_parameters": evidence(sfr),
        "numerical_runtime_manifest": evidence(numerical_runtime),
        "tams_reference": evidence(tams),
    }


def validate_input_evidence(
    value: Any, snapshots: dict[str, secure.FileSnapshot]
) -> dict[str, Any]:
    inputs = exact_keys(
        value,
        {
            "parameters_original",
            "parameters_runtime",
            "sfr_peaks_parameters",
            "numerical_runtime_manifest",
            "tams_reference",
        },
        "radial run input evidence",
    )
    expected_names = {
        "parameters_original": "parameters.original",
        "parameters_runtime": "parameters.runtime",
        "sfr_peaks_parameters": "sfrd_peaks_parameters",
        "numerical_runtime_manifest": secure.RUNTIME_NAME,
        "tams_reference": "tams_parsec_danxhuber.txt",
    }
    for key, name in expected_names.items():
        item = adapt_error(secure.validate_evidence, inputs[key], name, f"{key} evidence")
        snapshot = snapshots[key]
        if item != evidence(snapshot):
            fail(f"{key} evidence does not bind current private package bytes")
    return inputs


def result_summary(derived: dict[str, Any]) -> dict[str, Any]:
    return {
        "dR_kpc": derived["dR_kpc"],
        "radial_nodes": derived["radial_nodes"],
        "ssp_file_count": derived["ssp_file_count"],
        "ssp_member_sha256": derived["ssp_member_sha256"],
        "selected_stellar_assembly_rows": derived[
            "selected_stellar_assembly_rows"
        ],
        "compact_remnant_rows_rejected": derived[
            "compact_remnant_rows_rejected"
        ],
        "compact_remnant_surface_weight_rejected_sum_pc-2": derived[
            "compact_remnant_surface_weight_rejected_sum_pc-2"
        ],
        "C1": derived["C1"],
        "domains": derived["domains"],
        "radial_rows_sha256": hashlib.sha256(
            canonical_bytes(derived["radial_rows"])
        ).hexdigest(),
    }


def validate_generated_result(
    value: Any, derived: dict[str, Any]
) -> dict[str, Any]:
    result = exact_keys(
        value,
        {
            "experiment",
            "jj_commit",
            "isochrone_family",
            "dR_kpc",
            "radial_nodes",
            "host_selector",
            "occurrence_branch",
            "selected_stellar_assembly_rows",
            "compact_remnant_rows_rejected",
            "compact_remnant_surface_weight_rejected_sum_pc-2",
            "C1",
            "domains",
        },
        "generated radial result",
    )
    if (
        result["experiment"] != "final_TAMS_radial_convergence"
        or result["jj_commit"] != JJ_SHA
        or result["isochrone_family"] != "Padova"
        or result["host_selector"] != EXPECTED_SELECTOR
        or result["occurrence_branch"] != EXPECTED_OCCURRENCE
    ):
        fail("generated radial result metadata changed")
    close_number(result["dR_kpc"], derived["dR_kpc"], "generated dR_kpc")
    if type(result["radial_nodes"]) is not int or result["radial_nodes"] != derived["radial_nodes"]:
        fail("generated radial node count differs from raw SSP")
    for key in (
        "selected_stellar_assembly_rows",
        "compact_remnant_rows_rejected",
    ):
        if type(result[key]) is not int or result[key] != derived[key]:
            fail(f"generated {key} differs from raw SSP")
    close_number(
        result["compact_remnant_surface_weight_rejected_sum_pc-2"],
        derived["compact_remnant_surface_weight_rejected_sum_pc-2"],
        "generated compact-remnant rejected weight",
    )
    close_number(result["C1"], derived["C1"], "generated occurrence normalization")
    domains = exact_keys(
        result["domains"], set(rederive.DOMAINS), "generated radial domains"
    )
    domain_keys = {
        "R_kpc",
        "N_G",
        "Lambda_ESHZ",
        "Lambda_earth10",
        "mean_f_HZ",
        "mean_f_earth10",
        "L2_over_L1",
    }
    for name, expected in derived["domains"].items():
        domain = exact_keys(domains[name], domain_keys, f"generated domain {name}")
        if not isinstance(domain["R_kpc"], list) or len(domain["R_kpc"]) != 2:
            fail(f"generated domain {name} has invalid endpoints")
        for index, expected_endpoint in enumerate(expected["R_kpc"]):
            close_number(
                domain["R_kpc"][index], expected_endpoint, f"generated {name} endpoint"
            )
        for key in domain_keys - {"R_kpc"}:
            close_number(domain[key], expected[key], f"generated {name} {key}")
    return result


def canonical_uuid(value: Any, description: str) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        fail(f"invalid {description}: {exc}")
    if parsed != value:
        fail(f"{description} must use canonical lowercase UUID form")
    return parsed


def nonce(value: Any, description: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(f"{description} must be exactly 32 lowercase-hex bytes")
    return value


def validate_hash_evidence(value: Any, description: str) -> dict[str, Any]:
    item = exact_keys(value, {"sha256", "size_bytes"}, description)
    require_sha(item["sha256"], 64, f"{description} SHA-256")
    if type(item["size_bytes"]) is not int or item["size_bytes"] < 0:
        fail(f"{description} size must be a nonnegative JSON integer")
    return item


def validate_private_provenance(
    document: Any,
    *,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    dr: float,
    snapshots: dict[str, secure.FileSnapshot],
) -> dict[str, Any]:
    provenance = exact_keys(
        document,
        {
            "schema_version",
            "contract_id",
            "candidate_set_id",
            "triplet_label",
            "signer_id",
            "dR_kpc",
            "execution_id",
            "nonce_hex",
            "execution_environment",
            "challenge_issued_utc",
            "run_started_utc",
            "run_completed_utc",
            "source_state",
            "generation_program",
            "controller_programs",
            "inputs",
            "start_challenge",
            "start_challenge_signature",
            "execution_record",
            "ssp_manifest",
            "generated_radial",
            "generated_result",
        },
        "radial private provenance",
    )
    if type(provenance["schema_version"]) is not int or provenance["schema_version"] != 1:
        fail("radial private provenance schema_version must be integer 1")
    if provenance["contract_id"] != contract["contract_id"]:
        fail("radial private provenance contract id mismatch")
    if provenance["candidate_set_id"] != candidate["id"]:
        fail("radial private provenance candidate id mismatch")
    require_safe_id(provenance["triplet_label"], "radial triplet label")
    signer = candidate_signer(candidate, provenance["signer_id"])
    canonical_uuid(provenance["execution_id"], "radial execution id")
    nonce(provenance["nonce_hex"], "radial execution nonce")
    if provenance["execution_environment"] not in secure.ALLOWED_ENVIRONMENTS:
        fail("radial execution environment is not allowed")
    close_number(provenance["dR_kpc"], dr, "private provenance dR")
    issued = parse_utc(provenance["challenge_issued_utc"], "challenge_issued_utc")
    started = parse_utc(provenance["run_started_utc"], "run_started_utc")
    completed = parse_utc(provenance["run_completed_utc"], "run_completed_utc")
    if not (issued <= started < completed):
        fail("radial execution timestamps are not strictly ordered")
    validate_source_state(provenance["source_state"])
    adapt_error(
        secure.validate_evidence,
        provenance["generation_program"],
        Path(GENERATOR_RELATIVE).name,
        "radial generation program evidence",
    )
    validate_controller_evidence(provenance["controller_programs"])
    validate_input_evidence(provenance["inputs"], snapshots)
    for key, filename in (
        ("start_challenge", secure.START_CHALLENGE_NAME),
        ("start_challenge_signature", secure.START_CHALLENGE_SIGNATURE_NAME),
        ("execution_record", secure.EXECUTION_RECORD_NAME),
        ("ssp_manifest", "SSP_SHA256SUMS.txt"),
        ("generated_radial", "tams_radial.csv"),
        ("generated_result", "tams_result.json"),
    ):
        item = adapt_error(
            secure.validate_evidence, provenance[key], filename, f"{key} evidence"
        )
        if item != evidence(snapshots[key]):
            fail(f"private provenance {key} does not bind current bytes")
    if signer["signer_id"] != provenance["signer_id"]:
        fail("private provenance signer mismatch")
    return provenance


def validate_start_challenge(
    document: Any,
    *,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    snapshots: dict[str, secure.FileSnapshot],
) -> dict[str, Any]:
    challenge = exact_keys(
        document,
        {
            "challenge_id",
            "schema_version",
            "contract_id",
            "candidate_set_id",
            "signer_id",
            "triplet_label",
            "dR_kpc",
            "execution_id",
            "nonce_hex",
            "issued_utc",
            "generation_program",
            "controller_programs",
            "source_state_sha256",
            "inputs",
        },
        "radial start challenge",
    )
    validate_document_id(challenge, "challenge_id", "radial start challenge")
    expected = {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_set_id": candidate["id"],
        "signer_id": provenance["signer_id"],
        "triplet_label": provenance["triplet_label"],
        "dR_kpc": provenance["dR_kpc"],
        "execution_id": provenance["execution_id"],
        "nonce_hex": provenance["nonce_hex"],
        "issued_utc": provenance["challenge_issued_utc"],
        "generation_program": provenance["generation_program"],
        "controller_programs": provenance["controller_programs"],
        "source_state_sha256": hashlib.sha256(
            canonical_bytes(provenance["source_state"])
        ).hexdigest(),
        "inputs": provenance["inputs"],
    }
    body = dict(challenge)
    body.pop("challenge_id")
    if body != expected:
        fail("radial start challenge does not bind current pre-run inputs")
    validate_input_evidence(challenge["inputs"], snapshots)
    return challenge


def validate_execution_record(
    document: Any,
    *,
    provenance: dict[str, Any],
    challenge: dict[str, Any],
    dr: float,
    ssp_hashes: dict[str, str],
    radial: secure.FileSnapshot,
    result: secure.FileSnapshot,
) -> dict[str, Any]:
    record = exact_keys(
        document,
        {
            "execution_record_id",
            "schema_version",
            "controller",
            "challenge_id",
            "execution_id",
            "nonce_hex",
            "dR_kpc",
            "argv",
            "cwd",
            "shell",
            "run_directory_created_empty",
            "generator_output_directory_created_empty",
            "run_started_utc",
            "run_completed_utc",
            "return_code",
            "stdout",
            "stderr",
            "ssp_member_sha256",
            "generated_radial",
            "generated_result",
        },
        "radial execution record",
    )
    validate_document_id(record, "execution_record_id", "radial execution record")
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or record["controller"] != "verify_radial_ssp_contract.execute_fresh_triplet"
        or record["challenge_id"] != challenge["challenge_id"]
        or record["execution_id"] != provenance["execution_id"]
        or record["nonce_hex"] != provenance["nonce_hex"]
        or record["shell"] is not False
        or record["run_directory_created_empty"] is not True
        or record["generator_output_directory_created_empty"] is not True
        or type(record["return_code"]) is not int
        or record["return_code"] != 0
    ):
        fail("radial execution record policy fields changed")
    close_number(record["dR_kpc"], dr, "execution-record dR")
    if (
        not isinstance(record["argv"], list)
        or len(record["argv"]) != 10
        or not all(isinstance(item, str) and item for item in record["argv"])
        or record["argv"][1].replace("\\", "/").split("/")[-3:]
        != GENERATOR_RELATIVE.split("/")[-3:]
        or record["argv"][2::2] != ["--jj-root", "--run-dir", "--out", "--iso"]
        or record["argv"][-1] != "Padova"
    ):
        fail("radial execution record argv is not the exact no-shell generator form")
    if not isinstance(record["cwd"], str) or not record["cwd"]:
        fail("radial execution cwd is invalid")
    if (
        record["run_started_utc"] != provenance["run_started_utc"]
        or record["run_completed_utc"] != provenance["run_completed_utc"]
    ):
        fail("radial execution record timestamps differ from provenance")
    validate_hash_evidence(record["stdout"], "radial stdout evidence")
    validate_hash_evidence(record["stderr"], "radial stderr evidence")
    if record["ssp_member_sha256"] != ssp_hashes:
        fail("radial execution record SSP tuple differs from current private bytes")
    if record["generated_radial"] != evidence(radial) or record["generated_result"] != evidence(result):
        fail("radial execution record generated-output evidence differs")
    return record


def completion_body(
    *,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    challenge: secure.FileSnapshot,
    challenge_signature: secure.FileSnapshot,
    execution_record: secure.FileSnapshot,
    private_provenance: secure.FileSnapshot,
    ssp_manifest: secure.FileSnapshot,
    radial: secure.FileSnapshot,
    result: secure.FileSnapshot,
    derived_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_set_id": candidate["id"],
        "signer_id": provenance["signer_id"],
        "triplet_label": provenance["triplet_label"],
        "dR_kpc": provenance["dR_kpc"],
        "execution_id": provenance["execution_id"],
        "nonce_hex": provenance["nonce_hex"],
        "source_state_sha256": hashlib.sha256(
            canonical_bytes(provenance["source_state"])
        ).hexdigest(),
        "inputs": provenance["inputs"],
        "controller_programs": provenance["controller_programs"],
        "start_challenge": evidence(challenge),
        "start_challenge_signature": evidence(challenge_signature),
        "execution_record": evidence(execution_record),
        "private_provenance": evidence(private_provenance),
        "ssp_manifest": evidence(ssp_manifest),
        "ssp_tuple_sha256": hashlib.sha256(
            canonical_bytes(derived_summary["ssp_member_sha256"])
        ).hexdigest(),
        "generated_radial": evidence(radial),
        "generated_result": evidence(result),
        "rederived_summary": derived_summary,
    }


def inspect_private_run(
    run_root_path: Path,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    dr: float,
) -> dict[str, Any]:
    root = adapt_error(secure.require_directory, run_root_path, f"private radial dR={dr} root")
    entries = {path.name for path in root.iterdir()}
    if entries != PRIVATE_RUN_FILES:
        fail(
            f"private radial dR={dr} root file set differs: "
            f"missing={sorted(PRIVATE_RUN_FILES - entries)!r}, "
            f"extra={sorted(entries - PRIVATE_RUN_FILES)!r}"
        )
    ssp_root = adapt_error(secure.require_directory, root / "ssp", "private radial SSP directory")
    expected_names = rederive.expected_ssp_names(dr)
    if {path.name for path in ssp_root.iterdir()} != set(expected_names):
        fail("private radial SSP directory member set differs")
    ssp = {
        name: adapt_error(secure.read_snapshot, ssp_root / name, f"private radial SSP {name}")
        for name in expected_names
    }
    snapshots = {
        "parameters_original": adapt_error(secure.read_snapshot, root / "parameters.original", "original tutorial2 parameters"),
        "parameters_runtime": adapt_error(secure.read_snapshot, root / "parameters.runtime", "runtime tutorial2 parameters"),
        "sfr_peaks_parameters": adapt_error(secure.read_snapshot, root / "sfrd_peaks_parameters", "tutorial2 SFR peaks"),
        "numerical_runtime_manifest": adapt_error(secure.read_snapshot, root / secure.RUNTIME_NAME, "numerical runtime manifest", maximum_bytes=secure.MAX_RUNTIME_BYTES),
        "tams_reference": adapt_error(secure.read_snapshot, rederive.independent_reference.TAMS_PATH, "canonical TAMS reference", maximum_bytes=100_000),
        "start_challenge": adapt_error(secure.read_snapshot, root / secure.START_CHALLENGE_NAME, "radial start challenge", maximum_bytes=MAX_JSON_BYTES),
        "start_challenge_signature": adapt_error(secure.read_snapshot, root / secure.START_CHALLENGE_SIGNATURE_NAME, "radial start challenge signature"),
        "execution_record": adapt_error(secure.read_snapshot, root / secure.EXECUTION_RECORD_NAME, "radial execution record", maximum_bytes=MAX_JSON_BYTES),
        "private_provenance": adapt_error(secure.read_snapshot, root / "RUN_PRIVATE_PROVENANCE.json", "radial private provenance", maximum_bytes=MAX_JSON_BYTES),
        "ssp_manifest": adapt_error(secure.read_snapshot, root / "SSP_SHA256SUMS.txt", "radial SSP manifest", maximum_bytes=secure.MAX_MANIFEST_BYTES),
        "generated_radial": adapt_error(secure.read_snapshot, root / "tams_radial.csv", "generated radial CSV"),
        "generated_result": adapt_error(secure.read_snapshot, root / "tams_result.json", "generated radial result", maximum_bytes=MAX_JSON_BYTES),
        "completion": adapt_error(secure.read_snapshot, root / "RUN_COMPLETION_ATTESTATION.json", "radial completion attestation", maximum_bytes=MAX_JSON_BYTES),
        "completion_signature": adapt_error(secure.read_snapshot, root / "RUN_COMPLETION_ATTESTATION.sig", "radial completion signature"),
    }
    if snapshots["parameters_original"].sha256 != TUTORIAL_PARAMETERS_SHA256:
        fail("private original tutorial2 parameters differ from the lock")
    if snapshots["sfr_peaks_parameters"].sha256 != TUTORIAL_SFR_SHA256:
        fail("private tutorial2 SFR peaks differ from the lock")
    if snapshots["tams_reference"].sha256 != TAMS_REFERENCE_SHA256:
        fail("canonical TAMS reference differs from the radial contract")
    if snapshots["parameters_runtime"].data != expected_runtime_parameters(
        snapshots["parameters_original"].data, dr
    ):
        fail("runtime parameters differ outside the exact dR/R/process substitutions")
    adapt_error(
        secure.validate_runtime_manifest,
        adapt_error(
            secure.load_json_bytes,
            snapshots["numerical_runtime_manifest"].data,
            "numerical runtime manifest",
        ),
    )
    manifest = adapt_error(
        secure.parse_manifest,
        snapshots["ssp_manifest"].data,
        expected_names,
        "radial SSP manifest",
    )
    actual_hashes = {name: ssp[name].sha256 for name in expected_names}
    if manifest != actual_hashes:
        fail("radial SSP manifest differs from current private SSP bytes")
    derived = adapt_error(rederive.rederive_private_run, ssp_root, dr)
    observed_rows = adapt_error(rederive.parse_generated_radial, root / "tams_radial.csv", dr)
    adapt_error(rederive.compare_radial_rows, observed_rows, derived["radial_rows"])
    result_document = adapt_error(
        secure.load_json_bytes, snapshots["generated_result"].data, "generated radial result"
    )
    validate_generated_result(result_document, derived)
    provenance_document = adapt_error(
        secure.load_json_bytes, snapshots["private_provenance"].data, "radial private provenance"
    )
    provenance = validate_private_provenance(
        provenance_document,
        contract=contract,
        candidate=candidate,
        dr=dr,
        snapshots=snapshots,
    )
    challenge_document = adapt_error(
        secure.load_json_bytes, snapshots["start_challenge"].data, "radial start challenge"
    )
    challenge = validate_start_challenge(
        challenge_document,
        contract=contract,
        candidate=candidate,
        provenance=provenance,
        snapshots=snapshots,
    )
    signer = candidate_signer(candidate, provenance["signer_id"])
    verify_signature_bytes(
        snapshots["start_challenge"].data,
        snapshots["start_challenge_signature"].data,
        signer,
        START_NAMESPACE,
    )
    execution_document = adapt_error(
        secure.load_json_bytes, snapshots["execution_record"].data, "radial execution record"
    )
    validate_execution_record(
        execution_document,
        provenance=provenance,
        challenge=challenge,
        dr=dr,
        ssp_hashes=actual_hashes,
        radial=snapshots["generated_radial"],
        result=snapshots["generated_result"],
    )
    summary = result_summary(derived)
    completion_document = adapt_error(
        secure.load_json_bytes, snapshots["completion"].data, "radial completion attestation"
    )
    exact_keys(
        completion_document,
        {"completion_id", *completion_body(
            contract=contract,
            candidate=candidate,
            provenance=provenance,
            challenge=snapshots["start_challenge"],
            challenge_signature=snapshots["start_challenge_signature"],
            execution_record=snapshots["execution_record"],
            private_provenance=snapshots["private_provenance"],
            ssp_manifest=snapshots["ssp_manifest"],
            radial=snapshots["generated_radial"],
            result=snapshots["generated_result"],
            derived_summary=summary,
        )},
        "radial completion attestation",
    )
    validate_document_id(completion_document, "completion_id", "radial completion attestation")
    expected_completion = completion_body(
        contract=contract,
        candidate=candidate,
        provenance=provenance,
        challenge=snapshots["start_challenge"],
        challenge_signature=snapshots["start_challenge_signature"],
        execution_record=snapshots["execution_record"],
        private_provenance=snapshots["private_provenance"],
        ssp_manifest=snapshots["ssp_manifest"],
        radial=snapshots["generated_radial"],
        result=snapshots["generated_result"],
        derived_summary=summary,
    )
    observed_body = dict(completion_document)
    observed_body.pop("completion_id")
    if observed_body != expected_completion:
        fail("radial completion attestation does not bind current private rederivation")
    verify_signature_bytes(
        snapshots["completion"].data,
        snapshots["completion_signature"].data,
        signer,
        COMPLETION_NAMESPACE,
    )
    return {
        "dR_kpc": dr,
        "triplet_label": provenance["triplet_label"],
        "signer_id": provenance["signer_id"],
        "execution_id": provenance["execution_id"],
        "nonce_hex": provenance["nonce_hex"],
        "execution_environment": provenance["execution_environment"],
        "source_state": provenance["source_state"],
        "inputs": provenance["inputs"],
        "summary": summary,
        "generated_radial": evidence(snapshots["generated_radial"]),
        "generated_result": evidence(snapshots["generated_result"]),
        "completion": evidence(snapshots["completion"]),
        "completion_signature": evidence(snapshots["completion_signature"]),
        "completion_bytes": snapshots["completion"].data,
        "completion_signature_bytes": snapshots["completion_signature"].data,
    }


def scientific_evidence(runs: dict[float, dict[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "radial_spacings_kpc": list(DRS),
        "runs": {},
        "comparisons": {},
        "pass_threshold_abs_fraction": 0.01,
    }
    for dr in DRS:
        run = runs[dr]
        value["runs"][str(dr)] = {
            "dR_kpc": dr,
            "inputs": run["inputs"],
            "summary": run["summary"],
            "generated_radial": run["generated_radial"],
            "generated_result": run["generated_result"],
        }
    quantities = ("N_G", "Lambda_ESHZ", "Lambda_earth10")
    for domain in rederive.DOMAINS:
        value["comparisons"][domain] = {}
        for coarse, fine in ((1.0, 0.5), (0.5, 0.25)):
            comparison: dict[str, Any] = {}
            for quantity in quantities:
                x0 = runs[coarse]["summary"]["domains"][domain][quantity]
                x1 = runs[fine]["summary"]["domains"][domain][quantity]
                if not math.isfinite(x0) or not math.isfinite(x1) or x1 == 0.0:
                    fail("cannot construct finite radial convergence comparison")
                delta = (x1 - x0) / x1
                comparison[quantity] = {
                    "coarse": x0,
                    "fine": x1,
                    "delta_fraction": delta,
                    "delta_percent": 100.0 * delta,
                }
            value["comparisons"][domain][f"{coarse}_to_{fine}"] = comparison
    final = value["comparisons"]["lineweaver_7_9"]["0.5_to_0.25"]
    if any(abs(final[name]["delta_fraction"]) >= 0.01 for name in quantities):
        fail("private raw-SSP rederivation does not satisfy the final <1% radial gate")
    return value


def validate_public_inputs(value: Any, dr: float) -> dict[str, Any]:
    inputs = exact_keys(
        value,
        {
            "parameters_original",
            "parameters_runtime",
            "sfr_peaks_parameters",
            "numerical_runtime_manifest",
            "tams_reference",
        },
        "public radial input hashes",
    )
    expected_names = {
        "parameters_original": "parameters.original",
        "parameters_runtime": "parameters.runtime",
        "sfr_peaks_parameters": "sfrd_peaks_parameters",
        "numerical_runtime_manifest": secure.RUNTIME_NAME,
        "tams_reference": "tams_parsec_danxhuber.txt",
    }
    for key, name in expected_names.items():
        adapt_error(secure.validate_evidence, inputs[key], name, f"public {key}")
    locked_hashes = {
        "parameters_original": TUTORIAL_PARAMETERS_SHA256,
        "sfr_peaks_parameters": TUTORIAL_SFR_SHA256,
        "tams_reference": TAMS_REFERENCE_SHA256,
    }
    for key, digest in locked_hashes.items():
        if inputs[key]["sha256"] != digest:
            fail(f"public {key} hash differs from the radial contract")
    if type(dr) is not float or dr not in DRS:
        fail("public radial input evidence has unsupported dR")
    return inputs


def validate_public_summary(value: Any, dr: float) -> dict[str, Any]:
    summary = exact_keys(
        value,
        {
            "dR_kpc",
            "radial_nodes",
            "ssp_file_count",
            "ssp_member_sha256",
            "selected_stellar_assembly_rows",
            "compact_remnant_rows_rejected",
            "compact_remnant_surface_weight_rejected_sum_pc-2",
            "C1",
            "domains",
            "radial_rows_sha256",
        },
        "public radial rederived summary",
    )
    close_number(summary["dR_kpc"], dr, "public summary dR")
    expected_nodes = len(rederive.radii_for_dr(dr))
    expected_files = len(rederive.expected_ssp_names(dr))
    if type(summary["radial_nodes"]) is not int or summary["radial_nodes"] != expected_nodes:
        fail("public summary radial node count changed")
    if type(summary["ssp_file_count"]) is not int or summary["ssp_file_count"] != expected_files:
        fail("public summary SSP file count changed")
    hashes = summary["ssp_member_sha256"]
    if not isinstance(hashes, dict) or set(hashes) != set(rederive.expected_ssp_names(dr)):
        fail("public summary SSP hash tuple member set changed")
    for name, digest in hashes.items():
        require_sha(digest, 64, f"public summary SSP hash {name}")
    require_nonnegative_int(
        summary["selected_stellar_assembly_rows"], "public selected-row count"
    )
    require_nonnegative_int(
        summary["compact_remnant_rows_rejected"], "public compact-row count"
    )
    compact_weight = finite_number(
        summary["compact_remnant_surface_weight_rejected_sum_pc-2"],
        "public compact-remnant rejected weight",
    )
    c1 = finite_number(summary["C1"], "public occurrence normalization")
    if compact_weight < 0.0 or c1 <= 0.0:
        fail("public summary contains invalid nonnegative/positive values")
    close_number(c1, rederive.occurrence_normalization(), "public occurrence normalization")
    require_sha(summary["radial_rows_sha256"], 64, "public radial-row digest")
    domains = exact_keys(summary["domains"], set(rederive.DOMAINS), "public radial domains")
    keys = {
        "R_kpc",
        "N_G",
        "Lambda_ESHZ",
        "Lambda_earth10",
        "mean_f_HZ",
        "mean_f_earth10",
        "L2_over_L1",
    }
    for name, endpoints in rederive.DOMAINS.items():
        domain = exact_keys(domains[name], keys, f"public domain {name}")
        if domain["R_kpc"] != list(endpoints):
            fail(f"public domain {name} endpoints changed")
        numeric = {
            key: finite_number(domain[key], f"public {name} {key}")
            for key in keys - {"R_kpc"}
        }
        if not (
            numeric["N_G"] > 0.0
            and 0.0 <= numeric["Lambda_earth10"] <= numeric["Lambda_ESHZ"]
        ):
            fail(f"public domain {name} population ordering is invalid")
        close_number(
            numeric["mean_f_HZ"],
            numeric["Lambda_ESHZ"] / numeric["N_G"],
            f"public {name} mean_f_HZ identity",
        )
        close_number(
            numeric["mean_f_earth10"],
            numeric["Lambda_earth10"] / numeric["N_G"],
            f"public {name} mean_f_earth10 identity",
        )
        close_number(
            numeric["L2_over_L1"],
            numeric["Lambda_earth10"] / numeric["Lambda_ESHZ"],
            f"public {name} L2/L1 identity",
        )
    return summary


def triplet_body(
    *,
    contract: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
    run_snapshots: dict[float, tuple[secure.FileSnapshot, secure.FileSnapshot]],
    scientific: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract_id": contract["contract_id"],
        "candidate_set_id": candidate["id"],
        "triplet_label": provenance["triplet_label"],
        "signer_id": provenance["signer_id"],
        "triplet_execution_id": provenance["triplet_execution_id"],
        "triplet_nonce_hex": provenance["triplet_nonce_hex"],
        "created_utc": provenance["created_utc"],
        "source_state_sha256": provenance["source_state_sha256"],
        "run_attestations": {
            str(dr): {
                "completion": evidence(run_snapshots[dr][0]),
                "completion_signature": evidence(run_snapshots[dr][1]),
                "execution_id": provenance["runs"][str(dr)]["execution_id"],
                "nonce_hex": provenance["runs"][str(dr)]["nonce_hex"],
            }
            for dr in DRS
        },
        "scientific_evidence_sha256": hashlib.sha256(
            canonical_bytes(scientific)
        ).hexdigest(),
    }


def inspect_private_triplet(
    contract_path: Path,
    private_root_path: Path,
    candidate_set_id: str | None = None,
) -> dict[str, Any]:
    contract, contract_snapshot = load_contract(contract_path)
    root = adapt_error(secure.require_directory, private_root_path, "private radial triplet root")
    entries = {path.name for path in root.iterdir()}
    expected_entries = {*PRIVATE_TRIPLET_FILES, *RUN_DIR_NAMES.values()}
    if entries != expected_entries:
        fail("private radial triplet root does not contain the exact member set")
    provenance_document, provenance_snapshot = strict_json_snapshot(
        root / "TRIPLET_PRIVATE_PROVENANCE.json", "radial triplet private provenance"
    )
    provenance = exact_keys(
        provenance_document,
        {
            "schema_version",
            "contract_id",
            "candidate_set_id",
            "triplet_label",
            "signer_id",
            "triplet_execution_id",
            "triplet_nonce_hex",
            "created_utc",
            "source_state_sha256",
            "runs",
        },
        "radial triplet private provenance",
    )
    if type(provenance["schema_version"]) is not int or provenance["schema_version"] != 1:
        fail("radial triplet provenance schema_version must be integer 1")
    if provenance["contract_id"] != contract["contract_id"]:
        fail("radial triplet provenance contract id mismatch")
    identifier = require_safe_id(provenance["candidate_set_id"], "radial candidate id")
    if candidate_set_id is not None and identifier != candidate_set_id:
        fail("private radial triplet candidate id differs from requested candidate")
    candidate = artifact_set(contract, identifier)
    require_safe_id(provenance["triplet_label"], "radial triplet label")
    signer = candidate_signer(candidate, provenance["signer_id"])
    canonical_uuid(provenance["triplet_execution_id"], "triplet execution id")
    nonce(provenance["triplet_nonce_hex"], "triplet nonce")
    parse_utc(provenance["created_utc"], "triplet created_utc")
    require_sha(provenance["source_state_sha256"], 64, "triplet source-state hash")
    runs_document = exact_keys(
        provenance["runs"], {str(dr) for dr in DRS}, "triplet run identities"
    )
    runs: dict[float, dict[str, Any]] = {}
    run_snapshots: dict[float, tuple[secure.FileSnapshot, secure.FileSnapshot]] = {}
    execution_ids: set[str] = set()
    nonces: set[str] = set()
    for dr in DRS:
        run = inspect_private_run(root / RUN_DIR_NAMES[dr], contract, candidate, dr)
        runs[dr] = run
        identity = exact_keys(
            runs_document[str(dr)],
            {"execution_id", "nonce_hex", "completion", "completion_signature"},
            f"triplet dR={dr} run identity",
        )
        if (
            identity["execution_id"] != run["execution_id"]
            or identity["nonce_hex"] != run["nonce_hex"]
            or identity["completion"] != run["completion"]
            or identity["completion_signature"] != run["completion_signature"]
        ):
            fail("triplet run identity does not bind current private run")
        if (
            run["triplet_label"] != provenance["triplet_label"]
            or run["signer_id"] != provenance["signer_id"]
            or hashlib.sha256(canonical_bytes(run["source_state"])).hexdigest()
            != provenance["source_state_sha256"]
        ):
            fail("triplet runs do not share label, signer, and exact source state")
        execution_ids.add(run["execution_id"])
        nonces.add(run["nonce_hex"])
        run_snapshots[dr] = (
            adapt_error(secure.read_snapshot, root / RUN_DIR_NAMES[dr] / "RUN_COMPLETION_ATTESTATION.json", "triplet completion attestation"),
            adapt_error(secure.read_snapshot, root / RUN_DIR_NAMES[dr] / "RUN_COMPLETION_ATTESTATION.sig", "triplet completion signature"),
        )
    if len(execution_ids) != 3 or len(nonces) != 3:
        fail("one radial triplet must contain three distinct executions and nonces")
    scientific = scientific_evidence(runs)
    triplet_document, triplet_snapshot = strict_json_snapshot(
        root / "TRIPLET_ATTESTATION.json", "radial triplet attestation"
    )
    expected_body = triplet_body(
        contract=contract,
        candidate=candidate,
        provenance=provenance,
        run_snapshots=run_snapshots,
        scientific=scientific,
    )
    exact_keys(
        triplet_document,
        {"triplet_attestation_id", *expected_body},
        "radial triplet attestation",
    )
    validate_document_id(
        triplet_document, "triplet_attestation_id", "radial triplet attestation"
    )
    actual_body = dict(triplet_document)
    actual_body.pop("triplet_attestation_id")
    if actual_body != expected_body:
        fail("radial triplet attestation does not bind current private runs")
    triplet_signature = adapt_error(
        secure.read_snapshot, root / "TRIPLET_ATTESTATION.sig", "radial triplet signature"
    )
    verify_signature_bytes(
        triplet_snapshot.data,
        triplet_signature.data,
        signer,
        TRIPLET_NAMESPACE,
    )
    public_runs: dict[str, Any] = {}
    for dr in DRS:
        run = runs[dr]
        public_runs[str(dr)] = {
            "execution_id": run["execution_id"],
            "nonce_hex": run["nonce_hex"],
            "completion_attestation_base64": base64.b64encode(
                run["completion_bytes"]
            ).decode("ascii"),
            "completion_signature_base64": base64.b64encode(
                run["completion_signature_bytes"]
            ).decode("ascii"),
        }
    public = {
        "triplet_label": provenance["triplet_label"],
        "signer_id": provenance["signer_id"],
        "triplet_execution_id": provenance["triplet_execution_id"],
        "triplet_nonce_hex": provenance["triplet_nonce_hex"],
        "source_state_sha256": provenance["source_state_sha256"],
        "source_provenance": runs[DRS[0]]["source_state"],
        "runs": public_runs,
        "triplet_attestation_base64": base64.b64encode(triplet_snapshot.data).decode("ascii"),
        "triplet_signature_base64": base64.b64encode(triplet_signature.data).decode("ascii"),
    }
    return {
        "contract_sha256": contract_snapshot.sha256,
        "candidate_set_id": candidate["id"],
        "triplet_label": provenance["triplet_label"],
        "signer_id": provenance["signer_id"],
        "triplet_execution_id": provenance["triplet_execution_id"],
        "triplet_nonce_hex": provenance["triplet_nonce_hex"],
        "source_state_sha256": provenance["source_state_sha256"],
        "execution_ids": sorted(execution_ids),
        "nonces": sorted(nonces),
        "scientific_evidence": scientific,
        "public_attestation_evidence": public,
        "private_provenance": evidence(provenance_snapshot),
    }


def assert_no_raw_public_payload(value: Any) -> None:
    def visit(item: Any, key: str = "") -> None:
        if key in {"radial_rows", "ssp_bytes", "raw_ssp", "row_level_data"}:
            fail("public radial qualification contains forbidden row-level data")
        if isinstance(item, dict):
            for child_key, child in item.items():
                visit(child, child_key)
        elif isinstance(item, list):
            for child in item:
                visit(child, key)
    visit(value)


def qualification_body(
    contract: dict[str, Any],
    candidate: dict[str, Any],
    first: dict[str, Any],
    second: dict[str, Any],
) -> dict[str, Any]:
    scientific = first["scientific_evidence"]
    return {
        "schema_version": 1,
        "status": "PASS",
        "contract_id": contract["contract_id"],
        "candidate_set_id": candidate["id"],
        "created_utc": utc_now(),
        "qualified_public_evidence_sha256": hashlib.sha256(
            canonical_bytes(scientific)
        ).hexdigest(),
        "scientific_evidence": scientific,
        "triplets": [
            first["public_attestation_evidence"],
            second["public_attestation_evidence"],
        ],
    }


def qualify_triplets(
    contract_path: Path,
    first_root: Path,
    second_root: Path,
    candidate_set_id: str,
    report_out: Path,
) -> dict[str, Any]:
    contract, _ = load_contract(contract_path)
    candidate = artifact_set(
        contract, require_safe_id(candidate_set_id, "radial candidate id")
    )
    if candidate["qualification_eligible"] is not True:
        fail("radial candidate is not qualification eligible")
    first_path = adapt_error(secure.require_directory, first_root, "first private radial triplet")
    second_path = adapt_error(secure.require_directory, second_root, "second private radial triplet")
    if first_path == second_path:
        fail("radial qualification requires two distinct private triplet roots")
    first = inspect_private_triplet(contract_path, first_path, candidate["id"])
    second = inspect_private_triplet(contract_path, second_path, candidate["id"])
    if first["triplet_label"] == second["triplet_label"]:
        fail("radial qualification triplet labels must be distinct")
    if first["signer_id"] == second["signer_id"]:
        fail("radial qualification signers must be distinct")
    if first["triplet_execution_id"] == second["triplet_execution_id"]:
        fail("radial qualification triplet execution ids must be distinct")
    if first["triplet_nonce_hex"] == second["triplet_nonce_hex"]:
        fail("radial qualification triplet nonces must be distinct")
    if set(first["execution_ids"]) & set(second["execution_ids"]):
        fail("radial qualification reuses a run execution id")
    if set(first["nonces"]) & set(second["nonces"]):
        fail("radial qualification reuses a run nonce")
    if first["source_state_sha256"] != second["source_state_sha256"]:
        fail("radial qualification source states differ")
    if first["scientific_evidence"] != second["scientific_evidence"]:
        fail("two fresh radial triplets are not bit-identical in scientific evidence")
    body = qualification_body(contract, candidate, first, second)
    report = document_with_id(body, "qualification_id")
    assert_no_raw_public_payload(report)
    destination = Path(report_out)
    if destination.exists() or destination.is_symlink():
        fail("radial qualification report output must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        fail("radial qualification report parent must be a non-symlink directory")
    write_json_exclusive(destination, report)
    return report


def validate_public_report(
    contract: dict[str, Any], candidate: dict[str, Any], document: Any
) -> dict[str, Any]:
    report = exact_keys(
        document,
        {
            "qualification_id",
            "schema_version",
            "status",
            "contract_id",
            "candidate_set_id",
            "created_utc",
            "qualified_public_evidence_sha256",
            "scientific_evidence",
            "triplets",
        },
        "radial public qualification report",
    )
    validate_document_id(report, "qualification_id", "radial public qualification report")
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["status"] != "PASS"
        or report["contract_id"] != contract["contract_id"]
        or report["candidate_set_id"] != candidate["id"]
    ):
        fail("radial public qualification metadata changed")
    parse_utc(report["created_utc"], "radial qualification created_utc")
    require_sha(
        report["qualified_public_evidence_sha256"],
        64,
        "qualified radial public evidence hash",
    )
    if report["qualified_public_evidence_sha256"] != hashlib.sha256(
        canonical_bytes(report["scientific_evidence"])
    ).hexdigest():
        fail("qualified radial public evidence hash mismatch")
    if not isinstance(report["triplets"], list) or len(report["triplets"]) != 2:
        fail("radial public qualification must contain exactly two triplet attestations")
    labels: set[str] = set()
    signers: set[str] = set()
    triplet_ids: set[str] = set()
    triplet_nonces: set[str] = set()
    source_state_hashes: set[str] = set()
    source_states: list[dict[str, Any]] = []
    run_ids: set[str] = set()
    run_nonces: set[str] = set()
    reconstructed: list[dict[str, Any]] = []
    for triplet_index, raw in enumerate(report["triplets"]):
        public = exact_keys(
            raw,
            {
                "triplet_label",
                "signer_id",
                "triplet_execution_id",
                "triplet_nonce_hex",
                "source_state_sha256",
                "source_provenance",
                "runs",
                "triplet_attestation_base64",
                "triplet_signature_base64",
            },
            f"public radial triplet {triplet_index}",
        )
        label = require_safe_id(public["triplet_label"], "public triplet label")
        signer = candidate_signer(candidate, public["signer_id"])
        triplet_execution_id = canonical_uuid(
            public["triplet_execution_id"], "public triplet execution id"
        )
        triplet_nonce = nonce(public["triplet_nonce_hex"], "public triplet nonce")
        require_sha(public["source_state_sha256"], 64, "public source-state hash")
        validate_source_state(public["source_provenance"])
        if hashlib.sha256(canonical_bytes(public["source_provenance"])).hexdigest() != public["source_state_sha256"]:
            fail("public source provenance does not match the signed source-state hash")
        source_state_hashes.add(public["source_state_sha256"])
        source_states.append(public["source_provenance"])
        labels.add(label)
        signers.add(signer["signer_id"])
        triplet_ids.add(triplet_execution_id)
        triplet_nonces.add(triplet_nonce)
        runs = exact_keys(
            public["runs"], {str(dr) for dr in DRS}, "public radial triplet runs"
        )
        reconstructed_runs: dict[float, dict[str, Any]] = {}
        completion_evidence: dict[str, Any] = {}
        for dr in DRS:
            member = exact_keys(
                runs[str(dr)],
                {
                    "execution_id",
                    "nonce_hex",
                    "completion_attestation_base64",
                    "completion_signature_base64",
                },
                f"public radial dR={dr} attestation",
            )
            execution_id = canonical_uuid(member["execution_id"], "public run execution id")
            run_nonce = nonce(member["nonce_hex"], "public run nonce")
            completion_bytes = adapt_error(
                secure.decode_base64,
                member["completion_attestation_base64"],
                "public radial completion attestation",
                MAX_JSON_BYTES,
            )
            signature_bytes = adapt_error(
                secure.decode_base64,
                member["completion_signature_base64"],
                "public radial completion signature",
                100_000,
            )
            completion = adapt_error(
                secure.load_json_bytes, completion_bytes, "public radial completion attestation"
            )
            if not isinstance(completion, dict):
                fail("public radial completion attestation must be an object")
            expected_keys = {
                "completion_id",
                "schema_version",
                "contract_id",
                "candidate_set_id",
                "signer_id",
                "triplet_label",
                "dR_kpc",
                "execution_id",
                "nonce_hex",
                "source_state_sha256",
                "inputs",
                "controller_programs",
                "start_challenge",
                "start_challenge_signature",
                "execution_record",
                "private_provenance",
                "ssp_manifest",
                "ssp_tuple_sha256",
                "generated_radial",
                "generated_result",
                "rederived_summary",
            }
            exact_keys(completion, expected_keys, "public radial completion attestation")
            validate_document_id(completion, "completion_id", "public radial completion attestation")
            if (
                type(completion["schema_version"]) is not int
                or completion["schema_version"] != 1
                or completion["contract_id"] != contract["contract_id"]
                or completion["candidate_set_id"] != candidate["id"]
                or completion["signer_id"] != signer["signer_id"]
                or completion["triplet_label"] != label
                or completion["execution_id"] != execution_id
                or completion["nonce_hex"] != run_nonce
                or completion["source_state_sha256"] != public["source_state_sha256"]
            ):
                fail("public radial completion identity fields mismatch")
            close_number(completion["dR_kpc"], dr, "public completion dR")
            require_sha(completion["ssp_tuple_sha256"], 64, "public SSP tuple hash")
            expected_evidence_names = {
                "start_challenge": secure.START_CHALLENGE_NAME,
                "start_challenge_signature": secure.START_CHALLENGE_SIGNATURE_NAME,
                "execution_record": secure.EXECUTION_RECORD_NAME,
                "private_provenance": "RUN_PRIVATE_PROVENANCE.json",
                "ssp_manifest": "SSP_SHA256SUMS.txt",
                "generated_radial": "tams_radial.csv",
                "generated_result": "tams_result.json",
            }
            for key, expected_filename in expected_evidence_names.items():
                item = completion[key]
                if not isinstance(item, dict) or set(item) != {"filename", "sha256", "size_bytes"}:
                    fail(f"public completion {key} evidence schema changed")
                adapt_error(
                    secure.validate_evidence,
                    item,
                    expected_filename,
                    f"public completion {key}",
                )
            summary = completion["rederived_summary"]
            if not isinstance(summary, dict):
                fail("public completion rederived summary must be an object")
            validate_public_inputs(completion["inputs"], dr)
            validate_controller_evidence(completion["controller_programs"])
            validate_public_summary(summary, dr)
            hashes = summary.get("ssp_member_sha256")
            if (
                not isinstance(hashes, dict)
                or set(hashes) != set(rederive.expected_ssp_names(dr))
            ):
                fail("public completion SSP hash tuple order/set changed")
            for name, digest in hashes.items():
                require_sha(digest, 64, f"public SSP member {name}")
            if hashlib.sha256(canonical_bytes(hashes)).hexdigest() != completion["ssp_tuple_sha256"]:
                fail("public completion SSP tuple hash mismatch")
            verify_signature_bytes(
                completion_bytes, signature_bytes, signer, COMPLETION_NAMESPACE
            )
            completion_snapshot = secure.synthetic_snapshot(
                "RUN_COMPLETION_ATTESTATION.json", completion_bytes
            )
            signature_snapshot = secure.synthetic_snapshot(
                "RUN_COMPLETION_ATTESTATION.sig", signature_bytes
            )
            completion_evidence[str(dr)] = {
                "completion": evidence(completion_snapshot),
                "completion_signature": evidence(signature_snapshot),
                "execution_id": execution_id,
                "nonce_hex": run_nonce,
            }
            reconstructed_runs[dr] = {
                "inputs": completion["inputs"],
                "summary": summary,
                "generated_radial": completion["generated_radial"],
                "generated_result": completion["generated_result"],
            }
            if execution_id in run_ids or run_nonce in run_nonces:
                fail("public radial qualification reuses execution identity or nonce")
            run_ids.add(execution_id)
            run_nonces.add(run_nonce)
        reconstructed_scientific = scientific_evidence(reconstructed_runs)
        triplet_bytes = adapt_error(
            secure.decode_base64,
            public["triplet_attestation_base64"],
            "public radial triplet attestation",
            MAX_JSON_BYTES,
        )
        triplet_signature_bytes = adapt_error(
            secure.decode_base64,
            public["triplet_signature_base64"],
            "public radial triplet signature",
            100_000,
        )
        triplet_document = adapt_error(
            secure.load_json_bytes, triplet_bytes, "public radial triplet attestation"
        )
        if not isinstance(triplet_document, dict):
            fail("public radial triplet attestation must be an object")
        expected_triplet_body = {
            "schema_version": 1,
            "contract_id": contract["contract_id"],
            "candidate_set_id": candidate["id"],
            "triplet_label": label,
            "signer_id": signer["signer_id"],
            "triplet_execution_id": triplet_execution_id,
            "triplet_nonce_hex": triplet_nonce,
            "created_utc": triplet_document.get("created_utc"),
            "source_state_sha256": public["source_state_sha256"],
            "run_attestations": completion_evidence,
            "scientific_evidence_sha256": hashlib.sha256(
                canonical_bytes(reconstructed_scientific)
            ).hexdigest(),
        }
        exact_keys(
            triplet_document,
            {"triplet_attestation_id", *expected_triplet_body},
            "public radial triplet attestation",
        )
        parse_utc(triplet_document["created_utc"], "public triplet created_utc")
        validate_document_id(
            triplet_document, "triplet_attestation_id", "public radial triplet attestation"
        )
        observed_triplet_body = dict(triplet_document)
        observed_triplet_body.pop("triplet_attestation_id")
        if observed_triplet_body != expected_triplet_body:
            fail("public radial triplet attestation hash bindings differ")
        verify_signature_bytes(
            triplet_bytes, triplet_signature_bytes, signer, TRIPLET_NAMESPACE
        )
        reconstructed.append(reconstructed_scientific)
    if len(labels) != 2 or len(signers) != 2 or len(triplet_ids) != 2 or len(triplet_nonces) != 2:
        fail("public radial qualification does not prove two distinct triplets/signers")
    if len(source_state_hashes) != 1 or source_states[0] != source_states[1]:
        fail("public radial qualification source provenance differs across triplets")
    if reconstructed[0] != reconstructed[1] or reconstructed[0] != report["scientific_evidence"]:
        fail("public radial scientific evidence differs across signed triplets")
    assert_no_raw_public_payload(report)
    return report


def accepted_candidate(contract: dict[str, Any]) -> dict[str, Any]:
    matches = [item for item in contract["artifact_sets"] if item["production_accepted"]]
    if len(matches) != 1:
        fail("radial contract does not contain exactly one production-accepted set")
    return matches[0]


def verify_public_qualification(
    contract_path: Path, report_path: Path
) -> dict[str, Any]:
    contract, contract_snapshot = load_contract(contract_path)
    candidate = accepted_candidate(contract)
    report_document, report_snapshot = strict_json_snapshot(
        report_path, "radial public qualification report"
    )
    lock = candidate["qualification_report"]
    if (
        report_snapshot.path.name != lock["path"]
        or report_snapshot.sha256 != lock["sha256"]
    ):
        fail("radial public qualification report differs from the accepted contract lock")
    report = validate_public_report(contract, candidate, report_document)
    if report["qualified_public_evidence_sha256"] != candidate[
        "qualified_public_evidence_sha256"
    ]:
        fail("accepted radial public evidence hash differs from the report")
    return {
        "artifact_set_id": candidate["id"],
        "contract_sha256": contract_snapshot.sha256,
        "qualification_report_sha256": report_snapshot.sha256,
        "qualified_public_evidence_sha256": report[
            "qualified_public_evidence_sha256"
        ],
        "scientific_evidence": report["scientific_evidence"],
    }


def bind_public_convergence(
    contract_path: Path, report_path: Path, convergence_root_path: Path
) -> dict[str, Any]:
    accepted = verify_public_qualification(contract_path, report_path)
    root = adapt_error(
        secure.require_directory, convergence_root_path, "public radial convergence root"
    )
    if (root / "freeze-contract").is_dir() and not (root / "freeze-contract").is_symlink():
        root = adapt_error(
            secure.require_directory, root / "freeze-contract", "public radial freeze-contract root"
        )
    scientific = accepted["scientific_evidence"]
    bound: dict[str, Any] = {}
    for dr in DRS:
        tag_value = rederive.tag(dr)
        radial = adapt_error(
            secure.read_snapshot,
            root / f"tams_radial_dr{tag_value}.csv",
            f"public radial dR={dr} CSV",
        )
        result = adapt_error(
            secure.read_snapshot,
            root / f"tams_result_dr{tag_value}.json",
            f"public radial dR={dr} result",
            maximum_bytes=MAX_JSON_BYTES,
        )
        expected = scientific["runs"][str(dr)]
        if radial.sha256 != expected["generated_radial"]["sha256"] or radial.size_bytes != expected["generated_radial"]["size_bytes"]:
            fail(f"public radial dR={dr} CSV differs from qualified private evidence")
        if result.sha256 != expected["generated_result"]["sha256"] or result.size_bytes != expected["generated_result"]["size_bytes"]:
            fail(f"public radial dR={dr} result differs from qualified private evidence")
        rows = adapt_error(rederive.parse_generated_radial, radial.path, dr)
        for index, row in enumerate(rows):
            if (
                any(row[key] < 0.0 for key in rederive.RADIAL_COLUMNS[1:])
                or row["dL2_dR"] > row["dL1_dR"] + 1.0e-8
                or row["Sigma_thick_TAMS_pc-2"] > row["Sigma_TAMS_pc-2"] + 1.0e-12
            ):
                fail(f"qualified public radial ordering fails at row {index + 2}")
            geometry = 2.0 * math.pi * row["R_kpc"] * 1.0e6 * row["Sigma_TAMS_pc-2"]
            close_number(row["dN_dR"], geometry, "qualified public radial geometry")
        summary = expected["summary"]
        if hashlib.sha256(canonical_bytes(rows)).hexdigest() != summary["radial_rows_sha256"]:
            fail("public radial rows differ from signed independently rederived rows")
        derived = dict(summary)
        derived["radial_rows"] = rows
        result_document = adapt_error(
            secure.load_json_bytes, result.data, f"public radial dR={dr} result"
        )
        validate_generated_result(result_document, derived)
        bound[str(dr)] = {
            "generated_radial": evidence(radial),
            "generated_result": evidence(result),
            "summary": summary,
        }
    return {
        **{key: value for key, value in accepted.items() if key != "scientific_evidence"},
        "convergence_root": str(root),
        "runs": bound,
        "status": "PASS",
    }


def write_manifest(
    path: Path, names: tuple[str, ...], snapshots: dict[str, secure.FileSnapshot]
) -> None:
    lines = [f"{snapshots[name].sha256}  {name}\n" for name in names]
    adapt_error(secure.write_bytes_exclusive, path, "".join(lines).encode("utf-8"))


def exact_fresh_roots(execution_root: Path, output_root: Path) -> tuple[Path, Path]:
    execution = Path(execution_root)
    output = Path(output_root)
    execution_resolved = execution.resolve()
    output_resolved = output.resolve()
    if (
        execution_resolved == output_resolved
        or execution_resolved in output_resolved.parents
        or output_resolved in execution_resolved.parents
    ):
        fail("radial execution and private output roots must be distinct and non-nested")
    for candidate, description in (
        (execution, "radial execution root"),
        (output, "radial private output root"),
    ):
        if candidate.exists() or candidate.is_symlink():
            fail(f"fresh {description} must not already exist: {candidate}")
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if candidate.parent.is_symlink() or not candidate.parent.is_dir():
            fail(f"fresh {description} parent must be a non-symlink directory")
    execution.mkdir()
    return execution, output


def execute_fresh_triplet(
    contract_path: Path,
    *,
    jj_root: Path,
    jj_source_archive: Path,
    tutorial_parameters: Path,
    sfr_peaks_parameters: Path,
    numerical_runtime_manifest: Path,
    padova_archive: Path,
    public_source_root: Path,
    public_repository: str,
    public_source_archive: Path,
    private_source_root: Path,
    private_repository: str,
    private_source_archive: Path,
    candidate_set_id: str,
    signer_id: str,
    signing_key: Path,
    triplet_label: str,
    execution_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Controller-create three fresh JJ executions and one signed private triplet."""

    _load_local_dependencies(
        public_source_archive=public_source_archive,
        private_source_archive=private_source_archive,
    )
    contract, _ = load_contract(contract_path)
    candidate = artifact_set(
        contract, require_safe_id(candidate_set_id, "radial candidate id")
    )
    if candidate["qualification_eligible"] is not True:
        fail("radial candidate is not qualification eligible")
    signer = candidate_signer(
        candidate, require_safe_id(signer_id, "radial signer id")
    )
    if adapt_error(secure.signing_public_key, signing_key) != signer["public_key"]:
        fail("radial signing key does not match the contract-locked signer")
    label = require_safe_id(triplet_label, "radial triplet label")
    execution_environment = adapt_error(secure.detect_execution_environment)
    execution, output = exact_fresh_roots(execution_root, output_root)

    padova = adapt_error(secure.read_snapshot, padova_archive, "locked Padova archive")
    if (
        padova.path.name != PADOVA_FILENAME
        or padova.sha256 != PADOVA_SHA256
        or padova.size_bytes != PADOVA_SIZE_BYTES
    ):
        fail("Padova archive does not match the radial release lock")
    source_state, padova_paths = build_source_state(
        jj_root=jj_root,
        jj_source_archive=jj_source_archive,
        padova_archive=padova,
        public_source_root=public_source_root,
        public_repository=public_repository,
        public_source_archive=public_source_archive,
        private_source_root=private_source_root,
        private_repository=private_repository,
        private_source_archive=private_source_archive,
    )
    private_root = adapt_error(
        secure.require_directory, private_source_root, "private production source"
    )
    generation_program = tracked_program_snapshot(private_root)
    controller_snapshots = tracked_controller_snapshots(private_root)
    controllers = controller_evidence(controller_snapshots)
    original_source = adapt_error(
        secure.read_snapshot, tutorial_parameters, "original tutorial2 parameters"
    )
    sfr_source = adapt_error(
        secure.read_snapshot, sfr_peaks_parameters, "original tutorial2 SFR peaks"
    )
    runtime_source = adapt_error(
        secure.read_snapshot,
        numerical_runtime_manifest,
        "numerical runtime manifest",
        maximum_bytes=secure.MAX_RUNTIME_BYTES,
    )
    runtime_document = adapt_error(
        secure.validate_runtime_manifest,
        adapt_error(
            secure.load_json_bytes, runtime_source.data, "numerical runtime manifest"
        ),
    )
    if original_source.sha256 != TUTORIAL_PARAMETERS_SHA256:
        fail("supplied original tutorial2 parameters differ from the radial lock")
    if sfr_source.sha256 != TUTORIAL_SFR_SHA256:
        fail("supplied tutorial2 SFR peaks differ from the radial lock")
    try:
        committed_parameters = subprocess.check_output(
            ["git", "show", "HEAD:jjmodel/tutorials/tutorial2/parameters"], cwd=jj_root
        )
        committed_sfr = subprocess.check_output(
            ["git", "show", "HEAD:jjmodel/tutorials/tutorial2/sfrd_peaks_parameters"],
            cwd=jj_root,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot read locked JJ tutorial2 configuration: {exc}")
    if committed_parameters != original_source.data or committed_sfr != sfr_source.data:
        fail("supplied tutorial2 inputs are not exact JJ HEAD bytes")
    private_tams = adapt_error(
        secure.read_snapshot,
        private_root
        / "research"
        / "jj-host-export"
        / "reference-data"
        / "tams_parsec_danxhuber.txt",
        "private production TAMS reference",
        maximum_bytes=100_000,
    )
    canonical_tams = adapt_error(
        secure.read_snapshot,
        rederive.independent_reference.TAMS_PATH,
        "canonical TAMS reference",
        maximum_bytes=100_000,
    )
    if (
        private_tams.sha256 != TAMS_REFERENCE_SHA256
        or canonical_tams.sha256 != TAMS_REFERENCE_SHA256
        or private_tams.data != canonical_tams.data
    ):
        fail("private and verifier TAMS references do not match the radial lock")
    python_executable = runtime_document["python_executable"]
    if not Path(python_executable).is_absolute() or not Path(python_executable).is_file():
        fail("numerical-runtime python_executable must be an existing absolute file")

    temporary = Path(tempfile.mkdtemp(prefix=".radial-ssp-triplet-", dir=output.parent))
    triplet_execution_id = str(uuid.uuid4())
    triplet_nonce_hex = secrets.token_hex(32)
    packaged_runs: dict[float, dict[str, Any]] = {}
    try:
        for dr in DRS:
            run_name = RUN_DIR_NAMES[dr]
            workspace = execution / run_name
            workspace.mkdir()
            run_dir = workspace / "jj-run"
            generator_output = workspace / "generator-output"
            input_dir = workspace / "challenge-inputs"
            run_dir.mkdir()
            generator_output.mkdir()
            input_dir.mkdir()
            adapt_error(
                secure.write_bytes_exclusive,
                input_dir / "parameters.original",
                original_source.data,
            )
            runtime_bytes = expected_runtime_parameters(original_source.data, dr)
            adapt_error(
                secure.write_bytes_exclusive,
                input_dir / "parameters.runtime",
                runtime_bytes,
            )
            adapt_error(
                secure.write_bytes_exclusive,
                input_dir / "sfrd_peaks_parameters",
                sfr_source.data,
            )
            adapt_error(
                secure.write_bytes_exclusive,
                input_dir / secure.RUNTIME_NAME,
                runtime_source.data,
            )
            adapt_error(
                secure.write_bytes_exclusive,
                run_dir / "parameters",
                runtime_bytes,
            )
            adapt_error(
                secure.write_bytes_exclusive,
                run_dir / "sfrd_peaks_parameters",
                sfr_source.data,
            )
            input_snapshots = {
                "parameters_original": adapt_error(secure.read_snapshot, input_dir / "parameters.original", "challenge original parameters"),
                "parameters_runtime": adapt_error(secure.read_snapshot, input_dir / "parameters.runtime", "challenge runtime parameters"),
                "sfr_peaks_parameters": adapt_error(secure.read_snapshot, input_dir / "sfrd_peaks_parameters", "challenge SFR peaks"),
                "numerical_runtime_manifest": adapt_error(secure.read_snapshot, input_dir / secure.RUNTIME_NAME, "challenge runtime manifest"),
                "tams_reference": private_tams,
            }
            inputs = exact_input_evidence(
                input_snapshots["parameters_original"],
                input_snapshots["parameters_runtime"],
                input_snapshots["sfr_peaks_parameters"],
                input_snapshots["numerical_runtime_manifest"],
                input_snapshots["tams_reference"],
            )
            execution_id = str(uuid.uuid4())
            nonce_hex = secrets.token_hex(32)
            issued_utc = utc_now()
            challenge_body = {
                "schema_version": 1,
                "contract_id": contract["contract_id"],
                "candidate_set_id": candidate["id"],
                "signer_id": signer["signer_id"],
                "triplet_label": label,
                "dR_kpc": dr,
                "execution_id": execution_id,
                "nonce_hex": nonce_hex,
                "issued_utc": issued_utc,
                "generation_program": evidence(generation_program),
                "controller_programs": controllers,
                "source_state_sha256": hashlib.sha256(
                    canonical_bytes(source_state)
                ).hexdigest(),
                "inputs": inputs,
            }
            challenge = document_with_id(challenge_body, "challenge_id")
            challenge_path = workspace / secure.START_CHALLENGE_NAME
            write_json_exclusive(challenge_path, challenge)
            sign_document(
                challenge_path,
                signing_key,
                START_NAMESPACE,
                secure.START_CHALLENGE_SIGNATURE_NAME,
            )
            challenge_snapshot = adapt_error(
                secure.read_snapshot, challenge_path, "issued radial start challenge"
            )
            challenge_signature = adapt_error(
                secure.read_snapshot,
                workspace / secure.START_CHALLENGE_SIGNATURE_NAME,
                "issued radial start signature",
            )
            argv = [
                python_executable,
                str(generation_program.path),
                "--jj-root",
                str(Path(jj_root).resolve()),
                "--run-dir",
                str(run_dir.resolve()),
                "--out",
                str(generator_output.resolve()),
                "--iso",
                "Padova",
            ]
            child_environment = os.environ.copy()
            child_environment.update(secure.EXPECTED_NUMERICAL_ENV)
            child_environment["PYTHONNOUSERSITE"] = "1"
            child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
            child_environment.pop("PYTHONPATH", None)
            started_utc = utc_now()
            try:
                result = subprocess.run(
                    argv,
                    cwd=private_root,
                    env=child_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    shell=False,
                )
            except OSError as exc:
                fail(f"cannot execute pinned radial JJ generator: {exc}")
            completed_utc = utc_now()
            if result.returncode != 0:
                fail(
                    f"pinned radial generator failed at dR={dr} with return code "
                    f"{result.returncode}; execution retained at {execution}"
                )
            post_source_state, post_padova_paths = build_source_state(
                jj_root=jj_root,
                jj_source_archive=jj_source_archive,
                padova_archive=padova,
                public_source_root=public_source_root,
                public_repository=public_repository,
                public_source_archive=public_source_archive,
                private_source_root=private_source_root,
                private_repository=private_repository,
                private_source_archive=private_source_archive,
            )
            if post_padova_paths != padova_paths or post_source_state != source_state:
                fail("source state or locked Padova overlay changed during radial execution")
            if tracked_program_snapshot(private_root) != generation_program:
                fail("radial generation program changed during controlled execution")
            if tracked_controller_snapshots(private_root) != controller_snapshots:
                fail("radial controller dependency changed during controlled execution")
            if adapt_error(secure.read_snapshot, rederive.independent_reference.TAMS_PATH, "post-run TAMS reference").data != canonical_tams.data:
                fail("TAMS reference changed during controlled radial execution")
            derived = adapt_error(rederive.rederive_private_run, run_dir, dr)
            generated_radial_path = generator_output / f"tams_radial_dr{rederive.tag(dr)}.csv"
            generated_result_path = generator_output / f"tams_result_dr{rederive.tag(dr)}.json"
            generated_radial = adapt_error(
                secure.read_snapshot, generated_radial_path, "generated radial CSV"
            )
            generated_result = adapt_error(
                secure.read_snapshot,
                generated_result_path,
                "generated radial result",
                maximum_bytes=MAX_JSON_BYTES,
            )
            normalized_radial_evidence = secure.synthetic_snapshot(
                "tams_radial.csv", generated_radial.data
            )
            normalized_result_evidence = secure.synthetic_snapshot(
                "tams_result.json", generated_result.data
            )
            observed_rows = adapt_error(
                rederive.parse_generated_radial, generated_radial_path, dr
            )
            adapt_error(rederive.compare_radial_rows, observed_rows, derived["radial_rows"])
            validate_generated_result(
                adapt_error(
                    secure.load_json_bytes,
                    generated_result.data,
                    "generated radial result",
                ),
                derived,
            )
            ssp = adapt_error(rederive.discover_private_ssp, run_dir, dr)
            execution_body = {
                "schema_version": 1,
                "controller": "verify_radial_ssp_contract.execute_fresh_triplet",
                "challenge_id": challenge["challenge_id"],
                "execution_id": execution_id,
                "nonce_hex": nonce_hex,
                "dR_kpc": dr,
                "argv": argv,
                "cwd": str(private_root),
                "shell": False,
                "run_directory_created_empty": True,
                "generator_output_directory_created_empty": True,
                "run_started_utc": started_utc,
                "run_completed_utc": completed_utc,
                "return_code": result.returncode,
                "stdout": {
                    "sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "size_bytes": len(result.stdout),
                },
                "stderr": {
                    "sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "size_bytes": len(result.stderr),
                },
                "ssp_member_sha256": derived["ssp_member_sha256"],
                "generated_radial": evidence(normalized_radial_evidence),
                "generated_result": evidence(normalized_result_evidence),
            }
            execution_record = document_with_id(
                execution_body, "execution_record_id"
            )
            execution_record_path = workspace / secure.EXECUTION_RECORD_NAME
            write_json_exclusive(execution_record_path, execution_record)
            execution_record_snapshot = adapt_error(
                secure.read_snapshot, execution_record_path, "radial execution record"
            )

            package = temporary / run_name
            package.mkdir()
            package_ssp = package / "ssp"
            package_ssp.mkdir()
            copies = (
                (input_snapshots["parameters_original"], "parameters.original"),
                (input_snapshots["parameters_runtime"], "parameters.runtime"),
                (input_snapshots["sfr_peaks_parameters"], "sfrd_peaks_parameters"),
                (input_snapshots["numerical_runtime_manifest"], secure.RUNTIME_NAME),
                (challenge_snapshot, secure.START_CHALLENGE_NAME),
                (challenge_signature, secure.START_CHALLENGE_SIGNATURE_NAME),
                (execution_record_snapshot, secure.EXECUTION_RECORD_NAME),
                (generated_radial, "tams_radial.csv"),
                (generated_result, "tams_result.json"),
            )
            for source, name in copies:
                adapt_error(secure.write_bytes_exclusive, package / name, source.data)
            packaged_ssp: dict[str, secure.FileSnapshot] = {}
            for name in rederive.expected_ssp_names(dr):
                adapt_error(secure.write_bytes_exclusive, package_ssp / name, ssp[name].data)
                packaged_ssp[name] = adapt_error(
                    secure.read_snapshot, package_ssp / name, f"packaged radial SSP {name}"
                )
            write_manifest(
                package / "SSP_SHA256SUMS.txt",
                rederive.expected_ssp_names(dr),
                packaged_ssp,
            )
            package_snapshots = {
                "parameters_original": adapt_error(secure.read_snapshot, package / "parameters.original", "packaged original parameters"),
                "parameters_runtime": adapt_error(secure.read_snapshot, package / "parameters.runtime", "packaged runtime parameters"),
                "sfr_peaks_parameters": adapt_error(secure.read_snapshot, package / "sfrd_peaks_parameters", "packaged SFR peaks"),
                "numerical_runtime_manifest": adapt_error(secure.read_snapshot, package / secure.RUNTIME_NAME, "packaged runtime manifest"),
                "tams_reference": canonical_tams,
                "start_challenge": adapt_error(secure.read_snapshot, package / secure.START_CHALLENGE_NAME, "packaged start challenge"),
                "start_challenge_signature": adapt_error(secure.read_snapshot, package / secure.START_CHALLENGE_SIGNATURE_NAME, "packaged start signature"),
                "execution_record": adapt_error(secure.read_snapshot, package / secure.EXECUTION_RECORD_NAME, "packaged execution record"),
                "ssp_manifest": adapt_error(secure.read_snapshot, package / "SSP_SHA256SUMS.txt", "packaged SSP manifest"),
                "generated_radial": adapt_error(secure.read_snapshot, package / "tams_radial.csv", "packaged radial CSV"),
                "generated_result": adapt_error(secure.read_snapshot, package / "tams_result.json", "packaged radial result"),
            }
            provenance = {
                "schema_version": 1,
                "contract_id": contract["contract_id"],
                "candidate_set_id": candidate["id"],
                "triplet_label": label,
                "signer_id": signer["signer_id"],
                "dR_kpc": dr,
                "execution_id": execution_id,
                "nonce_hex": nonce_hex,
                "execution_environment": execution_environment,
                "challenge_issued_utc": issued_utc,
                "run_started_utc": started_utc,
                "run_completed_utc": completed_utc,
                "source_state": source_state,
                "generation_program": evidence(generation_program),
                "controller_programs": controllers,
                "inputs": exact_input_evidence(
                    package_snapshots["parameters_original"],
                    package_snapshots["parameters_runtime"],
                    package_snapshots["sfr_peaks_parameters"],
                    package_snapshots["numerical_runtime_manifest"],
                    package_snapshots["tams_reference"],
                ),
                "start_challenge": evidence(package_snapshots["start_challenge"]),
                "start_challenge_signature": evidence(package_snapshots["start_challenge_signature"]),
                "execution_record": evidence(package_snapshots["execution_record"]),
                "ssp_manifest": evidence(package_snapshots["ssp_manifest"]),
                "generated_radial": evidence(package_snapshots["generated_radial"]),
                "generated_result": evidence(package_snapshots["generated_result"]),
            }
            provenance_path = package / "RUN_PRIVATE_PROVENANCE.json"
            write_json_exclusive(provenance_path, provenance)
            provenance_snapshot = adapt_error(
                secure.read_snapshot, provenance_path, "packaged private provenance"
            )
            completion = document_with_id(
                completion_body(
                    contract=contract,
                    candidate=candidate,
                    provenance=provenance,
                    challenge=package_snapshots["start_challenge"],
                    challenge_signature=package_snapshots["start_challenge_signature"],
                    execution_record=package_snapshots["execution_record"],
                    private_provenance=provenance_snapshot,
                    ssp_manifest=package_snapshots["ssp_manifest"],
                    radial=package_snapshots["generated_radial"],
                    result=package_snapshots["generated_result"],
                    derived_summary=result_summary(derived),
                ),
                "completion_id",
            )
            completion_path = package / "RUN_COMPLETION_ATTESTATION.json"
            write_json_exclusive(completion_path, completion)
            sign_document(
                completion_path,
                signing_key,
                COMPLETION_NAMESPACE,
                "RUN_COMPLETION_ATTESTATION.sig",
            )
            if {path.name for path in package.iterdir()} != PRIVATE_RUN_FILES:
                fail("generated private radial run package file set changed")
            packaged_runs[dr] = {
                "execution_id": execution_id,
                "nonce_hex": nonce_hex,
                "completion": evidence(adapt_error(secure.read_snapshot, completion_path, "generated completion attestation")),
                "completion_signature": evidence(adapt_error(secure.read_snapshot, package / "RUN_COMPLETION_ATTESTATION.sig", "generated completion signature")),
            }

        source_state_sha256 = hashlib.sha256(canonical_bytes(source_state)).hexdigest()
        triplet_provenance = {
            "schema_version": 1,
            "contract_id": contract["contract_id"],
            "candidate_set_id": candidate["id"],
            "triplet_label": label,
            "signer_id": signer["signer_id"],
            "triplet_execution_id": triplet_execution_id,
            "triplet_nonce_hex": triplet_nonce_hex,
            "created_utc": utc_now(),
            "source_state_sha256": source_state_sha256,
            "runs": {str(dr): packaged_runs[dr] for dr in DRS},
        }
        triplet_provenance_path = temporary / "TRIPLET_PRIVATE_PROVENANCE.json"
        write_json_exclusive(triplet_provenance_path, triplet_provenance)
        inspected_runs = {
            dr: inspect_private_run(temporary / RUN_DIR_NAMES[dr], contract, candidate, dr)
            for dr in DRS
        }
        scientific = scientific_evidence(inspected_runs)
        run_attestation_snapshots = {
            dr: (
                adapt_error(secure.read_snapshot, temporary / RUN_DIR_NAMES[dr] / "RUN_COMPLETION_ATTESTATION.json", "generated triplet completion"),
                adapt_error(secure.read_snapshot, temporary / RUN_DIR_NAMES[dr] / "RUN_COMPLETION_ATTESTATION.sig", "generated triplet completion signature"),
            )
            for dr in DRS
        }
        triplet_attestation = document_with_id(
            triplet_body(
                contract=contract,
                candidate=candidate,
                provenance=triplet_provenance,
                run_snapshots=run_attestation_snapshots,
                scientific=scientific,
            ),
            "triplet_attestation_id",
        )
        triplet_path = temporary / "TRIPLET_ATTESTATION.json"
        write_json_exclusive(triplet_path, triplet_attestation)
        sign_document(
            triplet_path,
            signing_key,
            TRIPLET_NAMESPACE,
            "TRIPLET_ATTESTATION.sig",
        )
        if {path.name for path in temporary.iterdir()} != {
            *PRIVATE_TRIPLET_FILES,
            *RUN_DIR_NAMES.values(),
        }:
            fail("generated private radial triplet file set changed")
        os.replace(temporary, output)
        return inspect_private_triplet(contract_path, output, candidate["id"])
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        "--mode",
        required=True,
        choices=("execute", "verify-private", "qualify", "verify-public", "bind"),
    )
    argument_parser.add_argument("--contract", required=True, type=Path)
    argument_parser.add_argument("--private-root", type=Path)
    argument_parser.add_argument("--first-root", type=Path)
    argument_parser.add_argument("--second-root", type=Path)
    argument_parser.add_argument("--qualification-report", type=Path)
    argument_parser.add_argument("--convergence-root", type=Path)
    argument_parser.add_argument("--candidate-set-id")
    argument_parser.add_argument("--report-out", type=Path)
    argument_parser.add_argument("--jj-root", type=Path)
    argument_parser.add_argument("--jj-source-archive", type=Path)
    argument_parser.add_argument("--tutorial-parameters", type=Path)
    argument_parser.add_argument("--sfr-peaks-parameters", type=Path)
    argument_parser.add_argument("--numerical-runtime-manifest", type=Path)
    argument_parser.add_argument("--padova-archive", type=Path)
    argument_parser.add_argument("--public-source-root", type=Path)
    argument_parser.add_argument("--public-repository")
    argument_parser.add_argument("--public-source-archive", type=Path)
    argument_parser.add_argument("--private-source-root", type=Path)
    argument_parser.add_argument("--private-repository")
    argument_parser.add_argument("--private-source-archive", type=Path)
    argument_parser.add_argument("--signer-id")
    argument_parser.add_argument("--signing-key", type=Path)
    argument_parser.add_argument("--triplet-label")
    argument_parser.add_argument("--execution-root", type=Path)
    argument_parser.add_argument("--out", type=Path)
    return argument_parser


def required_options(args: argparse.Namespace, names: tuple[str, ...]) -> None:
    missing = sorted(name for name in names if getattr(args, name) is None)
    if missing:
        fail(f"radial {args.mode} mode lacks options: {missing}")


def main(argv: Iterable[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        if args.mode == "execute":
            required_options(
                args, ("public_source_archive", "private_source_archive")
            )
            _load_local_dependencies(
                public_source_archive=args.public_source_archive,
                private_source_archive=args.private_source_archive,
            )
        else:
            _load_local_dependencies()
        if args.mode == "verify-private":
            required_options(args, ("private_root",))
            result = inspect_private_triplet(
                args.contract, args.private_root, args.candidate_set_id
            )
            print(
                "PASS radial private SSP triplet "
                f"({result['triplet_label']}; three fresh executions)"
            )
            return
        if args.mode == "qualify":
            required_options(
                args,
                ("first_root", "second_root", "candidate_set_id", "report_out"),
            )
            result = qualify_triplets(
                args.contract,
                args.first_root,
                args.second_root,
                args.candidate_set_id,
                args.report_out,
            )
            print(f"PASS radial SSP qualification ({result['qualification_id']})")
            return
        if args.mode == "verify-public":
            required_options(args, ("qualification_report",))
            result = verify_public_qualification(
                args.contract, args.qualification_report
            )
            print(
                "PASS accepted radial SSP qualification "
                f"({result['artifact_set_id']})"
            )
            return
        if args.mode == "bind":
            required_options(args, ("qualification_report", "convergence_root"))
            result = bind_public_convergence(
                args.contract, args.qualification_report, args.convergence_root
            )
            print(
                "PASS accepted radial SSP public binding "
                f"({result['artifact_set_id']}; three spacings)"
            )
            return
        required_options(
            args,
            (
                "jj_root",
                "jj_source_archive",
                "tutorial_parameters",
                "sfr_peaks_parameters",
                "numerical_runtime_manifest",
                "padova_archive",
                "public_source_root",
                "public_repository",
                "public_source_archive",
                "private_source_root",
                "private_repository",
                "private_source_archive",
                "candidate_set_id",
                "signer_id",
                "signing_key",
                "triplet_label",
                "execution_root",
                "out",
            ),
        )
        result = execute_fresh_triplet(
            args.contract,
            jj_root=args.jj_root,
            jj_source_archive=args.jj_source_archive,
            tutorial_parameters=args.tutorial_parameters,
            sfr_peaks_parameters=args.sfr_peaks_parameters,
            numerical_runtime_manifest=args.numerical_runtime_manifest,
            padova_archive=args.padova_archive,
            public_source_root=args.public_source_root,
            public_repository=args.public_repository,
            public_source_archive=args.public_source_archive,
            private_source_root=args.private_source_root,
            private_repository=args.private_repository,
            private_source_archive=args.private_source_archive,
            candidate_set_id=args.candidate_set_id,
            signer_id=args.signer_id,
            signing_key=args.signing_key,
            triplet_label=args.triplet_label,
            execution_root=args.execution_root,
            output_root=args.out,
        )
        print(
            "PASS radial controlled fresh SSP triplet "
            f"({result['triplet_label']}; three spacings)"
        )
    except (RadialContractError, RadialBootstrapError) as exc:
        raise SystemExit(f"RADIAL SSP CONTRACT FAIL: {exc}") from exc


if __name__ != "__main__":
    _load_local_dependencies()


if __name__ == "__main__":
    main()
