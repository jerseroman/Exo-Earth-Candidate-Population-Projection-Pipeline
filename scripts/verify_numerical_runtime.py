#!/usr/bin/env python3
"""Validate and record the release numerical-runtime policy before computation."""

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
import json
import os
import platform
import sys
from pathlib import Path
from typing import Mapping


EXPECTED_ENV = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,"
        "AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
REQUIRED_ENABLED = ("AVX2", "FMA3")
REQUIRED_DISABLED = (
    "AVX512F",
    "AVX512CD",
    "AVX512_KNL",
    "AVX512_KNM",
    "AVX512_SKX",
    "AVX512_CLX",
    "AVX512_CNL",
    "AVX512_ICL",
)
EXPECTED_NUMPY_VERSION = "1.23.5"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_environment(environ: Mapping[str, str]) -> dict[str, str]:
    observed = {key: environ.get(key, "") for key in EXPECTED_ENV}
    require(
        observed == EXPECTED_ENV,
        f"numerical environment mismatch: {observed!r} != {EXPECTED_ENV!r}",
    )
    return observed


def validate_cpu_features(features: Mapping[str, bool]) -> dict[str, bool]:
    missing = [name for name in REQUIRED_ENABLED + REQUIRED_DISABLED if name not in features]
    require(not missing, f"NumPy CPU-feature report lacks: {missing}")
    for name in REQUIRED_ENABLED:
        require(features[name] is True, f"required CPU feature is inactive: {name}")
    for name in REQUIRED_DISABLED:
        require(features[name] is False, f"forbidden CPU dispatch target is active: {name}")
    names = REQUIRED_ENABLED + REQUIRED_DISABLED
    return {name: bool(features.get(name, False)) for name in names}


def collect_report() -> dict:
    environment = validate_environment(os.environ)
    # The dispatch mask must already be present before this first NumPy import.
    import numpy as np

    require(
        np.__version__ == EXPECTED_NUMPY_VERSION,
        f"NumPy version mismatch: {np.__version__} != {EXPECTED_NUMPY_VERSION}",
    )
    dispatch = np.core._multiarray_umath  # NumPy 1.23 pinned introspection API
    features = validate_cpu_features(dispatch.__cpu_features__)
    return {
        "schema_version": 1,
        "status": "PASS",
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "numpy_version": np.__version__,
        "numpy_cpu_baseline": list(dispatch.__cpu_baseline__),
        "numpy_cpu_dispatch_build": list(dispatch.__cpu_dispatch__),
        "selected_cpu_features": features,
        "environment": environment,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = collect_report()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"WROTE {args.output}")
    print(rendered, end="")


if __name__ == "__main__":
    main()
