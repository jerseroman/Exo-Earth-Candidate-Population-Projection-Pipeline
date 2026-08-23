#!/usr/bin/env python3
"""Freeze an estimand-aware primary-literature comparison for v4."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text_lf(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def require_source_fields(source: dict[str, Any]) -> None:
    required = {
        "key",
        "authors",
        "year",
        "journal",
        "doi",
        "primary_url",
        "quantity",
        "definition",
        "reported_result",
        "comparison_role",
        "comparability",
    }
    missing = required.difference(source)
    if missing:
        raise RuntimeError(f"Literature source lacks required fields: {sorted(missing)}")
    if not str(source["primary_url"]).startswith("https://"):
        raise RuntimeError(f"Primary URL is not HTTPS for {source['key']}")
    if "/" not in str(source["doi"]):
        raise RuntimeError(f"Malformed DOI for {source['key']}")


def require_bryson_gstar_anchor(source: dict[str, Any]) -> None:
    """Require the temperature-matched Table 5 source-fidelity benchmark."""
    if source.get("key") != "Bryson2021":
        raise RuntimeError("Bryson source-model anchor has the wrong key")
    definition = str(source.get("definition", ""))
    result = str(source.get("reported_result", ""))
    if "5300--6000 K" not in definition or "Table 5" not in definition:
        raise RuntimeError("Bryson benchmark is not the temperature-matched Table 5 result")
    for anchor in ("0.38", "0.63", "constant-extrapolation", "zero-extrapolation"):
        if anchor not in result:
            raise RuntimeError(f"Bryson G-star benchmark lacks {anchor}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--numerical-freeze", required=True, type=Path)
    parser.add_argument("--dr25-audit", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    numerical = load_json(args.numerical_freeze)
    dr25 = load_json(args.dr25_audit)
    registry = load_json(args.sources)

    if numerical.get("status") != "PASS":
        raise RuntimeError("Numerical result is not frozen PASS")
    if dr25.get("status") != "FAIL_LOCAL_EMPIRICAL_SUPPORT":
        raise RuntimeError("DR25 support audit has changed unexpectedly")
    if registry.get("schema_version") != 1:
        raise RuntimeError("Unsupported literature registry schema")

    sources = registry.get("sources", [])
    if len(sources) < 5:
        raise RuntimeError("Primary-literature comparison is unexpectedly sparse")
    for source in sources:
        require_source_fields(source)
    keys = [source["key"] for source in sources]
    if len(keys) != len(set(keys)):
        raise RuntimeError("Duplicate literature source key")
    if "Bryson2021" not in keys:
        raise RuntimeError("Source-model anchor Bryson2021 is missing")
    bryson = next(source for source in sources if source["key"] == "Bryson2021")
    require_bryson_gstar_anchor(bryson)
    transport_keys = {"Dai2021", "BashiZucker2022", "Sayeed2025", "Frankel2020"}
    missing_transport = sorted(transport_keys.difference(keys))
    if missing_transport:
        raise RuntimeError(f"Modern source-to-target transport sources are missing: {missing_transport}")

    galactic = numerical["galactic_results"]
    comparison: dict[str, Any] = {
        "status": "PASS_ESTIMAND_AWARE_COMPARISON",
        "scientific_interpretation": "CONDITIONAL_MODEL_PROJECTION_ONLY",
        "search_cutoff": registry["search_cutoff"],
        "inclusion_policy": registry["inclusion_policy"],
        "inputs": {
            "numerical_freeze": {
                "path": str(args.numerical_freeze),
                "sha256": sha256(args.numerical_freeze),
            },
            "dr25_support_audit": {
                "path": str(args.dr25_audit),
                "sha256": sha256(args.dr25_audit),
            },
            "primary_literature_registry": {
                "path": str(args.sources),
                "sha256": sha256(args.sources),
            },
        },
        "v4_estimand": {
            "unit": "planets per star",
            "radius_R_earth": [0.9, 1.1],
            "instellation_I_earth": [0.9, 1.1],
            "climate_intersection": "conservative Kopparapu habitable zone",
            "host_temperature_K": [5300.0, 6000.0],
            "spatial_domain_kpc": [7.0, 9.0],
        },
        "v4_posterior": {},
        "local_empirical_support": {
            "status": dr25["status"],
            "nominal_target_candidates": dr25["nominal_support"]["earth_analog_target"]["candidate_count"],
            "nominal_target_reliability_sum": dr25["nominal_support"]["earth_analog_target"]["sum_totalReliability"],
        },
        "primary_sources": sources,
        "comparison_findings": [
            "No listed literature value has the same radius, instellation, climate-intersection, host-temperature, and catalog definition as v4.",
            "The Bryson et al. (2021) Table 5 G-star values of 0.38 and 0.63 are the temperature-matched source-fidelity benchmark for the reconstructed v4 broad-HZ medians of 0.388 and 0.659; this is not independent validation.",
            "The v4 mean occurrence is numerically below broad-HZ literature estimates, as expected for its much narrower integrated phase-space box.",
            "The absence of nominal DR25 candidates in the exact v4 box prevents a direct candidate-supported interpretation.",
            "Published literature supports treating occurrence-model form and long-period extrapolation as material epistemic uncertainty not included in the v4 posterior interval.",
            "Modern age and kinematic studies do not establish a transferable correction: Dai et al. (2021) and Bashi and Zucker (2022) report conditional close-in trends, whereas Sayeed et al. (2025) find no significant overall FGK age trend.",
            "Frankel et al. (2020) show that radial migration mixes present-day radius and birth radius; the 7--9 kpc mask is therefore a present-day spatial estimand, not a birth-environment selection.",
        ],
        "prohibited_inferences": [
            "Do not call literature values inconsistent with v4 solely because their point estimates differ.",
            "Do not convert Gamma_Earth to an integrated eta value without specifying and applying an integration model.",
            "Do not describe v4 as an independent reproduction of Bryson et al. (2021).",
            "Do not treat the literature spread as a statistical confidence interval.",
            "Do not convert close-in age or kinematic trends into an HZ correction factor without a matched occurrence model and selection function.",
            "Do not interpret the present-day annulus as a sharply bounded stellar birth annulus.",
        ],
    }

    for branch in ("constant", "zero"):
        values = galactic[branch]
        comparison["v4_posterior"][branch] = {
            "mean_f_EE": values["mean_f_EE"],
            "mean_f_HZ": values["mean_f_HZ"],
            "narrow_to_broad_HZ_ratio": values["Lambda_EE_over_Lambda_HZ"],
            "Lambda_EE": values["Lambda_EE"],
        }

    constant_hz = comparison["v4_posterior"]["constant"]["mean_f_HZ"]["q50"]
    zero_hz = comparison["v4_posterior"]["zero"]["mean_f_HZ"]["q50"]
    if not 0.35 < constant_hz < 0.45:
        raise RuntimeError("Constant broad-HZ source-fidelity anchor moved")
    if not 0.55 < zero_hz < 0.75:
        raise RuntimeError("Zero broad-HZ source-fidelity anchor moved")

    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "primary_literature_comparison.json"
    csv_path = output / "primary_literature_comparison.csv"
    write_text_lf(json_path, json.dumps(comparison, indent=2) + "\n")
    with csv_path.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "key",
                "authors",
                "year",
                "doi",
                "quantity",
                "definition",
                "reported_result",
                "comparison_role",
                "comparability",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        for source in sources:
            writer.writerow({field: source[field] for field in writer.fieldnames})

    manifest = output / "SHA256SUMS_primary_literature.txt"
    write_text_lf(
        manifest,
        "".join(
            f"{sha256(path)}  {path.name}\n" for path in (csv_path, json_path)
        ),
    )
    print(json.dumps({"json": str(json_path), "sha256": sha256(json_path)}, indent=2))


if __name__ == "__main__":
    main()
