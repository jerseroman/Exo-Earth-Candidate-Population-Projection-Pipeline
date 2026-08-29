#!/usr/bin/env python3
"""Aggregate seeded Bryson hab2 posterior shards.

Every outer reliability/measurement realization contributes the same number of
post-burn samples, preserving the equal-mixture convention of the public
Bryson notebook.  The constant- and zero-completeness branches are aggregated
separately and are never merged into an implicit model-averaged posterior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from clustered_monte_carlo import (
    DETERMINISTIC_GZIP_COMPRESSION,
    cluster_bootstrap_quantile_mcse,
    contiguous_batch_quantile_mcse,
    equalize_realizations,
    quantile_summary,
)
from measurement_error import LEGACY_SOURCE_MIXTURE, MEASUREMENT_ERROR_MODES

PARAMETERS = ("F0", "alpha", "beta", "gamma")
ARCHIVED = {
    "constant": {
        "q16": [0.665, -1.934, -1.139, -4.242],
        "q50": [1.107, -1.082, -0.839, -2.671],
        "q84": [1.988, -0.142, -0.517, -1.084],
    },
    "zero": {
        "q16": [0.887, -2.048, -1.550, -3.152],
        "q50": [1.590, -1.175, -1.195, -1.376],
        "q84": [3.149, -0.219, -0.824, 0.467],
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--branch", required=True, choices=("constant", "zero"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-shards", type=int, default=8)
    parser.add_argument("--trials-per-shard", type=int, default=50)
    parser.add_argument("--walkers", type=int, default=8)
    parser.add_argument("--steps", type=int, default=2000)
    parser.add_argument("--runner-thin", type=int, default=10)
    parser.add_argument(
        "--samples-per-realization",
        type=int,
        default=None,
        help=(
            "For adaptive chains, deterministically select this many evenly "
            "spaced post-burn rows from every realization."
        ),
    )
    parser.add_argument(
        "--require-all-converged",
        action="store_true",
        help="Fail unless every adaptive realization passed its tau gates.",
    )
    parser.add_argument("--cluster-bootstrap-replicates", type=int, default=0)
    parser.add_argument("--bootstrap-seed", type=int, default=2026082101)
    parser.add_argument("--inner-chain-batches", type=int, default=0)
    parser.add_argument(
        "--expected-measurement-error-mode",
        choices=MEASUREMENT_ERROR_MODES,
        default=None,
        help="Fail unless every shard used this measurement-error mode.",
    )
    parser.add_argument(
        "--propagation-stride",
        type=int,
        default=5,
        help="Additional within-realization thinning for Galactic propagation only.",
    )
    return parser.parse_args()


def qsummary(values: np.ndarray) -> dict[str, float]:
    return quantile_summary(values)


def parse_shard(label: str) -> int:
    match = re.fullmatch(r"production-shard-(\d+)", label)
    if match is None:
        raise RuntimeError(f"Unexpected production run label: {label!r}")
    return int(match.group(1))


def resolve_measurement_error_mode(
    summaries: list[dict[str, Any]], expected_mode: str | None = None
) -> tuple[str, dict[str, Any]]:
    """Reject mixed shard modes and return their common interpretation."""

    shard_modes: set[str] = set()
    explicit_metadata: list[dict[str, Any]] = []
    for summary in summaries:
        metadata = summary.get("measurement_error")
        if metadata is None:
            mode = LEGACY_SOURCE_MIXTURE
        elif isinstance(metadata, dict) and metadata.get("mode") in MEASUREMENT_ERROR_MODES:
            mode = str(metadata["mode"])
            explicit_metadata.append(metadata)
        else:
            raise RuntimeError("Invalid measurement-error metadata in shard summary")
        shard_modes.add(mode)

    if len(shard_modes) != 1:
        raise RuntimeError(f"Cannot mix measurement-error modes: {sorted(shard_modes)}")
    mode = next(iter(shard_modes))
    if expected_mode is not None and mode != expected_mode:
        raise RuntimeError(
            f"Measurement-error mode mismatch: expected {expected_mode!r}, found {mode!r}"
        )
    if explicit_metadata:
        metadata = explicit_metadata[0]
    else:
        metadata = {
            "mode": LEGACY_SOURCE_MIXTURE,
            "metadata_inferred_from_pre_v4_shard_summaries": True,
        }
    return mode, metadata


def validate_diagnostic_modes(
    diagnostics: list[dict[str, Any]], expected_mode: str
) -> None:
    """Require trial diagnostics to agree with the shard summaries."""

    diagnostic_modes = {
        str(entry.get("measurement_error_mode", LEGACY_SOURCE_MIXTURE))
        for entry in diagnostics
    }
    if diagnostic_modes != {expected_mode}:
        raise RuntimeError(
            "Diagnostic measurement-error modes do not match shard summaries: "
            f"{sorted(diagnostic_modes)} versus {expected_mode!r}"
        )


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    chain_paths = sorted(
        root.rglob(f"joint_posterior_{args.branch}_production-shard-*.csv")
    )
    diagnostics_paths = sorted(
        root.rglob(f"trial_diagnostics_{args.branch}_production-shard-*.json")
    )
    summary_paths = sorted(
        root.rglob(f"posterior_summary_{args.branch}_production-shard-*.json")
    )
    audit_paths = sorted(
        root.rglob(f"perturbation_audit_{args.branch}_production-shard-*.csv")
    )
    if len(chain_paths) != args.expected_shards:
        raise RuntimeError(
            f"Expected {args.expected_shards} chain shards, found {len(chain_paths)}"
        )
    if len(diagnostics_paths) != args.expected_shards:
        raise RuntimeError(
            f"Expected {args.expected_shards} diagnostic shards, found {len(diagnostics_paths)}"
        )
    if len(summary_paths) != args.expected_shards:
        raise RuntimeError(
            f"Expected {args.expected_shards} summary shards, found {len(summary_paths)}"
        )

    shard_summaries: list[dict[str, Any]] = []
    for path in summary_paths:
        summary = json.loads(path.read_text(encoding="utf-8"))
        if summary.get("branch") != args.branch:
            raise RuntimeError(f"Summary branch mismatch in {path}")
        if summary.get("period_cutoff_days") is not None:
            raise RuntimeError(f"Unexpected period cutoff in {path}")
        shard_summaries.append(summary)

    measurement_error_mode, measurement_error = resolve_measurement_error_mode(
        shard_summaries, args.expected_measurement_error_mode
    )

    diagnostics: list[dict[str, Any]] = []
    for path in diagnostics_paths:
        match = re.search(r"production-shard-(\d+)", path.name)
        if match is None:
            raise RuntimeError(f"Cannot identify diagnostic shard from {path}")
        shard = int(match.group(1))
        entries = json.loads(path.read_text(encoding="utf-8"))
        for entry in entries:
            entry["shard"] = shard
            entry["global_trial"] = (
                shard * args.trials_per_shard + int(entry["trial"])
            )
            diagnostics.append(entry)
    if len(diagnostics) != args.expected_shards * args.trials_per_shard:
        raise RuntimeError(
            f"Diagnostic realization count {len(diagnostics)} is incomplete"
        )
    validate_diagnostic_modes(diagnostics, measurement_error_mode)
    adaptive_entries = [
        entry for entry in diagnostics if bool(entry.get("adaptive_production"))
    ]
    converged_count = int(
        sum(bool(entry.get("converged")) for entry in adaptive_entries)
    )
    if args.require_all_converged:
        if len(adaptive_entries) != len(diagnostics):
            raise RuntimeError(
                "--require-all-converged was requested but not every realization "
                "used adaptive production"
            )
        if converged_count != len(diagnostics):
            failed = [
                int(entry["global_trial"])
                for entry in diagnostics
                if not bool(entry.get("converged"))
            ]
            raise RuntimeError(
                f"Adaptive convergence failed for global trials {failed}"
            )

    summaries_require_audit = any(
        "perturbation_audit_file" in summary for summary in shard_summaries
    )
    if summaries_require_audit and len(audit_paths) != args.expected_shards:
        raise RuntimeError(
            f"Expected {args.expected_shards} perturbation-audit shards, "
            f"found {len(audit_paths)}"
        )
    if not summaries_require_audit and audit_paths:
        raise RuntimeError(
            "Perturbation-audit CSVs are present but shard summaries do not declare them"
        )

    full_audit_path: Path | None = None
    if summaries_require_audit:
        audit_frames: list[pd.DataFrame] = []
        for path in audit_paths:
            frame = pd.read_csv(path)
            if set(frame.branch.astype(str)) != {args.branch}:
                raise RuntimeError(f"Audit branch mismatch in {path}")
            modes = set(frame.measurement_error_mode.astype(str))
            if modes != {measurement_error_mode}:
                raise RuntimeError(
                    f"Audit measurement-error mode mismatch in {path}: {modes}"
                )
            labels = set(frame.run_label.astype(str))
            if len(labels) != 1:
                raise RuntimeError(f"Multiple audit run labels in {path}: {labels}")
            shard = parse_shard(next(iter(labels)))
            if frame.trial.nunique() != args.trials_per_shard:
                raise RuntimeError(f"Audit trial count mismatch in {path}")
            frame.insert(3, "shard", shard)
            frame.insert(5, "global_trial", shard * args.trials_per_shard + frame.trial)
            audit_frames.append(frame)
        full_audit = pd.concat(audit_frames, ignore_index=True)
        full_audit.sort_values(["global_trial", "source_row"], inplace=True)
        full_audit.reset_index(drop=True, inplace=True)
        full_audit_path = out / f"perturbation_audit_{args.branch}_full.csv.gz"
        full_audit.to_csv(
            full_audit_path,
            index=False,
            compression=DETERMINISTIC_GZIP_COMPRESSION,
        )

    fixed_samples_per_trial = args.walkers * (args.steps // args.runner_thin)
    frames: list[pd.DataFrame] = []

    for path in chain_paths:
        frame = pd.read_csv(path)
        if (
            args.samples_per_realization is None
            and len(frame) != args.trials_per_shard * fixed_samples_per_trial
        ):
            raise RuntimeError(
                f"Unexpected row count {len(frame)} in {path}; expected "
                f"{args.trials_per_shard * fixed_samples_per_trial}"
            )
        if set(frame.branch.astype(str)) != {args.branch}:
            raise RuntimeError(f"Branch mismatch in {path}")
        labels = set(frame.run_label.astype(str))
        if len(labels) != 1:
            raise RuntimeError(f"Multiple run labels in {path}: {labels}")
        label = next(iter(labels))
        shard = parse_shard(label)
        if frame.trial.nunique() != args.trials_per_shard:
            raise RuntimeError(f"Trial count mismatch in {path}")
        counts = frame.groupby("trial", sort=False).size().to_numpy()
        if args.samples_per_realization is None:
            if not np.all(counts == fixed_samples_per_trial):
                raise RuntimeError(f"Unequal mixture weights in {path}")
        elif np.any(counts < args.samples_per_realization):
            raise RuntimeError(
                f"A realization in {path} has fewer than "
                f"{args.samples_per_realization} retained MCMC rows"
            )
        frame.insert(2, "shard", shard)
        frame.insert(4, "global_trial", shard * args.trials_per_shard + frame.trial)
        frames.append(frame)

    full = pd.concat(frames, ignore_index=True)
    if full.global_trial.nunique() != args.expected_shards * args.trials_per_shard:
        raise RuntimeError("Global trial identifiers are incomplete or duplicated")
    if not np.isfinite(full.loc[:, PARAMETERS].to_numpy(dtype=float)).all():
        raise RuntimeError("Non-finite posterior values detected")

    full.sort_values(
        ["global_trial", "production_step", "walker"], inplace=True
    )
    full.reset_index(drop=True, inplace=True)
    if args.samples_per_realization is not None:
        full = equalize_realizations(
            full, "global_trial", args.samples_per_realization
        )
        samples_per_trial = args.samples_per_realization
    else:
        samples_per_trial = fixed_samples_per_trial
    expected_total = (
        args.expected_shards * args.trials_per_shard * samples_per_trial
    )
    if len(full) != expected_total:
        raise RuntimeError(f"Aggregate row count {len(full)} != {expected_total}")
    full_path = out / f"joint_posterior_{args.branch}_full.csv.gz"
    full.to_csv(
        full_path,
        index=False,
        compression=DETERMINISTIC_GZIP_COMPRESSION,
    )

    # Preserve equal representation from every outer realization when creating
    # the smaller sample file used by the Galactic propagation stage.
    within_trial_row = full.groupby("global_trial", sort=False).cumcount()
    propagation = full.loc[
        within_trial_row.mod(args.propagation_stride).eq(0)
    ].copy()
    propagation.reset_index(drop=True, inplace=True)
    expected_propagation = (
        args.expected_shards
        * args.trials_per_shard
        * int(np.ceil(samples_per_trial / args.propagation_stride))
    )
    if len(propagation) != expected_propagation:
        raise RuntimeError(
            f"Propagation sample count {len(propagation)} != {expected_propagation}"
        )
    propagation_path = out / f"joint_posterior_{args.branch}_for_galactic_propagation.csv.gz"
    propagation.loc[
        :, ["branch", "global_trial", "F0", "alpha", "beta", "gamma"]
    ].to_csv(
        propagation_path,
        index=False,
        compression=DETERMINISTIC_GZIP_COMPRESSION,
    )

    values = full.loc[:, PARAMETERS].to_numpy(dtype=float)
    quantiles = {
        name: qsummary(values[:, index])
        for index, name in enumerate(PARAMETERS)
    }
    cluster_bootstrap_mcse = None
    if args.cluster_bootstrap_replicates:
        cluster_bootstrap_mcse = cluster_bootstrap_quantile_mcse(
            full,
            PARAMETERS,
            "global_trial",
            args.cluster_bootstrap_replicates,
            args.bootstrap_seed,
        )
    inner_chain_mcse = None
    if args.inner_chain_batches:
        inner_chain_mcse = contiguous_batch_quantile_mcse(
            full,
            PARAMETERS,
            "global_trial",
            args.inner_chain_batches,
        )
    correlation = pd.DataFrame(
        np.corrcoef(values, rowvar=False), index=PARAMETERS, columns=PARAMETERS
    )
    correlation_path = out / f"joint_posterior_{args.branch}_correlation.csv"
    correlation.to_csv(correlation_path, index=True)

    archived = ARCHIVED[args.branch]
    comparison: dict[str, dict[str, float]] = {}
    for index, name in enumerate(PARAMETERS):
        comparison[name] = {
            "reconstructed_q16": quantiles[name]["q16"],
            "reconstructed_q50": quantiles[name]["q50"],
            "reconstructed_q84": quantiles[name]["q84"],
            "archived_q16_from_printed_summary": float(archived["q16"][index]),
            "archived_q50_from_printed_summary": float(archived["q50"][index]),
            "archived_q84_from_printed_summary": float(archived["q84"][index]),
            "median_difference": float(
                quantiles[name]["q50"] - archived["q50"][index]
            ),
        }

    acceptance = np.asarray(
        [entry["mean_acceptance_fraction"] for entry in diagnostics], dtype=float
    )
    runtime = np.asarray(
        [entry["runtime_seconds"] for entry in diagnostics], dtype=float
    )
    candidate_count = np.asarray(
        [entry["selected_after_domain"] for entry in diagnostics], dtype=float
    )
    optimizer_failures = int(
        sum(not bool(entry["optimizer_success"]) for entry in diagnostics)
    )

    tau_rows: list[np.ndarray] = []
    ess_rows: list[np.ndarray] = []
    for entry in diagnostics:
        tau = entry.get("autocorrelation_time")
        if tau is None:
            continue
        array = np.asarray(tau, dtype=float)
        if array.shape == (4,) and np.all(np.isfinite(array)) and np.all(array > 0):
            tau_rows.append(array)
            completed_steps = int(entry.get("production_steps_completed", args.steps))
            ess = entry.get("effective_sample_size_source_order")
            ess_array = (
                np.asarray(ess, dtype=float)
                if ess is not None
                else args.walkers * completed_steps / array
            )
            if ess_array.shape == (4,) and np.all(np.isfinite(ess_array)):
                ess_rows.append(ess_array)
    tau_summary = None
    ess_summary = None
    if tau_rows:
        tau_matrix = np.vstack(tau_rows)
        # emcee reports tau in production steps for source order
        # F0, beta_inst, alpha_radius, gamma.
        source_names = ("F0", "beta", "alpha", "gamma")
        tau_summary = {
            name: {
                "q16": float(np.quantile(tau_matrix[:, index], 0.16)),
                "q50": float(np.quantile(tau_matrix[:, index], 0.50)),
                "q84": float(np.quantile(tau_matrix[:, index], 0.84)),
            }
            for index, name in enumerate(source_names)
        }
        ess_matrix = np.vstack(ess_rows)
        ess_summary = {
            name: {
                "minimum_per_realization": float(np.min(ess_matrix[:, index])),
                "q16_per_realization": float(np.quantile(ess_matrix[:, index], 0.16)),
                "median_per_realization": float(np.median(ess_matrix[:, index])),
                "sum_over_realizations": float(np.sum(ess_matrix[:, index])),
            }
            for index, name in enumerate(source_names)
        }

    diagnostics_path = out / f"trial_diagnostics_{args.branch}_full.jsonl"
    with diagnostics_path.open("w", encoding="utf-8") as handle:
        for entry in diagnostics:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    aggregate_summary = {
        "status": (
            "new seeded no-period-cutoff reconstruction; not the missing "
            "historical Bryson chain"
        ),
        "source_repository": "stevepur/DR25-occurrence-public",
        "source_commit": "d200f54b6f0df49e0dae530e69983cdce5397bfb",
        "branch": args.branch,
        "period_cutoff_days": None,
        "measurement_error": measurement_error,
        "mixture_definition": (
            "equal number of deterministically spaced post-burn ensemble "
            "samples from every reliability and measurement-error realization"
        ),
        "parameter_order": ["F0", "alpha_radius", "beta_inst", "gamma"],
        "shards": args.expected_shards,
        "trials_per_shard": args.trials_per_shard,
        "total_trials": args.expected_shards * args.trials_per_shard,
        "walkers": args.walkers,
        "burnin_steps": int(shard_summaries[0]["burnin_steps"]),
        "production_steps_requested_minimum": args.steps,
        "production_steps_completed_q16_q50_q84": [
            float(value)
            for value in np.quantile(
                np.asarray(
                    [
                        entry.get("production_steps_completed", args.steps)
                        for entry in diagnostics
                    ],
                    dtype=float,
                ),
                [0.16, 0.50, 0.84],
            )
        ],
        "runner_thin": args.runner_thin,
        "equalized_samples_per_realization": samples_per_trial,
        "full_sample_count": int(len(full)),
        "propagation_stride_within_each_realization": args.propagation_stride,
        "galactic_propagation_sample_count": int(len(propagation)),
        "perturbation_audit_file": (
            full_audit_path.name if full_audit_path is not None else None
        ),
        "posterior_quantiles": quantiles,
        "posterior_quantile_monte_carlo_error": {
            "outer_realization_cluster_bootstrap": cluster_bootstrap_mcse,
            "outer_realization_cluster_bootstrap_replicates": (
                args.cluster_bootstrap_replicates
            ),
            "outer_realization_cluster_bootstrap_seed": args.bootstrap_seed,
            "inner_chain_contiguous_batch_mcse": inner_chain_mcse,
            "inner_chain_batches": args.inner_chain_batches,
            "interpretation": (
                "Whole outer realizations, not posterior rows, are resampled. "
                "The separate contiguous-block estimate diagnoses residual "
                "within-chain Monte Carlo error while retaining every outer realization."
            ),
        },
        "comparison_with_archived_printed_marginal_summary": comparison,
        "correlation_matrix_file": correlation_path.name,
        "diagnostics": {
            "optimizer_failures": optimizer_failures,
            "acceptance_fraction_q16_q50_q84": [
                float(value)
                for value in np.quantile(acceptance, [0.16, 0.50, 0.84])
            ],
            "runtime_seconds_per_realization_q16_q50_q84": [
                float(value)
                for value in np.quantile(runtime, [0.16, 0.50, 0.84])
            ],
            "candidate_count_q16_q50_q84": [
                float(value)
                for value in np.quantile(candidate_count, [0.16, 0.50, 0.84])
            ],
            "realizations_with_estimable_autocorrelation": len(tau_rows),
            "adaptive_realizations": len(adaptive_entries),
            "adaptive_realizations_converged": converged_count,
            "autocorrelation_time_by_source_parameter": tau_summary,
            "estimated_chain_ess_by_source_parameter": ess_summary,
        },
        "scientific_limits": [
            "This is a new reproducible rerun, not the unavailable historical chain.",
            "Each outer realization has its own conditional posterior; the pooled result is a mixture.",
            "The completeness branches remain separate model scenarios.",
            "Host-model and transport systematics are not included in these occurrence-only intervals.",
        ],
    }
    summary_path = out / f"joint_posterior_{args.branch}_aggregate_summary.json"
    summary_path.write_text(
        json.dumps(aggregate_summary, indent=2), encoding="utf-8"
    )

    manifest_targets = [
        full_path,
        propagation_path,
        correlation_path,
        diagnostics_path,
        summary_path,
    ]
    if full_audit_path is not None:
        manifest_targets.append(full_audit_path)
    manifest_path = out / f"SHA256SUMS_{args.branch}_aggregate.txt"
    manifest_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in manifest_targets),
        encoding="utf-8",
    )
    print(json.dumps(aggregate_summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
