#!/usr/bin/env python3
"""Equal-mixture sampling and cluster-aware Monte Carlo diagnostics."""
from __future__ import annotations

from typing import Any, Iterable

import numpy as np
import pandas as pd

DETERMINISTIC_GZIP_COMPRESSION = {
    "method": "gzip",
    "compresslevel": 9,
    "mtime": 0,
}

QUANTILE_NAMES = ("q2.5", "q16", "q50", "q84", "q97.5")
QUANTILE_PROBABILITIES = np.array([0.025, 0.16, 0.50, 0.84, 0.975])


def equalize_realizations(
    frame: pd.DataFrame,
    cluster_column: str,
    samples_per_realization: int,
) -> pd.DataFrame:
    """Select deterministic, evenly spaced rows from every realization."""

    if samples_per_realization <= 0:
        raise ValueError("samples_per_realization must be positive")
    selected: list[pd.DataFrame] = []
    for _, group in frame.groupby(cluster_column, sort=True):
        count = len(group)
        if count < samples_per_realization:
            raise ValueError(
                f"Realization contains {count} rows; need {samples_per_realization}"
            )
        positions = np.floor(
            (np.arange(samples_per_realization, dtype=float) + 0.5)
            * count
            / samples_per_realization
        ).astype(int)
        selected.append(group.iloc[positions].copy())
    result = pd.concat(selected, ignore_index=True)
    counts = result.groupby(cluster_column, sort=False).size().to_numpy()
    if not np.all(counts == samples_per_realization):
        raise RuntimeError("Equal-mixture selection produced unequal cluster sizes")
    return result


def _integer_weighted_quantiles(
    sorted_values: np.ndarray,
    sorted_cluster_codes: np.ndarray,
    cluster_multiplicities: np.ndarray,
    probabilities: np.ndarray,
) -> np.ndarray:
    """Match NumPy linear quantiles after integer-weight cluster replication."""

    weights = cluster_multiplicities[sorted_cluster_codes]
    cumulative = np.cumsum(weights, dtype=np.int64)
    total = int(cumulative[-1])
    ranks = (total - 1) * probabilities
    lower_rank = np.floor(ranks).astype(np.int64)
    upper_rank = np.ceil(ranks).astype(np.int64)
    lower_index = np.searchsorted(cumulative, lower_rank + 1, side="left")
    upper_index = np.searchsorted(cumulative, upper_rank + 1, side="left")
    fraction = ranks - lower_rank
    return (
        sorted_values[lower_index] * (1.0 - fraction)
        + sorted_values[upper_index] * fraction
    )


def cluster_bootstrap_quantile_mcse(
    frame: pd.DataFrame,
    value_columns: Iterable[str],
    cluster_column: str,
    replicates: int,
    seed: int,
) -> dict[str, dict[str, dict[str, float]]]:
    """Resample whole realizations and estimate finite-outer-sample quantile SE."""

    if replicates < 2:
        raise ValueError("At least two cluster-bootstrap replicates are required")
    cluster_codes, labels = pd.factorize(frame[cluster_column], sort=True)
    cluster_count = len(labels)
    if cluster_count < 2:
        raise ValueError("At least two realization clusters are required")
    counts = np.bincount(cluster_codes)
    if not np.all(counts == counts[0]):
        raise ValueError("Cluster bootstrap requires equal realization weights")

    rng = np.random.RandomState(seed)
    multiplicities = rng.multinomial(
        cluster_count,
        np.full(cluster_count, 1.0 / cluster_count),
        size=replicates,
    )
    output: dict[str, dict[str, dict[str, float]]] = {}
    for column in value_columns:
        values = frame[column].to_numpy(dtype=float)
        order = np.argsort(values, kind="mergesort")
        sorted_values = values[order]
        sorted_codes = cluster_codes[order]
        bootstrap = np.empty((replicates, len(QUANTILE_PROBABILITIES)))
        for index in range(replicates):
            bootstrap[index, :] = _integer_weighted_quantiles(
                sorted_values,
                sorted_codes,
                multiplicities[index],
                QUANTILE_PROBABILITIES,
            )
        column_result: dict[str, dict[str, float]] = {}
        for index, name in enumerate(QUANTILE_NAMES):
            column_result[name] = {
                "standard_error": float(np.std(bootstrap[:, index], ddof=1)),
                "bootstrap_q2.5": float(np.quantile(bootstrap[:, index], 0.025)),
                "bootstrap_q97.5": float(np.quantile(bootstrap[:, index], 0.975)),
            }
        output[column] = column_result
    return output


def contiguous_batch_quantile_mcse(
    frame: pd.DataFrame,
    value_columns: Iterable[str],
    cluster_column: str,
    batches: int,
) -> dict[str, dict[str, float]]:
    """Estimate inner-chain quantile MCSE from matched contiguous chain blocks."""

    if batches < 2:
        raise ValueError("At least two inner-chain batches are required")
    counts = frame.groupby(cluster_column, sort=True).size().to_numpy()
    if len(counts) < 2 or not np.all(counts == counts[0]):
        raise ValueError("Inner-chain batches require equal realization weights")
    if counts[0] < batches or counts[0] % batches:
        raise ValueError("Samples per realization must be divisible by batches")

    working = frame.copy()
    within = working.groupby(cluster_column, sort=False).cumcount().to_numpy()
    block_size = counts[0] // batches
    working["_inner_batch"] = within // block_size

    output: dict[str, dict[str, float]] = {}
    for column in value_columns:
        batch_estimates = np.vstack(
            [
                np.quantile(group[column].to_numpy(dtype=float), QUANTILE_PROBABILITIES)
                for _, group in working.groupby("_inner_batch", sort=True)
            ]
        )
        output[column] = {
            name: float(np.std(batch_estimates[:, index], ddof=1) / np.sqrt(batches))
            for index, name in enumerate(QUANTILE_NAMES)
        }
    return output


def quantile_summary(values: np.ndarray) -> dict[str, float]:
    quantiles = np.quantile(np.asarray(values, dtype=float), QUANTILE_PROBABILITIES)
    return {
        name: float(value) for name, value in zip(QUANTILE_NAMES, quantiles)
    }
