# SPDX-FileCopyrightText: Copyright holders of stevepur/DR25-occurrence-public
# SPDX-FileCopyrightText: 2026 Roman Jerše
# SPDX-License-Identifier: GPL-2.0-only
#
# Derived from the Bryson DR25 occurrence implementation identified in
# MODIFICATIONS_BRYSON.md. Roman Jerše's modifications remain under GPL-2.0-only.
# Modified by Roman Jerše on 2026-08-21; see MODIFICATIONS_BRYSON.md.
"""Measurement-error propagation for the Bryson hab2 reconstruction.

Two deliberately separate modes are provided:

``legacy_source_mixture``
    Reproduces the public notebook's random-number consumption and perturbation
    equations exactly.  Because the selected Gaussian deviate retains its sign,
    this is a symmetric mixture of two Gaussian scales rather than a two-sided
    asymmetric distribution.  It also preserves the notebook's omission of the
    post-perturbation effective-temperature domain filter.

``quantile_matched_two_sided``
    Chooses the lower or upper side with equal probability and multiplies the
    side-specific scale by ``abs(Z)`` for ``Z ~ Normal(0, 1)``.  It therefore
    has Q_0.158655 = mu - sigma_minus, Q_0.5 = mu, and
    Q_0.841345 = mu + sigma_plus.  All three source-domain cuts are reapplied
    after perturbation.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Sequence

import numpy as np
import pandas as pd

LEGACY_SOURCE_MIXTURE = "legacy_source_mixture"
QUANTILE_MATCHED_TWO_SIDED = "quantile_matched_two_sided"
MEASUREMENT_ERROR_MODES = (
    LEGACY_SOURCE_MIXTURE,
    QUANTILE_MATCHED_TWO_SIDED,
)


@dataclass(frozen=True)
class PerturbationResult:
    """Retained likelihood sample plus a complete post-perturbation audit."""

    retained: pd.DataFrame
    audit: pd.DataFrame
    counts: dict[str, int]


def _float_vector(name: str, values: Sequence[float] | np.ndarray) -> np.ndarray:
    vector = np.asarray(values, dtype=float)
    if vector.ndim != 1:
        raise ValueError(f"{name} must be one-dimensional, got shape {vector.shape}")
    return vector


def draw_asymmetric_measurement(
    nominal: Sequence[float] | np.ndarray,
    sigma_minus: Sequence[float] | np.ndarray,
    sigma_plus: Sequence[float] | np.ndarray,
    rng: Any,
    mode: str,
) -> np.ndarray:
    """Draw one perturbed value per row under the selected propagation mode.

    The order and number of calls to ``rng.rand`` and ``rng.randn`` intentionally
    match the public notebook in legacy mode.  ``rng`` may be NumPy's module-level
    random API or a ``RandomState`` instance.
    """

    if mode not in MEASUREMENT_ERROR_MODES:
        raise ValueError(
            f"Unknown measurement-error mode {mode!r}; expected one of "
            f"{MEASUREMENT_ERROR_MODES}"
        )

    center = _float_vector("nominal", nominal)
    lower = _float_vector("sigma_minus", sigma_minus)
    upper = _float_vector("sigma_plus", sigma_plus)
    if not (len(center) == len(lower) == len(upper)):
        raise ValueError("nominal, sigma_minus, and sigma_plus must have equal length")

    if mode == QUANTILE_MATCHED_TWO_SIDED:
        for name, scale in (("sigma_minus", lower), ("sigma_plus", upper)):
            if np.any(np.isfinite(scale) & (scale < 0.0)):
                raise ValueError(f"{name} contains a negative finite uncertainty")

    plus = rng.rand(len(center)) > 0.5
    minus = ~plus
    plus_noise = rng.randn(int(np.sum(plus)))
    minus_noise = rng.randn(int(np.sum(minus)))
    if mode == QUANTILE_MATCHED_TWO_SIDED:
        plus_noise = np.abs(plus_noise)
        minus_noise = np.abs(minus_noise)

    perturbed = np.zeros(len(center), dtype=float)
    perturbed[plus] = center[plus] + upper[plus] * plus_noise
    perturbed[minus] = center[minus] - lower[minus] * minus_noise
    return perturbed


def perturb_planets(
    all_kois: pd.DataFrame,
    rng: Any,
    instellation_range: tuple[float, float],
    radius_range: tuple[float, float],
    teff_range: tuple[float, float],
    period_max_days: float | None,
    mode: str,
) -> PerturbationResult:
    """Reliability-resample, perturb, domain-filter, and audit planet rows."""

    if mode not in MEASUREMENT_ERROR_MODES:
        raise ValueError(
            f"Unknown measurement-error mode {mode!r}; expected one of "
            f"{MEASUREMENT_ERROR_MODES}"
        )

    selected_mask = rng.rand(len(all_kois)) < all_kois.totalReliability.to_numpy(
        dtype=float
    )
    selected = all_kois.loc[selected_mask].copy()

    flux = draw_asymmetric_measurement(
        selected.gaia_iso_insol.to_numpy(dtype=float),
        selected.gaia_iso_insol_errm.to_numpy(dtype=float),
        selected.gaia_iso_insol_errp.to_numpy(dtype=float),
        rng,
        mode,
    )
    radius = draw_asymmetric_measurement(
        selected.gaia_iso_prad.to_numpy(dtype=float),
        selected.gaia_iso_prad_errm.to_numpy(dtype=float),
        selected.gaia_iso_prad_errp.to_numpy(dtype=float),
        rng,
        mode,
    )
    teff = draw_asymmetric_measurement(
        selected.teff.to_numpy(dtype=float),
        selected.teff_err2.to_numpy(dtype=float),
        selected.teff_err1.to_numpy(dtype=float),
        rng,
        mode,
    )

    instellation_ok = (
        np.isfinite(flux)
        & (instellation_range[0] <= flux)
        & (flux <= instellation_range[1])
    )
    radius_ok = (
        np.isfinite(radius)
        & (radius_range[0] <= radius)
        & (radius <= radius_range[1])
    )
    teff_ok = (
        np.isfinite(teff)
        & (teff_range[0] <= teff)
        & (teff <= teff_range[1])
    )
    period_ok = np.ones(len(selected), dtype=bool)
    if period_max_days is not None:
        period = selected.koi_period.to_numpy(dtype=float)
        period_ok = np.isfinite(period) & (period <= period_max_days)

    active_domain = instellation_ok & radius_ok
    if mode == QUANTILE_MATCHED_TWO_SIDED:
        active_domain &= teff_ok
    retained_mask = active_domain & period_ok

    selected["perturbed_flux"] = flux
    selected["perturbed_radius"] = radius
    selected["perturbed_teff"] = teff
    retained = selected.loc[retained_mask].copy()

    preferred_columns = [
        "source_row",
        "kepoi_name",
        "kepid_x",
        "totalReliability",
        "koi_period",
        "gaia_iso_insol",
        "gaia_iso_insol_errm",
        "gaia_iso_insol_errp",
        "gaia_iso_prad",
        "gaia_iso_prad_errm",
        "gaia_iso_prad_errp",
        "teff",
        "teff_err2",
        "teff_err1",
        "perturbed_flux",
        "perturbed_radius",
        "perturbed_teff",
    ]
    audit = selected[[name for name in preferred_columns if name in selected]].copy()
    audit["instellation_in_source_domain"] = instellation_ok
    audit["radius_in_source_domain"] = radius_ok
    audit["teff_in_source_domain"] = teff_ok
    audit["period_passes_optional_cutoff"] = period_ok
    audit["teff_filter_active"] = mode == QUANTILE_MATCHED_TWO_SIDED
    audit["retained_by_active_policy"] = retained_mask

    reasons: list[str] = []
    for flux_pass, radius_pass, teff_pass, period_pass, retained_pass in zip(
        instellation_ok, radius_ok, teff_ok, period_ok, retained_mask
    ):
        row_reasons: list[str] = []
        if not flux_pass:
            row_reasons.append("instellation_outside_source_domain")
        if not radius_pass:
            row_reasons.append("radius_outside_source_domain")
        if not teff_pass:
            if mode == QUANTILE_MATCHED_TWO_SIDED:
                row_reasons.append("teff_outside_source_domain")
            else:
                row_reasons.append("teff_outside_source_domain_not_filtered_in_legacy")
        if not period_pass:
            row_reasons.append("period_above_optional_cutoff")
        if retained_pass and not row_reasons:
            row_reasons.append("retained")
        reasons.append(";".join(row_reasons))
    audit["audit_status"] = reasons

    all_three_ok = instellation_ok & radius_ok & teff_ok
    counts = {
        "n_catalog_rows": int(len(all_kois)),
        "n_reliability_selected_before_domain": int(len(selected)),
        "n_outside_instellation_source_domain": int(np.sum(~instellation_ok)),
        "n_outside_radius_source_domain": int(np.sum(~radius_ok)),
        "n_outside_teff_source_domain": int(np.sum(~teff_ok)),
        "n_outside_any_of_three_source_domains": int(np.sum(~all_three_ok)),
        "n_failing_optional_period_cutoff": int(np.sum(~period_ok)),
        "n_retained_by_active_policy": int(np.sum(retained_mask)),
        "n_retained_with_teff_outside_source_domain": int(
            np.sum(retained_mask & ~teff_ok)
        ),
    }
    return PerturbationResult(retained=retained, audit=audit, counts=counts)


def measurement_error_metadata(mode: str) -> dict[str, Any]:
    """Machine-readable interpretation of a propagation mode."""

    if mode not in MEASUREMENT_ERROR_MODES:
        raise ValueError(
            f"Unknown measurement-error mode {mode!r}; expected one of "
            f"{MEASUREMENT_ERROR_MODES}"
        )
    one_sigma_lower = 0.5 * math.erfc(1.0 / math.sqrt(2.0))
    if mode == LEGACY_SOURCE_MIXTURE:
        return {
            "mode": mode,
            "distribution": "equal-weight symmetric two-scale Gaussian mixture",
            "source_faithful": True,
            "post_perturbation_teff_filter": False,
            "warning": (
                "The selected Gaussian deviate retains both signs, so the branch "
                "label does not constrain the perturbation to that side of the median."
            ),
        }
    return {
        "mode": mode,
        "distribution": "equal-side-probability two-sided half-normal",
        "source_faithful": False,
        "post_perturbation_teff_filter": True,
        "construction": (
            "B~Bernoulli(0.5), U=abs(Z), Z~Normal(0,1); "
            "X=mu-sigma_minus*U if B=0, else mu+sigma_plus*U"
        ),
        "target_quantiles": {
            "lower_probability": one_sigma_lower,
            "lower_value": "mu-sigma_minus",
            "median_probability": 0.5,
            "median_value": "mu",
            "upper_probability": 1.0 - one_sigma_lower,
            "upper_value": "mu+sigma_plus",
        },
    }
