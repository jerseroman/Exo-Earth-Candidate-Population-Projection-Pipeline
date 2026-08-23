#!/usr/bin/env python3
"""Convergence control shared by the Bryson v4 MCMC runner and tests."""
from __future__ import annotations

from typing import Any

import numpy as np


def tau_convergence_status(
    tau: np.ndarray,
    steps: int,
    previous_tau: np.ndarray | None,
    tau_multiple: float,
    relative_tolerance: float,
) -> dict[str, Any]:
    """Assess emcee's chain-length and successive-tau convergence checks."""

    tau = np.asarray(tau, dtype=float)
    valid = bool(
        tau.shape == (4,) and np.all(np.isfinite(tau)) and np.all(tau > 0.0)
    )
    if not valid:
        return {
            "valid": False,
            "length_ok": False,
            "stable": False,
            "max_relative_tau_change": None,
        }

    length_ok = bool(np.all(steps >= tau_multiple * tau))
    stable = False
    max_relative_change: float | None = None
    if previous_tau is not None:
        previous_tau = np.asarray(previous_tau, dtype=float)
        if (
            previous_tau.shape == tau.shape
            and np.all(np.isfinite(previous_tau))
            and np.all(previous_tau > 0.0)
        ):
            relative_change = np.abs(tau - previous_tau) / tau
            max_relative_change = float(np.max(relative_change))
            stable = bool(max_relative_change <= relative_tolerance)

    return {
        "valid": True,
        "length_ok": length_ok,
        "stable": stable,
        "max_relative_tau_change": max_relative_change,
    }


def run_production_chain(
    sampler: Any,
    state: Any,
    *,
    minimum_steps: int,
    adaptive: bool,
    maximum_steps: int,
    check_interval: int,
    tau_multiple: float,
    relative_tolerance: float,
    required_stable_checks: int,
) -> tuple[Any, list[float] | None, bool, list[dict[str, Any]]]:
    """Run a fixed or convergence-controlled production chain."""

    if not adaptive:
        final_state = sampler.run_mcmc(state, minimum_steps, progress=False)
        try:
            tau = [float(value) for value in sampler.get_autocorr_time(tol=0)]
        except Exception:
            tau = None
        return final_state, tau, False, []

    checks: list[dict[str, Any]] = []
    previous_tau: np.ndarray | None = None
    stable_streak = 0
    converged = False
    final_state = state

    while sampler.iteration < maximum_steps:
        remaining = maximum_steps - sampler.iteration
        chunk = min(check_interval, remaining)
        final_state = sampler.run_mcmc(final_state, chunk, progress=False)
        completed = int(sampler.iteration)
        if completed < minimum_steps:
            continue

        try:
            current_tau = np.asarray(sampler.get_autocorr_time(tol=0), dtype=float)
        except Exception:
            current_tau = np.full(4, np.nan, dtype=float)
        status = tau_convergence_status(
            current_tau,
            completed,
            previous_tau,
            tau_multiple,
            relative_tolerance,
        )
        if status["valid"] and status["length_ok"] and status["stable"]:
            stable_streak += 1
        else:
            stable_streak = 0
        checks.append(
            {
                "production_steps": completed,
                "autocorrelation_time": (
                    [float(value) for value in current_tau]
                    if status["valid"]
                    else None
                ),
                "length_ok": status["length_ok"],
                "stable": status["stable"],
                "max_relative_tau_change": status["max_relative_tau_change"],
                "stable_check_streak": stable_streak,
            }
        )
        if stable_streak >= required_stable_checks:
            converged = True
            break
        if status["valid"]:
            previous_tau = current_tau

    final_tau: list[float] | None = None
    if checks and checks[-1]["autocorrelation_time"] is not None:
        final_tau = list(checks[-1]["autocorrelation_time"])
    else:
        try:
            final_tau = [
                float(value) for value in sampler.get_autocorr_time(tol=0)
            ]
        except Exception:
            final_tau = None
    return final_state, final_tau, converged, checks
