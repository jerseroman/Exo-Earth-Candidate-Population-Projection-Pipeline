#!/usr/bin/env python3
"""Reviewable Bryson Model-1 and Kopparapu occurrence reference functions."""

from __future__ import annotations

import numpy as np


F0 = 1.107
ALPHA = -1.082
BETA = -0.839
GAMMA = -2.671
T0 = 3900.0
T_BREAK = 5117.0
T1 = 6300.0
RUNAWAY_GREENHOUSE = (1.107, 1.332e-4, 1.58e-8, -8.308e-12, -1.931e-15)
MAXIMUM_GREENHOUSE = (0.356, 6.171e-5, 1.698e-9, -3.198e-12, -5.575e-16)


def power_integral(lower: float, upper: float, exponent: float) -> float:
    return (upper ** (exponent + 1.0) - lower ** (exponent + 1.0)) / (
        exponent + 1.0
    )


RADIUS_FIT = power_integral(0.5, 2.5, ALPHA)
INSTELLATION_FIT = power_integral(0.2, 2.2, BETA)
Q1 = GAMMA + 3.16
Q2 = GAMMA + 4.49
GEOMETRIC_MEAN = (
    10.0 ** (-11.839) * power_integral(T0, T_BREAK, Q1)
    + 10.0 ** (-16.769) * power_integral(T_BREAK, T1, Q2)
) / (T1 - T0)
NORMALIZATION = 1.0 / (RADIUS_FIT * INSTELLATION_FIT * GEOMETRIC_MEAN)
RADIUS_HZ = power_integral(0.5, 1.5, ALPHA)
RADIUS_EARTH10 = power_integral(0.9, 1.1, ALPHA)


def hz_edges(teff: np.ndarray | float) -> tuple[np.ndarray, np.ndarray]:
    temperature = np.asarray(teff, dtype=float)
    offset = temperature - 5780.0
    inner = sum(
        coefficient * offset**power
        for power, coefficient in enumerate(RUNAWAY_GREENHOUSE)
    )
    outer = sum(
        coefficient * offset**power
        for power, coefficient in enumerate(MAXIMUM_GREENHOUSE)
    )
    return outer, inner


def occurrence_prefactor(teff: np.ndarray | float) -> np.ndarray:
    temperature = np.asarray(teff, dtype=float)
    geometric = np.where(
        temperature <= T_BREAK,
        10.0 ** (-11.839) * temperature**3.16,
        10.0 ** (-16.769) * temperature**4.49,
    )
    return F0 * NORMALIZATION * temperature**GAMMA * geometric


def f_hz(teff: np.ndarray | float) -> np.ndarray:
    outer, inner = hz_edges(teff)
    instellation = (inner ** (BETA + 1.0) - outer ** (BETA + 1.0)) / (
        BETA + 1.0
    )
    return occurrence_prefactor(teff) * RADIUS_HZ * instellation


def f_earth10(teff: np.ndarray | float) -> np.ndarray:
    outer, inner = hz_edges(teff)
    lower = np.maximum(0.9, outer)
    upper = np.minimum(1.1, inner)
    instellation = np.where(
        upper > lower,
        (upper ** (BETA + 1.0) - lower ** (BETA + 1.0)) / (BETA + 1.0),
        0.0,
    )
    return occurrence_prefactor(teff) * RADIUS_EARTH10 * instellation
