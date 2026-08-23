#!/usr/bin/env python3
"""Unit tests for adaptive emcee convergence control."""
from __future__ import annotations

import unittest

import numpy as np

from mcmc_convergence import run_production_chain, tau_convergence_status


class FakeSampler:
    def __init__(self, tau_by_iteration: dict[int, list[float]]) -> None:
        self.iteration = 0
        self.tau_by_iteration = tau_by_iteration

    def run_mcmc(self, state, steps: int, progress: bool = False):
        del progress
        self.iteration += steps
        return {"iteration": self.iteration, "previous": state}

    def get_autocorr_time(self, tol: int = 0):
        del tol
        return np.asarray(self.tau_by_iteration[self.iteration], dtype=float)


class ConvergenceTests(unittest.TestCase):
    def test_tau_gate_requires_length_and_successive_stability(self) -> None:
        first = np.array([20.0, 21.0, 22.0, 23.0])
        status = tau_convergence_status(first, 2500, None, 100.0, 0.05)
        self.assertTrue(status["length_ok"])
        self.assertFalse(status["stable"])

        second = np.array([20.2, 21.1, 21.8, 23.2])
        status = tau_convergence_status(second, 2500, first, 100.0, 0.05)
        self.assertTrue(status["length_ok"])
        self.assertTrue(status["stable"])

    def test_adaptive_chain_stops_after_two_stable_checks(self) -> None:
        sampler = FakeSampler(
            {
                1000: [8.0, 8.5, 9.0, 9.5],
                2000: [8.1, 8.6, 9.1, 9.4],
                3000: [8.0, 8.7, 9.0, 9.5],
            }
        )
        _, tau, converged, checks = run_production_chain(
            sampler,
            state=None,
            minimum_steps=1000,
            adaptive=True,
            maximum_steps=5000,
            check_interval=1000,
            tau_multiple=100.0,
            relative_tolerance=0.05,
            required_stable_checks=2,
        )
        self.assertTrue(converged)
        self.assertEqual(sampler.iteration, 3000)
        self.assertEqual(len(checks), 3)
        self.assertEqual(checks[-1]["stable_check_streak"], 2)
        self.assertEqual(tau, [8.0, 8.7, 9.0, 9.5])

    def test_adaptive_chain_reports_nonconvergence_at_maximum(self) -> None:
        sampler = FakeSampler(
            {
                1000: [50.0, 50.0, 50.0, 50.0],
                2000: [60.0, 60.0, 60.0, 60.0],
            }
        )
        _, _, converged, checks = run_production_chain(
            sampler,
            state=None,
            minimum_steps=1000,
            adaptive=True,
            maximum_steps=2000,
            check_interval=1000,
            tau_multiple=100.0,
            relative_tolerance=0.05,
            required_stable_checks=1,
        )
        self.assertFalse(converged)
        self.assertFalse(checks[-1]["length_ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
