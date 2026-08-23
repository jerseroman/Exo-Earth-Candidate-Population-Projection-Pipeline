#!/usr/bin/env python3
"""Generate fresh standalone vector figures from frozen v4 audit artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import numpy as np
import pandas as pd


BLUE = "#1769AA"
ORANGE = "#D97706"
GREEN = "#15803D"
RED = "#B91C1C"
PURPLE = "#7E22CE"
GRAY = "#64748B"
LIGHT = "#CBD5E1"

# Frozen reproducibility timestamp, not a claim about the wall-clock rerun time.
REPRODUCIBLE_TIMESTAMP = dt.datetime(2026, 8, 23, tzinfo=dt.timezone.utc)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pdf_metadata(title: str, subject: str) -> dict[str, object]:
    return {
        "Title": title,
        "Author": "Roman Jerše",
        "Subject": subject,
        "Keywords": "ExoEarth, Kepler DR25, occurrence rate, Milky Way",
        "Creator": "research/v4-validation/make_v4_figures.py",
        "CreationDate": REPRODUCIBLE_TIMESTAMP,
        "ModDate": REPRODUCIBLE_TIMESTAMP,
    }


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9,
            "axes.titlesize": 10,
            "axes.labelsize": 9,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 8,
            "figure.titlesize": 11,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "axes.grid.axis": "x",
            "grid.alpha": 0.22,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.bbox": "tight",
        }
    )


def draw_interval(ax: plt.Axes, row: pd.Series, y: float, color: str) -> None:
    ax.hlines(y, row["q2.5"], row["q97.5"], color=LIGHT, linewidth=7, zorder=1)
    ax.hlines(y, row["q16"], row["q84"], color=color, linewidth=4, zorder=2)
    ax.plot(row["q50"], y, marker="o", color="white", markeredgecolor=color,
            markeredgewidth=2, markersize=7, zorder=3)


def posterior_figure(quantiles_path: Path, output: Path) -> None:
    data = pd.read_csv(quantiles_path)
    quantile_columns = ["q2.5", "q16", "q50", "q84", "q97.5"]
    occurrence = (
        data[data["quantity"] == "mean_f_EE"]
        .set_index("branch")[quantile_columns]
        .mul(100.0)
    )
    counts = (
        data[data["quantity"] == "Lambda_EE"]
        .set_index("branch")[quantile_columns]
        .div(1_000_000.0)
    )
    branches = [("constant", "Constant completeness", BLUE), ("zero", "Zero completeness", ORANGE)]

    fig, axes = plt.subplots(1, 2, figsize=(7.3, 3.15), constrained_layout=True)
    for ax, frame, title, xlabel in (
        (axes[0], occurrence, "Narrow-domain occurrence", "Expected planets per 100 stars"),
        (axes[1], counts, "7-9 kpc population expectation", "Expected planets (millions)"),
    ):
        for y, (branch, _, color) in zip((1.0, 0.0), branches):
            draw_interval(ax, frame.loc[branch], y, color)
        ax.set_yticks([1.0, 0.0], [label for _, label, _ in branches])
        ax.set_title(title, loc="left", fontweight="bold")
        ax.set_xlabel(xlabel)
        ax.set_ylim(-0.55, 1.55)
        ax.axvline(0.0, color="#0F172A", linewidth=0.7)

    axes[0].set_xlim(0.0, 6.5)
    axes[1].set_xlim(0.0, 17.0)
    fig.suptitle("Corrected v4 posterior: median, 68%, and 95% intervals", x=0.02,
                 ha="left", fontweight="bold")
    fig.text(0.02, -0.01, "Pale: 95% posterior interval   Dark: 68% posterior interval   Circle: median",
             fontsize=8, color="#334155")
    fig.savefig(
        output,
        format="pdf",
        metadata=pdf_metadata(
            "Corrected v4 posterior intervals",
            "Frozen posterior intervals for occurrence and Galactic population expectation",
        ),
    )
    plt.close(fig)


def dr25_support_figure(near_path: Path, frequency_path: Path, output: Path) -> None:
    near = pd.read_csv(near_path)
    frequency = pd.read_csv(frequency_path)
    radius_mask = near["radius_0p9_1p1"].astype(bool)
    hz_mask = near["conservative_hz_instellation_intersection"].astype(bool)

    fig, axes = plt.subplots(1, 2, figsize=(7.3, 3.45), constrained_layout=True)
    ax = axes[0]
    ax.scatter(
        near.loc[radius_mask, "gaia_iso_prad"],
        near.loc[radius_mask, "gaia_iso_insol"],
        s=24,
        facecolor=BLUE,
        edgecolor="white",
        linewidth=0.4,
        alpha=0.80,
        label="Radius-near candidates (n=54)",
    )
    ax.scatter(
        near.loc[hz_mask, "gaia_iso_prad"],
        near.loc[hz_mask, "gaia_iso_insol"],
        s=42,
        marker="D",
        facecolor=ORANGE,
        edgecolor="white",
        linewidth=0.5,
        label="Conservative-HZ candidates (n=3)",
    )
    ax.add_patch(Rectangle((0.9, 0.9), 0.2, 0.2, facecolor=GREEN, edgecolor=GREEN,
                           alpha=0.25, linewidth=1.5))
    ax.set_yscale("log")
    ax.set_xlim(0.82, 3.65)
    ax.set_ylim(0.7, 6000)
    ax.set_xlabel(r"Planet radius ($R_\oplus$)")
    ax.set_ylabel(r"Instellation ($I_\oplus$)")
    ax.set_title("Nominal DR25 near-support set", loc="left", fontweight="bold")
    ax.legend(loc="upper right", frameon=False)

    zoom = axes[1]
    zoom.set_xlim(0.84, 1.60)
    zoom.set_ylim(0.75, 1.25)
    zoom.add_patch(Rectangle((0.9, 0.9), 0.2, 0.2, facecolor=GREEN, edgecolor=GREEN,
                             alpha=0.20, linewidth=1.8))
    in_zoom = (
        near["gaia_iso_prad"].between(0.84, 1.60)
        & near["gaia_iso_insol"].between(0.75, 1.25)
    )
    zoom.scatter(
        near.loc[in_zoom, "gaia_iso_prad"],
        near.loc[in_zoom, "gaia_iso_insol"],
        s=50,
        marker="D",
        facecolor=ORANGE,
        edgecolor="white",
        linewidth=0.6,
    )
    entrant_rows = frequency.drop_duplicates("kepoi_name")
    for _, row in entrant_rows.iterrows():
        zoom.scatter(row["nominal_radius"], row["nominal_flux"], s=60, facecolor="none",
                     edgecolor=RED, linewidth=1.4, zorder=4)
        zoom.annotate(
            row["kepoi_name"],
            (row["nominal_radius"], row["nominal_flux"]),
            xytext=(5, 7),
            textcoords="offset points",
            fontsize=7.5,
            color=RED,
        )
    zoom.text(1.0, 1.0, "0 nominal\ncandidates", ha="center", va="center",
              color=GREEN, fontweight="bold", fontsize=8)
    zoom.set_xlabel(r"Planet radius ($R_\oplus$)")
    zoom.set_ylabel(r"Instellation ($I_\oplus$)")
    zoom.set_title("Exact target neighborhood", loc="left", fontweight="bold")
    zoom.text(
        0.02,
        0.02,
        "Green box: fixed 0.9-1.1 domain;\ntarget is additionally climate-clipped.",
        transform=zoom.transAxes,
        va="bottom",
        fontsize=7.2,
        color="#334155",
    )

    fig.suptitle("Direct DR25 support audit for the v4 target", x=0.02, ha="left",
                 fontweight="bold")
    fig.savefig(
        output,
        format="pdf",
        metadata=pdf_metadata(
            "DR25 local-support audit",
            "Nominal Kepler DR25 support near the v4 Earth-analog target",
        ),
    )
    plt.close(fig)


def sensitivity_figure(register_path: Path, output: Path) -> None:
    data = pd.read_csv(register_path)
    selected_labels = {
        "legacy measurement-error propagation": "Legacy measurement propagation",
        "zero versus constant completeness": "Zero vs. constant completeness",
        "legacy fixed-logg selector (constant)": "Legacy host selector (constant)",
        "native solar curve without the 5200 K anchor": "Native TAMS without 5200 K anchor",
        "radial grid 0.5 to 0.25 kpc": "Radial grid: 0.5 to 0.25 kpc",
        "Bryson Model 2 versus Model 1": "Occurrence Model 2 vs. Model 1",
        "runaway-greenhouse flux scale 0.95": "Inner HZ flux x0.95",
        "runaway-greenhouse flux scale 1.05": "Inner HZ flux x1.05",
        "Kopparapu runaway boundary for 0.1 Earth masses": "0.1 Earth-mass HZ prescription",
        "Kopparapu runaway boundary for 5 Earth masses": "5 Earth-mass HZ prescription",
        "optimistic versus conservative HZ": "Optimistic vs. conservative HZ",
        "JJ-weighted versus uniform 5300--6000 K average": "JJ vs. uniform temperature weighting",
    }
    frame = data[data["sensitivity"].isin(selected_labels)].copy()
    frame["label"] = frame["sensitivity"].map(selected_labels)
    ordered = list(selected_labels)
    frame["order"] = frame["sensitivity"].map({value: idx for idx, value in enumerate(ordered)})
    frame = frame.sort_values("order", ascending=False)

    status_colors = {
        "PASS": GREEN,
        "PASS_SENSITIVITY": GREEN,
        "SCENARIO_NOT_INTERVAL": ORANGE,
        "MODEL_SENSITIVITY": RED,
        "POINT_ESTIMATE_ONLY": PURPLE,
        "NUMERICAL_PERTURBATION": BLUE,
        "ALTERNATIVE_PRESCRIPTION": PURPLE,
        "ALTERNATIVE_ESTIMAND": PURPLE,
    }
    colors = [status_colors.get(status, GRAY) for status in frame["status"]]

    fig = plt.figure(figsize=(7.5, 6.7), constrained_layout=True)
    grid = fig.add_gridspec(2, 1, height_ratios=[5.2, 1.2])
    ax = fig.add_subplot(grid[0])
    y = range(len(frame))
    ax.axvline(0.0, color="#0F172A", linewidth=0.9)
    ax.hlines(y, 0.0, frame["percent_change"], color=colors, linewidth=2.2)
    ax.scatter(frame["percent_change"], y, color=colors, s=38, zorder=3)
    for yi, value in zip(y, frame["percent_change"]):
        ax.annotate(
            f"{value:+.2f}%",
            (value, yi),
            xytext=(5, 0),
            textcoords="offset points",
            va="center",
            ha="left",
            fontsize=7.5,
            bbox={"facecolor": "white", "edgecolor": "none", "alpha": 0.82, "pad": 0.4},
        )
    ax.set_yticks(list(y), frame["label"])
    ax.set_xlim(-65, 50)
    ax.set_xlabel(r"Change in $\Lambda_{\rm EE}$ relative to stated reference (%)")
    ax.set_title("One-at-a-time checks, scenarios, and alternative prescriptions",
                 loc="left", fontweight="bold")

    spatial = data[data["category"] == "spatial domain"].copy()
    spatial["label"] = spatial["sensitivity"].replace(
        {
            "Broad solar annulus 6-10 kpc": "6-10 kpc domain",
            "Full JJ disk 4-14 kpc": "4-14 kpc domain",
        }
    )
    ax2 = fig.add_subplot(grid[1])
    sy = range(len(spatial))
    ax2.barh(list(sy), spatial["percent_change"], color=PURPLE, height=0.45)
    for yi, value in zip(sy, spatial["percent_change"]):
        ax2.text(value + 6, yi, f"{value:+.1f}%", va="center", fontsize=8)
    ax2.set_yticks(list(sy), spatial["label"])
    ax2.set_xlim(0, 400)
    ax2.set_xlabel("Change from redefining the spatial estimand (%)")
    ax2.set_title("Alternative spatial estimands (not uncertainty intervals)",
                  loc="left", fontweight="bold")

    fig.suptitle("Frozen v4 sensitivity register", x=0.01, ha="left", fontweight="bold")
    fig.text(
        0.01,
        -0.01,
        "Categorical findings: direct local DR25 support = ABSENT; metallicity-dependent TAMS test = EXCLUDED.",
        color=RED,
        fontsize=8,
        fontweight="bold",
    )
    fig.savefig(
        output,
        format="pdf",
        metadata=pdf_metadata(
            "Frozen v4 sensitivity register",
            "Audited sensitivity checks and alternative estimands for the v4 ExoEarth projection",
        ),
    )
    plt.close(fig)


def load_occurrence_model(root: Path) -> Any:
    module_path = (
        root
        / "research"
        / "bryson-joint-posterior"
        / "propagate_hab2_joint_posterior.py"
    )
    module_dir = str(module_path.parent)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    spec = importlib.util.spec_from_file_location("v4_occurrence_model", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load occurrence model: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inner_target_crossing_k(model: Any) -> float:
    """Solve the 1-Earth-mass runaway-greenhouse crossing S_eff = 1.1."""
    def residual(teff: float) -> float:
        return float(model.seff(np.asarray([teff]), model.RUNAWAY_1MEARTH)[0] - 1.1)

    lower, upper = 5300.0, 6000.0
    f_lower, f_upper = residual(lower), residual(upper)
    if f_lower * f_upper >= 0.0:
        raise RuntimeError("HZ crossing is not bracketed over 5300--6000 K")
    for _ in range(80):
        midpoint = 0.5 * (lower + upper)
        f_midpoint = residual(midpoint)
        if f_lower * f_midpoint <= 0.0:
            upper, f_upper = midpoint, f_midpoint
        else:
            lower, f_lower = midpoint, f_midpoint
    return 0.5 * (lower + upper)


def deterministic_outer_subsample(
    draws_path: Path,
    samples_per_outer_realization: int = 128,
) -> pd.DataFrame:
    columns = ["global_trial", "F0", "alpha", "beta", "gamma"]
    draws = pd.read_csv(draws_path, usecols=columns)
    counts = draws.groupby("global_trial", sort=True).size()
    if len(counts) != 400 or counts.nunique() != 1 or int(counts.iloc[0]) != 512:
        raise RuntimeError(f"Unexpected equalized posterior layout in {draws_path}")
    selected = []
    for _, group in draws.groupby("global_trial", sort=True):
        indices = np.linspace(
            0,
            len(group) - 1,
            samples_per_outer_realization,
            dtype=int,
        )
        selected.append(group.iloc[indices])
    frame = pd.concat(selected, ignore_index=True)
    selected_counts = frame.groupby("global_trial").size()
    if not np.all(selected_counts.to_numpy() == samples_per_outer_realization):
        raise RuntimeError("Plotting subsample does not preserve equal outer weights")
    return frame


def occurrence_curve_quantiles(
    samples: pd.DataFrame,
    teff: np.ndarray,
    model: Any,
) -> dict[str, np.ndarray]:
    f0 = samples.F0.to_numpy(dtype=float)[:, None]
    alpha = samples.alpha.to_numpy(dtype=float)[:, None]
    beta = samples.beta.to_numpy(dtype=float)[:, None]
    gamma = samples.gamma.to_numpy(dtype=float)[:, None]
    temperature = teff[None, :]

    geometric = np.where(
        temperature <= model.TEFF_BREAK,
        model.TEFF_COEFFICIENT[0] * temperature ** model.TEFF_EXPONENT[0],
        model.TEFF_COEFFICIENT[1] * temperature ** model.TEFF_EXPONENT[1],
    )
    temperature_factor = (
        geometric
        * np.power(temperature, gamma)
        / model.temperature_normalization(gamma)
    )
    radius_denominator = model.power_integral(
        model.SOURCE_RADIUS[0], model.SOURCE_RADIUS[1], alpha
    )
    radius_hz = model.power_integral(0.5, 1.5, alpha) / radius_denominator
    radius_ee = model.power_integral(0.9, 1.1, alpha) / radius_denominator

    inner = model.seff(teff, model.RUNAWAY_1MEARTH)
    outer = model.seff(teff, model.MAXIMUM_GREENHOUSE)
    instellation_denominator = model.power_integral(
        model.SOURCE_INSTELLATION[0], model.SOURCE_INSTELLATION[1], beta
    )
    instellation_hz = (
        model.power_integral(outer[None, :], inner[None, :], beta)
        / instellation_denominator
    )
    lower_ee = np.maximum(0.9, outer)
    upper_ee = np.minimum(1.1, inner)
    instellation_ee = np.where(
        upper_ee[None, :] > lower_ee[None, :],
        model.power_integral(lower_ee[None, :], upper_ee[None, :], beta)
        / instellation_denominator,
        0.0,
    )
    curves = {
        "f_HZ": f0 * radius_hz * temperature_factor * instellation_hz,
        "f_EE": f0 * radius_ee * temperature_factor * instellation_ee,
    }
    return {
        f"{name}_{label}": values
        for name, curve in curves.items()
        for label, values in zip(
            ("q16", "q50", "q84"),
            np.quantile(curve, (0.16, 0.50, 0.84), axis=0),
        )
    }


def hz_boundary_figure(root: Path, output: Path) -> None:
    model = load_occurrence_model(root)
    teff = np.linspace(5300.0, 6000.0, 351)
    inner = model.seff(teff, model.RUNAWAY_1MEARTH)
    outer = model.seff(teff, model.MAXIMUM_GREENHOUSE)
    target_lower = np.maximum(0.9, outer)
    target_upper = np.minimum(1.1, inner)
    valid = target_upper > target_lower
    crossing_teff = inner_target_crossing_k(model)

    fig, ax = plt.subplots(figsize=(7.3, 3.55), constrained_layout=True)
    ax.fill_between(teff, outer, inner, color=BLUE, alpha=0.13, label="Conservative HZ")
    ax.plot(teff, inner, color=RED, linewidth=2.0, label="Runaway greenhouse (inner)")
    ax.plot(teff, outer, color=BLUE, linewidth=2.0, label="Maximum greenhouse (outer)")
    ax.fill_between(
        teff,
        target_lower,
        target_upper,
        where=valid,
        color=GREEN,
        alpha=0.38,
        label="Climate-clipped 0.9-1.1 target",
    )
    ax.axhline(0.9, color=GREEN, linestyle="--", linewidth=1.0)
    ax.axhline(1.1, color=GREEN, linestyle="--", linewidth=1.0)
    ax.axvline(crossing_teff, color=GRAY, linestyle=":", linewidth=1.0)
    ax.annotate(
        rf"$S_{{\rm in}}=1.1$ at {crossing_teff:.1f} K",
        (crossing_teff, 1.1),
        xytext=(-112, 22),
        textcoords="offset points",
        arrowprops={"arrowstyle": "->", "color": GRAY, "linewidth": 0.8},
        fontsize=8,
        color="#334155",
    )
    ax.set_xlim(5300, 6000)
    ax.set_ylim(0.28, 1.20)
    ax.set_xlabel(r"Stellar effective temperature $T_{\rm eff}$ (K)")
    ax.set_ylabel(r"Effective stellar flux $S_{\rm eff}/S_\oplus$")
    ax.set_title("Conservative habitable-zone boundaries and narrow target", loc="left", fontweight="bold")
    ax.grid(axis="both", alpha=0.22)
    ax.legend(loc="center left", bbox_to_anchor=(0.01, 0.57), frameon=False)
    fig.savefig(
        output,
        format="pdf",
        metadata=pdf_metadata(
            "Conservative habitable-zone boundaries",
            "Kopparapu conservative HZ boundaries and climate-clipped v4 target",
        ),
    )
    plt.close(fig)


def occurrence_teff_figure(
    root: Path,
    constant_draws: Path,
    zero_draws: Path,
    output: Path,
) -> None:
    model = load_occurrence_model(root)
    teff = np.linspace(5300.0, 6000.0, 141)
    branches = {
        "constant": (
            deterministic_outer_subsample(constant_draws),
            "Constant completeness",
            BLUE,
        ),
        "zero": (
            deterministic_outer_subsample(zero_draws),
            "Zero completeness",
            ORANGE,
        ),
    }
    summaries = {
        branch: occurrence_curve_quantiles(samples, teff, model)
        for branch, (samples, _, _) in branches.items()
    }
    crossing_teff = inner_target_crossing_k(model)

    fig, axes = plt.subplots(1, 2, figsize=(7.3, 3.55), constrained_layout=True)
    for ax, quantity, title, ylabel in (
        (axes[0], "f_HZ", r"Broad conservative-HZ occurrence", r"$f_{\rm HZ}(T)$ (planets per star)"),
        (axes[1], "f_EE", r"Narrow-domain occurrence", r"$f_{\rm EE}(T)$ (planets per star)"),
    ):
        for branch, (_, label, color) in branches.items():
            summary = summaries[branch]
            ax.fill_between(
                teff,
                summary[f"{quantity}_q16"],
                summary[f"{quantity}_q84"],
                color=color,
                alpha=0.20,
            )
            ax.plot(teff, summary[f"{quantity}_q50"], color=color, linewidth=2.0, label=label)
        ax.set_xlim(5300, 6000)
        ax.set_xlabel(r"$T_{\rm eff}$ (K)")
        ax.set_ylabel(ylabel)
        ax.set_title(title, loc="left", fontweight="bold")
        ax.grid(axis="both", alpha=0.22)
        ax.set_ylim(bottom=0.0)
    axes[1].axvline(crossing_teff, color=GRAY, linestyle=":", linewidth=1.0)
    axes[0].legend(frameon=False, loc="upper left")
    fig.suptitle("Temperature-dependent occurrence from the frozen corrected posterior", x=0.02, ha="left", fontweight="bold")
    fig.text(
        0.02,
        -0.01,
        "Lines: posterior median. Bands: central 68%. Deterministic 128-draw subsample from each of 400 equally weighted outer realizations per branch.",
        fontsize=7.5,
        color="#334155",
    )
    fig.savefig(
        output,
        format="pdf",
        metadata=pdf_metadata(
            "Temperature-dependent occurrence posterior",
            "Frozen v4 f_HZ(T) and f_EE(T) posterior medians and 68 percent bands",
        ),
    )
    plt.close(fig)


def radial_annulus_figure(radial_path: Path, output: Path) -> None:
    radial = pd.read_csv(radial_path)
    required = {"R_kpc", "B_N", "B_L2"}
    if not required.issubset(radial.columns):
        raise RuntimeError(f"Radial input lacks {sorted(required - set(radial.columns))}")

    fig, axes = plt.subplots(1, 2, figsize=(7.3, 3.35), constrained_layout=True)
    panels = (
        (axes[0], radial["B_N"] / 1.0e8, BLUE, r"Selected-host intensity", r"$\mathrm{d}N_\star/\mathrm{d}R$ ($10^8$ stars kpc$^{-1}$)"),
        (axes[1], radial["B_L2"] / 1.0e6, GREEN, r"Point-vector ExoEarth intensity", r"$\mathrm{d}\Lambda_{\rm EE}/\mathrm{d}R$ ($10^6$ planets kpc$^{-1}$)"),
    )
    for ax, values, color, title, ylabel in panels:
        ax.axvspan(7.0, 9.0, color=ORANGE, alpha=0.18, label="Adopted 7-9 kpc annulus")
        ax.plot(radial["R_kpc"], values, color=color, marker="o", markersize=3.2, linewidth=1.8)
        ax.set_xlim(4.0, 14.0)
        ax.set_ylim(bottom=0.0)
        ax.set_xlabel(r"Galactocentric radius $R_{\rm GC}$ (kpc)")
        ax.set_ylabel(ylabel)
        ax.set_title(title, loc="left", fontweight="bold")
        ax.grid(axis="both", alpha=0.22)
    axes[0].legend(frameon=False, loc="upper right")
    fig.suptitle("Frozen JJ/PARSEC/TAMS radial structure across 4-14 kpc", x=0.02, ha="left", fontweight="bold")
    fig.text(
        0.02,
        -0.01,
        "The right panel uses the archived constant-completeness point vector only to show radial shape; it is not a posterior interval.",
        fontsize=7.5,
        color="#334155",
    )
    fig.savefig(
        output,
        format="pdf",
        metadata=pdf_metadata(
            "Radial host and ExoEarth intensity",
            "JJ host and point-vector ExoEarth radial intensity with the 7-9 kpc annulus highlighted",
        ),
    )
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    output = (args.out or root / "outputs" / "figures").resolve()
    output.mkdir(parents=True, exist_ok=True)
    configure_style()

    figure_names = [
        "v4_posterior_intervals.pdf",
        "v4_dr25_local_support.pdf",
        "v4_hz_boundaries.pdf",
        "v4_occurrence_vs_teff.pdf",
        "v4_radial_annulus.pdf",
        "v4_sensitivity_register.pdf",
    ]
    figures = [output / name for name in figure_names]
    baseline_dir = (
        root
        / "local-artifacts"
        / "v4"
        / "statistical-baseline-reaudit-20260822"
    )
    constant_draws = (
        baseline_dir
        / "constant-galactic"
        / "galactic_posterior_draws_constant.csv.gz"
    )
    zero_draws = (
        baseline_dir
        / "zero-galactic"
        / "galactic_posterior_draws_zero.csv.gz"
    )
    radial = root / "local-artifacts" / "v4" / "host-canonical" / "tams_ab_radial.csv"
    required_inputs = [constant_draws, zero_draws, radial]
    missing = [str(path) for path in required_inputs if not path.is_file()]
    if missing:
        raise RuntimeError(f"Missing frozen figure inputs: {missing}")

    posterior_figure(
        root / "research" / "bryson-joint-posterior" / "frozen-v4" / "v4_galactic_quantiles.csv",
        figures[0],
    )
    dr25_support_figure(
        root / "research" / "v4-validation" / "frozen-dr25-support" / "dr25_nominal_near_support.csv",
        root / "research" / "v4-validation" / "frozen-dr25-support" / "dr25_perturbed_candidate_frequency.csv",
        figures[1],
    )
    hz_boundary_figure(root, figures[2])
    occurrence_teff_figure(root, constant_draws, zero_draws, figures[3])
    radial_annulus_figure(radial, figures[4])
    sensitivity_figure(
        root / "research" / "v4-validation" / "frozen-sensitivities" / "v4_sensitivity_register.csv",
        figures[5],
    )
    for figure in figures:
        if not figure.is_file() or figure.stat().st_size < 10_000:
            raise RuntimeError(f"Figure was not created correctly: {figure}")
    manifest = output / "SHA256SUMS_figures.txt"
    with manifest.open("w", encoding="utf-8", newline="\n") as handle:
        for figure in figures:
            handle.write(f"{sha256(figure)}  {figure.name}\n")

    baseline_audit_path = (
        root
        / "research"
        / "v4-validation"
        / "frozen-statistical-baseline"
        / "V4_STATISTICAL_BASELINE_AUDIT.json"
    )
    baseline_audit = json.loads(baseline_audit_path.read_text(encoding="utf-8"))
    source_inputs = {
        "posterior_quantiles": root / "research" / "bryson-joint-posterior" / "frozen-v4" / "v4_galactic_quantiles.csv",
        "dr25_nominal_near_support": root / "research" / "v4-validation" / "frozen-dr25-support" / "dr25_nominal_near_support.csv",
        "dr25_perturbed_candidate_frequency": root / "research" / "v4-validation" / "frozen-dr25-support" / "dr25_perturbed_candidate_frequency.csv",
        "sensitivity_register": root / "research" / "v4-validation" / "frozen-sensitivities" / "v4_sensitivity_register.csv",
        "constant_equalized_galactic_draws": constant_draws,
        "zero_equalized_galactic_draws": zero_draws,
        "canonical_radial_profile": radial,
        "occurrence_propagation_model": root / "research" / "bryson-joint-posterior" / "propagate_hab2_joint_posterior.py",
    }
    provenance = {
        "schema_version": 1,
        "status": "PASS",
        "reproducible_timestamp_utc": REPRODUCIBLE_TIMESTAMP.isoformat().replace("+00:00", "Z"),
        "method": "Six standalone vector PDFs generated directly by the plotting script; no PDF-page cropping or extraction.",
        "plotting_script": {
            "path": str(Path(__file__).resolve().relative_to(root)).replace("\\", "/"),
            "sha256": sha256(Path(__file__).resolve()),
        },
        "temperature_curve_sampling": {
            "method": "Deterministic equally spaced row indices within every equalized outer realization",
            "outer_realizations_per_branch": 400,
            "available_draws_per_outer_realization": 512,
            "selected_draws_per_outer_realization": 128,
            "selected_draws_per_branch": 51_200,
            "interval": "central 68 percent (q16-q84)",
        },
        "statistical_baseline": {
            "label": baseline_audit["baseline_label"],
            "audit_sha256": sha256(baseline_audit_path),
            "actions_runs": {
                key: value["id"]
                for key, value in baseline_audit["actions_runs"].items()
            },
            "selected_artifacts": {
                key: {
                    "run_id": value["run_id"],
                    "artifact_id": value["artifact_id"],
                    "github_archive_digest": value["github_archive_digest"],
                }
                for key, value in baseline_audit["selected_artifacts"].items()
            },
        },
        "inputs": {
            name: {
                "path": str(path.relative_to(root)).replace("\\", "/"),
                "sha256": sha256(path),
            }
            for name, path in source_inputs.items()
        },
        "figures": {
            figure.name: {
                "path": str(figure.relative_to(root)).replace("\\", "/"),
                "sha256": sha256(figure),
                "bytes": figure.stat().st_size,
            }
            for figure in figures
        },
    }
    (output / "V4_FIGURE_PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print("\n".join(f"{figure.name}: {sha256(figure)}" for figure in figures))


if __name__ == "__main__":
    main()
