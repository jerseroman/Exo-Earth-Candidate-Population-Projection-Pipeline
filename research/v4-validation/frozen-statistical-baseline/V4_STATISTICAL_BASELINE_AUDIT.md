# V4 statistical baseline audit

**Status: PASS.** This is an independent verification of the selected
downloaded GitHub Actions artifacts. No MCMC or propagation result was
recomputed or changed.

## Selected production lineage

- Constant branch: 400 converged realizations from the successful constant
  aggregate job inside Actions run `32472776218`. The workflow itself is
  correctly recorded as failed because its zero aggregate failed the original
  20,000-step ceiling; that failed zero artifact is excluded.
- Zero branch: 400 converged realizations from the clean 30,000-step-ceiling
  rerun `32506666772`, with identical seeds and unchanged convergence gates.
- Constant Galactic propagation: run `32527877921`.
- Seed-family pilot: run `32470830404`.

## Frozen provenance

- Source Actions repository: `jerseroman/are-we-alone-in-the-universe`.
- Run-provenance record: `provenance/RUN_PROVENANCE.json`.
- Source checkout before this audit: `950e762c4a6bcdc066bacb2e399742dea8c3ee54`.
- Committed numerical-freeze record SHA-256: `a4ce3d7f9f3ad0c35c33df6ae24e9457e5f88d2d90d36c196f7aea253d7ca6ea`.
- GitHub Actions evidence snapshot SHA-256: `727d7c5bd9ab7eccd14f99173ddeaa6832c68f882e3e375e193c1b21ee601783`.

| Selected artifact | Run ID | Artifact ID | GitHub archive SHA-256 |
|---|---:|---:|---|
| constant_seed_stability | 32470830404 | 9443107354 | `fcfe785dde462ce9ab800480e43ca2bb5e9a2eb9898e1dc7c1c8834300723f70` |
| zero_seed_stability | 32470830404 | 9443107657 | `cf8f5a54e8b3267bf541e74324d00b31ce6ffb9ef93ed81d522ec7800122d872` |
| constant_posterior | 32472776218 | 9454764527 | `6fbd662da9376e360e45c925f4e78bdeb58a5e2f5420a3ca725683a3a56ee37a` |
| zero_posterior | 32506666772 | 9462011443 | `aebdc142b0bda3fe74542052ebbd7ac2f03f3857d8680ba51dd7e3f8453f6016` |
| constant_galactic | 32527877921 | 9462827799 | `d99906b4117740cc8c679be2026b5761410931336e8ab522c83609990c73d1a0` |
| zero_galactic | 32506666772 | 9462029866 | `2051314d6da5f92bdffcfe9d1334f2d8fc9e0d6281a06bff720fab3fa71f2cdb` |

| Branch | Aggregate summary SHA-256 | Galactic summary SHA-256 | Seed-stability SHA-256 |
|---|---|---|---|
| constant | `8472f8b8a431d3e9a3f8fded5b40b8bab6f1f8e2d2368e44bc6816e716d960b1` | `5ff8de0d86c62c71c10b80cb9356df48abbe21f773a9c84f7ea67fe8a0f12945` | `04584e9fb72994bfb36dc15d5446372bbe5b4d2f5f40b677736b2e37d22acdde` |
| zero | `37217bf026addf201c3f46354324b55c2bbcb9afb1b28f86197a98fcc79bc85c` | `86752103927ddb8bccb45c047ee55b1deeed10b7f621255f7756da1786b1f73c` | `ae22c55ea2c9eddd830c165f05c22646f4edd398505662af3eb07f82f63f4156` |

## Reproduced gates

| Branch | Converged | Step min/median/max | Minimum ESS | Largest parameter outer MCSE | Largest Galactic outer MCSE |
|---|---:|---:|---:|---:|---:|
| constant | 400/400 | 8000/12000/17000 | 1682.3 | 1.634% | 1.478% |
| zero | 400/400 | 9000/14000/22000 | 1662.4 | 1.559% | 1.615% |

All 800 selected realizations therefore pass the declared adaptive
convergence gate. This statement refers to 400 constant realizations from
the successful constant artifact plus 400 zero realizations from the
successful extended rerun; it does not describe run `32472776218` as a
globally successful workflow.

## Headline medians

| Branch | N_star | median mean f_EE | product Lambda_EE | Reported |
|---|---:|---:|---:|---:|
| constant | 263061992.36670703 | 0.012255079394085128 | 3223845.6020202106 | 3.224 million |
| zero | 263061992.36670703 | 0.017381670273021337 | 4572456.8126821574 | 4.572 million |

The values 3.224 million and 4.572 million are direct rounded products
of the frozen 7--9 kpc host count and the corresponding branch-specific
posterior median mean occurrence. They are not newly fitted values.

## Freeze rule

These audited artifacts are the v4 statistical baseline. Manuscript,
figure, bibliography, and production changes must not alter the frozen
CSV/JSON values. Any numerical change requires a new statistical rerun, a
new audit record, and a new release candidate.
