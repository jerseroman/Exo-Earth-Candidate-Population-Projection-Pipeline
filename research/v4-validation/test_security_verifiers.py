#!/usr/bin/env python3
"""Adversarial regression tests for the release security verifiers."""

from __future__ import annotations

import contextlib
import hashlib
import io
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import verify_dependency_lock as dependency  # noqa: E402
from scripts import verify_workflow_security as workflow  # noqa: E402


class MemoryText:
    def __init__(self, text: str):
        self.text = text

    def read_text(self, encoding: str = "utf-8") -> str:
        return self.text


def workflow_text(step: str) -> str:
    return (
        "on: {workflow_dispatch: null}\n"
        "jobs:\n"
        "  audit:\n"
        "    runs-on: ubuntu-22.04\n"
        "    steps:\n"
        f"      - {step}\n"
    )


def command(body: str, *, working_directory: str | None = None) -> workflow.ShellCommand:
    return workflow.ShellCommand(
        run_line=1,
        body_start_line=1,
        scalar_style="|",
        body=body,
        step_name="synthetic",
        working_directory=working_directory,
    )


class WorkflowSecurityTests(unittest.TestCase):
    def test_current_repository_policy_passes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            workflow.main()

    def test_jj_audit_workflows_pin_and_validate_runner_parallelism(self) -> None:
        cases = {
            ".github/workflows/jj-tams-radial-convergence.yml": (
                '"$rundir/parameters"',
                "python research/jj-tams-convergence/tams_radial_convergence.py",
            ),
            ".github/workflows/jj-tams-metallicity-differential.yml": (
                "/tmp/jj-diff/parameters",
                "python research/jj-host-export/run_jj_export.py",
            ),
        }
        substitution_prefix = (
            r"sed -E -i 's/^(nprocess[[:space:]]+)4([[:space:]])/\12\2/' "
        )
        guard_prefix = r"grep -Eq '^nprocess[[:space:]]+2[[:space:]]' "

        for relative_path, (parameters, jj_command) in cases.items():
            with self.subTest(workflow=relative_path):
                text = (ROOT / relative_path).read_text(encoding="utf-8")
                substitution = substitution_prefix + parameters
                guard = guard_prefix + parameters
                self.assertEqual(text.count(substitution), 1)
                self.assertEqual(text.count(guard), 1)
                self.assertLess(text.index(substitution), text.index(guard))
                self.assertLess(text.index(guard), text.index(jj_command))
                self.assertIn("nprocess=2", text)

    def test_quoted_and_flow_run_forms_are_audited(self) -> None:
        cases = (
            '"run": python -m pip install evil',
            "{run: python -m pip install evil}",
        )
        for case in cases:
            with self.subTest(case=case):
                parsed = workflow.parse_workflow_text(workflow_text(case))
                self.assertEqual(len(parsed.commands), 1)
                with self.assertRaises(SystemExit):
                    workflow.audit_shell_command(Path("synthetic.yml"), parsed.commands[0])

    def test_ambiguous_yaml_constructs_are_rejected(self) -> None:
        cases = (
            (
                "anchor",
                "x: &bad python -m pip install evil\n"
                + workflow_text("run: *bad"),
            ),
            (
                "duplicate",
                workflow_text("run: echo safe\n        run: echo duplicate"),
            ),
            (
                "merge",
                workflow_text("<<: {run: echo hidden}"),
            ),
            (
                "tag",
                workflow_text("run: !custom echo hidden"),
            ),
            (
                "multiple-documents",
                workflow_text("run: echo safe") + "---\n{}\n",
            ),
        )
        for name, text in cases:
            with self.subTest(name=name), self.assertRaises(SystemExit):
                workflow.parse_workflow_text(text, name)

    def test_github_expression_in_shell_is_rejected(self) -> None:
        parsed = workflow.parse_workflow_text(
            workflow_text('run: echo "${{ github.event.pull_request.title }}"')
        )
        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(Path("synthetic.yml"), parsed.commands[0])

    def test_unapproved_input_taint_and_pip_environment_are_rejected(self) -> None:
        text = (
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      cmd: {required: true, type: string}\n"
            "jobs:\n"
            "  audit:\n"
            "    runs-on: ubuntu-22.04\n"
            "    steps:\n"
            "      - env:\n"
            "          CMD: ${{ inputs.cmd }}\n"
            "        run: echo \"$CMD\"\n"
        )
        parsed = workflow.parse_workflow_text(text)
        with self.assertRaises(SystemExit):
            workflow.validate_workflow_environment(
                Path("synthetic.yml"), parsed.data, set()
            )
        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(
                Path("synthetic.yml"), command("PIP_INDEX_URL=https://example.invalid\ntrue")
            )

    def test_pip_install_profiles_are_exact(self) -> None:
        allowed = (
            "--require-hashes --only-binary=:all: -r requirements.txt",
            "--only-binary=:all: --require-hashes --requirement=./requirements.txt",
            "--no-deps --no-build-isolation -e .",
        )
        rejected = (
            "--require-hashes -r requirements.txt",
            "--only-binary=:all: -r requirements.txt",
            "--no-deps -e .",
            "--no-build-isolation -e .",
            "--require-hashes --only-binary=:all: -r requirements.txt evil",
        )
        for arguments in allowed:
            with self.subTest(allowed=arguments):
                self.assertTrue(workflow._locked_pip_install(arguments)[0])
        for arguments in rejected:
            with self.subTest(rejected=arguments):
                self.assertFalse(workflow._locked_pip_install(arguments)[0])

    def test_dynamic_and_wrong_directory_installs_are_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(
                Path("synthetic.yml"), command('CMD=pip\n"$CMD" install evil')
            )
        locked = (
            "python -m pip install --only-binary=:all: --require-hashes "
            "-r requirements.txt"
        )
        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(
                Path("synthetic.yml"), command(locked, working_directory="/tmp")
            )
        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(
                Path("synthetic.yml"), command("echo before\n" + locked)
            )
        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(
                Path("synthetic.yml"), command(locked + " || true")
            )
        self.assertEqual(
            workflow.audit_shell_command(Path("synthetic.yml"), command(locked)),
            1,
        )

    def test_fail_fast_shell_semantics_are_immutable(self) -> None:
        unsafe_shell_bodies = (
            "set +e\ntrue",
            "set +x\ntrue",
            "set +o errexit\ntrue",
            "trap 'true' ERR\ntrue",
        )
        for body in unsafe_shell_bodies:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.audit_shell_command(Path("synthetic.yml"), command(body))

        unsafe_workflows = (
            workflow_text('shell: "bash {0}"\n        run: echo unsafe'),
            workflow_text("continue-on-error: true\n        run: echo unsafe"),
            *(
                workflow_text(
                    f"env: {{{key}: /tmp/unsafe}}\n        run: echo unsafe"
                )
                for key in sorted(workflow.FORBIDDEN_SHELL_ENV_KEYS)
            ),
        )
        for text in unsafe_workflows:
            with self.subTest(text=text), self.assertRaises(SystemExit):
                parsed = workflow.parse_workflow_text(text)
                workflow.validate_workflow_environment(
                    Path("synthetic.yml"), parsed.data, set()
                )

        approved = workflow.parse_workflow_text(
            workflow_text(
                'shell: "bash --noprofile --norc -e -o pipefail {0}"\n'
                "        continue-on-error: false\n"
                "        run: echo safe"
            )
        )
        workflow.validate_workflow_environment(
            Path("synthetic.yml"), approved.data, set()
        )

    def test_protected_python_script_paths_are_exact(self) -> None:
        for expected in sorted(workflow.PROTECTED_PYTHON_SCRIPTS):
            with self.subTest(expected=expected):
                matches = workflow._matching_python_invocations(
                    [command(f"python {expected}")], expected
                )
                self.assertEqual(len(matches), 1)
                workspace_matches = workflow._matching_python_invocations(
                    [command(f'python "$GITHUB_WORKSPACE/{expected}"')], expected
                )
                self.assertEqual(len(workspace_matches), 1)
            protected_name = expected.rsplit("/", 1)[-1]
            unsafe_paths = (f"/tmp/{protected_name}", f"../{expected}")
            for unsafe in unsafe_paths:
                with (
                    self.subTest(expected=expected, unsafe=unsafe),
                    self.assertRaises(SystemExit),
                ):
                    workflow._matching_python_invocations(
                        [command(f"python {unsafe}")], expected
                    )

    def test_action_policy_covers_steps_and_reusable_jobs(self) -> None:
        checkout = "actions/checkout@" + workflow.PINNED_ACTIONS["actions/checkout"]
        observed = workflow.validate_action_uses(
            Path("synthetic.yml"), [workflow.ActionUse(1, checkout)]
        )
        self.assertEqual(observed, {"actions/checkout"})
        rejected = (
            "actions/checkout@main",
            "owner/unreviewed@" + "a" * 40,
            "./local-action",
            "docker://image:latest",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                workflow.validate_action_uses(
                    Path("synthetic.yml"), [workflow.ActionUse(1, value)]
                )
        parsed = workflow.parse_workflow_text(
            "on: {workflow_dispatch: null}\n"
            "jobs:\n"
            "  delegated:\n"
            "    uses: owner/repo/.github/workflows/x.yml@main\n"
        )
        self.assertEqual(len(parsed.actions), 1)
        with self.assertRaises(SystemExit):
            workflow.validate_action_uses(Path("synthetic.yml"), parsed.actions)

    def test_inert_or_suppressed_runner_guards_are_rejected(self) -> None:
        runner = (
            "python research/bryson-joint-posterior/run_hab2_joint_posterior.py "
            "--run-status production_candidate"
        )
        rejected = (
            "echo " + runner,
            "if false; then\n  " + runner + "\nfi",
            "guard() {\n  " + runner + "\n}",
            runner + " || true",
            "python - <<'PY'\n" + runner + "\nPY",
        )
        for body in rejected:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.require_production_candidate_status(
                    Path("synthetic.yml"), [command(body)]
                )
        workflow.require_production_candidate_status(
            Path("synthetic.yml"), [command(runner)]
        )

    def test_acceptance_profile_and_guard_order_are_required(self) -> None:
        aggregate = (
            "python research/bryson-joint-posterior/aggregate_hab2_joint_posterior.py "
            "--expected-shards 16 --trials-per-shard 25 --walkers 16 --steps 3000 "
            "--runner-thin 20 --samples-per-realization 1024 --require-all-converged "
            "--minimum-ess-per-realization 1000 --cluster-bootstrap-replicates 1000 "
            "--inner-chain-batches 8 --maximum-outer-q50-mcse-fraction 0.10 "
            "--maximum-inner-q50-mcse-fraction 0.05 "
            f"--expected-bryson-source-sha256 {workflow.BRYSON_SOURCE_SHA256}"
        )
        path = Path("bryson-v4-corrected-production.yml")
        with self.assertRaises(SystemExit):
            workflow.require_production_aggregate_profile(path, [command(aggregate)])
        workflow.require_production_aggregate_profile(
            path,
            [command(aggregate + " --acceptance-profile v4.0.4-production")],
        )

        accepted = (
            "python scripts/verify_accepted_aggregate.py "
            "--artifact-root /tmp/bryson-v4-posterior --branch constant "
            f"--expected-bryson-source-sha256 {workflow.BRYSON_SOURCE_SHA256}"
        )
        propagation = (
            "python research/bryson-joint-posterior/propagate_hab2_joint_posterior.py "
            "--branch constant"
        )
        workflow.require_accepted_aggregate_guard(
            Path("synthetic.yml"), [command(accepted + "\n" + propagation)], "constant"
        )
        with self.assertRaises(SystemExit):
            workflow.require_accepted_aggregate_guard(
                Path("synthetic.yml"),
                [command(propagation + "\n" + accepted)],
                "constant",
            )

    def test_external_download_argv_count_and_order_are_exact(self) -> None:
        argv = (
            "gh",
            "run",
            "download",
            "$HOST_RUN_ID",
            "--repo",
            "$GH_REPOSITORY",
            "--name",
            "jj-g-host-export-padova-dr05-tams-canonical",
            "--dir",
            "/tmp/jj-hosts",
        )
        download = (
            'gh run download "$HOST_RUN_ID" --repo "$GH_REPOSITORY" '
            "--name jj-g-host-export-padova-dr05-tams-canonical "
            "--dir /tmp/jj-hosts"
        )
        accepted = (
            "python scripts/verify_accepted_aggregate.py "
            "--artifact-root /tmp/bryson-v4-posterior --branch constant "
            f"--expected-bryson-source-sha256 {workflow.BRYSON_SOURCE_SHA256}"
        )
        workflow.require_exact_external_downloads(
            Path("synthetic.yml"), [command(download)], (argv,)
        )
        with self.assertRaises(SystemExit):
            workflow.require_exact_external_downloads(
                Path("synthetic.yml"),
                [command(download + "\n" + accepted + "\n" + download)],
                (argv,),
            )
        with self.assertRaises(SystemExit):
            workflow.require_exact_external_downloads(
                Path("synthetic.yml"), [command(download + " || true")], (argv,)
            )


class DependencyLockTests(unittest.TestCase):
    def assert_lock_grammar_rejects(self, text: str) -> None:
        original = dependency.EXPECTED_LOCK_SHA256
        dependency.EXPECTED_LOCK_SHA256 = hashlib.sha256(
            text.encode("utf-8")
        ).hexdigest()
        try:
            with self.assertRaises(SystemExit):
                dependency.locked_pins_from_text(text)
        finally:
            dependency.EXPECTED_LOCK_SHA256 = original

    def test_current_repository_policy_passes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            dependency.main()

    def test_toml_comments_cannot_supply_dependencies(self) -> None:
        runtime = {
            name: version
            for name, version in dependency.EXPECTED_DIRECT_PINS.items()
            if name
            not in {"flit-core", "pip", "pyyaml", "setuptools", "tomli", "wheel"}
        }
        text = (
            "[build-system]\n"
            '# requires = ["setuptools==83.0.0"]\n'
            "requires = []\n"
            'build-backend = "setuptools.build_meta"\n\n'
            "[project]\n"
            'requires-python = ">=3.10,<3.11"\n'
            "# dependencies = [\n"
            + "".join(f'#   "{name}=={version}",\n' for name, version in runtime.items())
            + "# ]\n"
            "dependencies = []\n"
        )
        project, build = dependency.pyproject_pins_from_text(text)
        self.assertEqual(project, {})
        self.assertEqual(build, {})
        original = dependency.PYPROJECT
        dependency.PYPROJECT = MemoryText(text)  # type: ignore[assignment]
        try:
            with self.assertRaises(SystemExit):
                dependency.main()
        finally:
            dependency.PYPROJECT = original

    def test_build_and_project_policy_is_exact(self) -> None:
        baseline = dependency.PYPROJECT.read_text(encoding="utf-8")
        mutations = (
            baseline.replace("setuptools.build_meta", "attacker_backend"),
            baseline.replace(
                'build-backend = "setuptools.build_meta"',
                'build-backend = "setuptools.build_meta"\nbackend-path = ["."]',
            ),
            baseline.replace(">=3.10,<3.11", ">=3.8"),
            baseline + '\n[project.optional-dependencies]\nextra = ["evil==1"]\n',
            baseline.replace(
                "[tool.setuptools]", 'dynamic = ["optional-dependencies"]\n\n[tool.setuptools]'
            ),
            baseline + '\n[dependency-groups]\naudit = ["evil==1"]\n',
        )
        for text in mutations:
            with self.subTest(text=text[-100:]), self.assertRaises(SystemExit):
                dependency.pyproject_pins_from_text(text)

    def test_lock_digest_rejects_directives_extras_and_hash_tampering(self) -> None:
        baseline = dependency.LOCK.read_text(encoding="utf-8")
        first_hash = "1fa4437fe8d1e103f14cb1cb4e8449c93ae4190b5e9fd97e9c61a5155de9af0d"
        grammar_mutations = (
            baseline + "\n--requirement https://example.invalid/extra.txt\n",
            baseline + "\n--extra-index-url https://example.invalid/simple\n",
            baseline
            + "\ncolorama==0.4.6 \\\n"
            + "    --hash=sha256:4f1d9991f5acc0ca119f9d443620b77f9d6b33703e51011c16baf57afb285fc6\n",
            baseline.replace("# by the following command", "# claimed generator", 1),
        )
        for text in grammar_mutations:
            with self.subTest(suffix=text[-100:]):
                self.assert_lock_grammar_rejects(text)

        tampered_hash = baseline.replace(first_hash, "0" * 64, 1)
        self.assertNotEqual(tampered_hash, baseline)
        with self.assertRaises(SystemExit):
            dependency.locked_pins_from_text(tampered_hash)


if __name__ == "__main__":
    unittest.main()
