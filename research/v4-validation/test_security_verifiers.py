#!/usr/bin/env python3
"""Adversarial regression tests for the release security verifiers."""

from __future__ import annotations

import copy
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


def command(
    body: str,
    *,
    working_directory: str | None = None,
    run_line: int = 1,
) -> workflow.ShellCommand:
    return workflow.ShellCommand(
        run_line=run_line,
        body_start_line=run_line,
        scalar_style="|",
        body=body,
        step_name="synthetic",
        working_directory=working_directory,
    )


class WorkflowSecurityTests(unittest.TestCase):
    def test_current_repository_policy_passes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            workflow.main()

    def test_numerical_runtime_environment_is_exact_and_immutable(self) -> None:
        path = Path("verify.yml")
        expected = dict(workflow.EXPECTED_NUMERICAL_ENV)
        expected["PYTHONDONTWRITEBYTECODE"] = "1"
        workflow.require_numerical_runtime_environment(path, {"env": expected})

        mutations: list[dict[str, object]] = []
        for key in expected:
            missing = dict(expected)
            missing.pop(key)
            mutations.append({"env": missing})
            changed = dict(expected)
            changed[key] = "unexpected"
            mutations.append({"env": changed})
        extra = dict(expected)
        extra["NPY_ENABLE_CPU_FEATURES"] = "AVX512_SKX"
        mutations.append({"env": extra})
        mutations.append(
            {
                "env": dict(expected),
                "jobs": {"verify": {"env": {"OMP_NUM_THREADS": "8"}}},
            }
        )
        mutations.append(
            {
                "env": dict(expected),
                "jobs": {
                    "verify": {
                        "steps": [
                            {"env": {"NPY_ENABLE_CPU_FEATURES": "AVX512_SKX"}}
                        ]
                    }
                },
            }
        )
        for key in workflow.PROTECTED_EXECUTION_ENV_KEYS:
            mutations.append(
                {
                    "env": dict(expected),
                    "jobs": {"verify": {"env": {key: "/tmp/unsafe"}}},
                }
            )
        for key in ("BASH_FUNC_python%%", "LD_UNREVIEWED_INJECTION"):
            mutations.append(
                {
                    "env": dict(expected),
                    "jobs": {"verify": {"env": {key: "/tmp/unsafe"}}},
                }
            )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                workflow.require_numerical_runtime_environment(path, mutation)

        shell_mutations = (
            "unset OMP_NUM_THREADS",
            "export OPENBLAS_NUM_THREADS=8",
            "OMP_NUM_THREADS=8 python science.py",
            'k=OMP_NUM_THREADS\nunset "$k"',
            "env -u PYTHONHASHSEED python science.py",
            "env -u PYTHONDONTWRITEBYTECODE python science.py",
            "command env -i python science.py",
            "PATH=/tmp python science.py",
            "PYTHONPATH=/tmp python science.py",
            "PYTHONHOME=/tmp python science.py",
            "LD_AUDIT=/tmp/unsafe.so python science.py",
            "GITHUB_WORKSPACE=/tmp python science.py",
            'printf "PATH=/tmp\\n" >> "$GITHUB_ENV"',
            'printf "/tmp\\n" >> "$GITHUB_PATH"',
        )
        for body in shell_mutations:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.audit_shell_command(path, command(body))

    def test_shell_command_rebinding_is_rejected(self) -> None:
        path = Path("verify.yml")
        rejected = (
            "python() {\n  return 0\n}",
            "python(){ return 0; }",
            "function python {\n  return 0\n}",
            "function p'y'thon { return 0; }",
            "alias python=:",
            "unalias python",
            "hash -p /bin/true python",
            "enable -f /tmp/unsafe.so python",
            "shopt -s expand_aliases",
            "command -- hash -p /bin/true python",
            "command -p hash -p /bin/true python",
            "builtin -- alias python=:",
            "builtin builtin hash -p /bin/true python",
            r"\hash -p /bin/true python",
            "'alias' python=:",
            'h"ash" -p /bin/true python',
            "true && hash -p /bin/true python",
            ":; command -- hash -p /bin/true python",
        )
        for body in rejected:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.audit_shell_command(path, command(body))

        workflow.audit_shell_command(path, command("echo 'python() { inert text; }'"))

    def test_protected_python_sources_are_invocation_only(self) -> None:
        path = Path("verify.yml")
        script = "research/jj-host-export/run_jj_export.py"
        absolute = f"$GITHUB_WORKSPACE/{script}"
        workflow.audit_shell_command(
            path, command(f'python "{absolute}" --out /tmp/result')
        )

        rejected = (
            f"sed -i 's/unsafe/safe/' {script}",
            "cd research/jj-host-export\nsed -i 's/unsafe/safe/' run_jj_export.py",
            f'cp /tmp/replacement.py "{absolute}"',
            f'mv /tmp/replacement.py "{absolute}"',
            f'printf "%s\\n" unsafe > "{absolute}"',
            f': > "{absolute}"',
            f'python "{absolute}" > "{absolute}"',
            f'python "{absolute}" --label run_jj_export.py',
            "sed -i 's/unsafe/safe/' research/jj-host-export/"
            "run_jj_'export.py'",
        )
        for body in rejected:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.audit_shell_command(path, command(body))

        with self.assertRaises(SystemExit):
            workflow.audit_shell_command(
                path,
                command(
                    "sed -i 's/unsafe/safe/' run_jj_export.py",
                    working_directory="research/jj-host-export",
                ),
            )

    def test_every_protected_python_source_requires_absolute_invocation(self) -> None:
        path = Path("verify.yml")
        for script in sorted(workflow.PROTECTED_PYTHON_SCRIPTS):
            absolute = f"$GITHUB_WORKSPACE/{script}"
            with self.subTest(script=script, form="absolute"):
                workflow.audit_shell_command(
                    path, command(f'python "{absolute}" --synthetic-test')
                )
            with self.subTest(script=script, form="relative"), self.assertRaises(
                SystemExit
            ):
                workflow.audit_shell_command(
                    path, command(f"python {script} --synthetic-test")
                )
            with self.subTest(script=script, form="mutation"), self.assertRaises(
                SystemExit
            ):
                workflow.audit_shell_command(
                    path, command(f'sed -i s/old/new/ "{absolute}"')
                )

    def test_jj_export_profile_is_exact_and_integrity_gated(self) -> None:
        for name, expected_argv in workflow.EXPECTED_JJ_EXPORT_ARGV.items():
            path = ROOT / ".github" / "workflows" / name
            parsed = workflow.parse_workflow(path)
            with self.subTest(name=name):
                workflow.require_exact_jj_export_profile(path, parsed.commands)

            invocation = " ".join(expected_argv)
            canonical = command(
                "\n".join((*workflow.JJ_EXPORT_INTEGRITY_LINES, invocation))
            )
            workflow.require_exact_jj_export_profile(path, [canonical])

            rejected = (
                command(invocation),
                command(
                    "\n".join(
                        (*workflow.JJ_EXPORT_INTEGRITY_LINES, invocation + " --extra")
                    )
                ),
                command(
                    "\n".join(
                        (
                            *workflow.JJ_EXPORT_INTEGRITY_LINES[:-1],
                            "[[ 1 == 1 ]]",
                            invocation,
                        )
                    )
                ),
                command(
                    "\n".join(
                        (*workflow.JJ_EXPORT_INTEGRITY_LINES, invocation, invocation)
                    )
                ),
            )
            for candidate in rejected:
                with self.subTest(name=name, body=candidate.body), self.assertRaises(
                    SystemExit
                ):
                    workflow.require_exact_jj_export_profile(path, [candidate])

        unapproved = Path("unapproved.yml")
        expected = next(iter(workflow.EXPECTED_JJ_EXPORT_ARGV.values()))
        with self.assertRaises(SystemExit):
            workflow.require_exact_jj_export_profile(
                unapproved,
                [
                    command(
                        "\n".join(
                            (*workflow.JJ_EXPORT_INTEGRITY_LINES, " ".join(expected))
                        )
                    )
                ],
            )

    def test_numerical_runtime_verifier_order_and_arguments_are_closed(self) -> None:
        path = Path("verify.yml")
        install = (
            "python -m pip install --require-hashes --only-binary=:all: "
            "-r requirements.txt"
        )
        check = "python -m pip check"
        gate = 'python "$GITHUB_WORKSPACE/scripts/verify_numerical_runtime.py"'
        workflow.require_numerical_runtime_verification(
            path,
            [
                command("\n".join((install, check, gate))),
                command("\n".join((install, check, gate)), run_line=20),
            ],
        )

        rejected = (
            "\n".join((install, check)),
            "\n".join((install, gate, check)),
            "\n".join((install, check, "python science.py", gate)),
            "\n".join((install, check, gate, gate)),
            "\n".join((install, check, gate + " --output unexpected.json")),
            "\n".join((install, check, "python /tmp/verify_numerical_runtime.py")),
            "\n".join((install, check, gate + " || true")),
            "\n".join((install, check, "if false; then", "  " + gate, "fi")),
            "\n".join((install, check, "echo " + gate)),
        )
        for body in rejected:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.require_numerical_runtime_verification(path, [command(body)])

    def test_job_and_step_execution_conditions_are_pinned(self) -> None:
        public_path = ROOT / ".github" / "workflows" / "verify.yml"
        public = workflow.parse_workflow(public_path)
        workflow.require_workflow_execution_conditions(public_path, public.data)

        step_suppressed = copy.deepcopy(public.data)
        step_suppressed["jobs"]["verify"]["steps"][0]["if"] = "false"
        with self.assertRaises(SystemExit):
            workflow.require_workflow_execution_conditions(
                public_path, step_suppressed
            )

        job_suppressed = copy.deepcopy(public.data)
        job_suppressed["jobs"]["verify"]["if"] = "false"
        with self.assertRaises(SystemExit):
            workflow.require_workflow_execution_conditions(
                public_path, job_suppressed
            )

        extra_job = copy.deepcopy(public.data)
        extra_job["jobs"]["suppressed"] = copy.deepcopy(
            extra_job["jobs"]["verify"]
        )
        with self.assertRaises(SystemExit):
            workflow.require_workflow_execution_conditions(public_path, extra_job)

        private_path = (
            ROOT
            / ".github"
            / "workflows"
            / "jj-tams-metallicity-differential.yml"
        )
        private = workflow.parse_workflow(private_path)
        workflow.require_workflow_execution_conditions(private_path, private.data)
        private_suppressed = copy.deepcopy(private.data)
        private_suppressed["jobs"]["audit"]["if"] = "false"
        with self.assertRaises(SystemExit):
            workflow.require_workflow_execution_conditions(
                private_path, private_suppressed
            )

    def test_release_package_is_exactly_tag_gated(self) -> None:
        path = ROOT / ".github" / "workflows" / "verify.yml"
        parsed = workflow.parse_workflow(path)
        workflow.require_release_package_tag_gate(path, parsed.data)

        def release_step(document: dict[str, object]) -> dict[str, object]:
            return [
                step
                for step in document["jobs"]["verify"]["steps"]
                if step.get("name") == workflow.RELEASE_PACKAGE_STEP_NAME
            ][0]

        def publisher_step(document: dict[str, object]) -> dict[str, object]:
            return [
                step
                for step in document["jobs"]["publish-source-release-assets"][
                    "steps"
                ]
                if step.get("name") == workflow.RELEASE_PUBLISH_STEP_NAME
            ][0]

        mutations = []
        missing_tags = copy.deepcopy(parsed.data)
        missing_tags["on"]["push"].pop("tags")
        mutations.append(missing_tags)
        broad_tags = copy.deepcopy(parsed.data)
        broad_tags["on"]["push"]["tags"] = ["*"]
        mutations.append(broad_tags)
        wrong_release_tag = copy.deepcopy(parsed.data)
        wrong_release_tag["on"]["push"]["tags"] = ["v4.0.5"]
        mutations.append(wrong_release_tag)
        unguarded = copy.deepcopy(parsed.data)
        release_step(unguarded).pop("if")
        mutations.append(unguarded)
        wrong_condition = copy.deepcopy(parsed.data)
        release_step(wrong_condition)["if"] = "always()"
        mutations.append(wrong_condition)
        shallow_checkout = copy.deepcopy(parsed.data)
        shallow_checkout["jobs"]["verify"]["steps"][0]["with"] = {
            "fetch-depth": "1"
        }
        mutations.append(shallow_checkout)
        duplicate_build = copy.deepcopy(parsed.data)
        release_step(duplicate_build)["run"] += (
            "make public-package\n"
        )
        mutations.append(duplicate_build)
        missing_results_download = copy.deepcopy(parsed.data)
        release_step(missing_results_download)["run"] = (
            release_step(missing_results_download)["run"].replace(
                "gh release download v4.0.4", "true"
            )
        )
        mutations.append(missing_results_download)
        comment_only_bypass = copy.deepcopy(parsed.data)
        release_step(comment_only_bypass)["run"] = release_step(
            comment_only_bypass
        )["run"].replace("make public-package", "# make public-package")
        mutations.append(comment_only_bypass)
        no_op_prefix = copy.deepcopy(parsed.data)
        release_step(no_op_prefix)["run"] = "true\n" + release_step(no_op_prefix)["run"]
        mutations.append(no_op_prefix)
        publisher_clobber = copy.deepcopy(parsed.data)
        publisher_step(publisher_clobber)["run"] += " --clobber\n"
        mutations.append(publisher_clobber)
        publisher_read_only = copy.deepcopy(parsed.data)
        publisher_read_only["jobs"]["publish-source-release-assets"]["permissions"] = {
            "contents": "read"
        }
        mutations.append(publisher_read_only)
        persistent_credentials = copy.deepcopy(parsed.data)
        persistent_credentials["jobs"]["publish-source-release-assets"]["steps"][0][
            "with"
        ]["persist-credentials"] = "true"
        mutations.append(persistent_credentials)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(SystemExit):
                workflow.require_release_package_tag_gate(path, mutation)

    def test_verify_job_schema_rejects_privilege_and_runner_mutations(self) -> None:
        path = ROOT / ".github" / "workflows" / "verify.yml"
        parsed = workflow.parse_workflow(path)
        mutations: list[tuple[str, dict[str, object]]] = []

        contents_write = copy.deepcopy(parsed.data)
        contents_write["jobs"]["verify"]["permissions"] = {"contents": "write"}
        mutations.append(("verify contents:write", contents_write))

        self_hosted = copy.deepcopy(parsed.data)
        self_hosted["jobs"]["verify"]["runs-on"] = "self-hosted"
        mutations.append(("self-hosted runner", self_hosted))

        container = copy.deepcopy(parsed.data)
        container["jobs"]["verify"]["container"] = "python:3.10"
        mutations.append(("job container", container))

        services = copy.deepcopy(parsed.data)
        services["jobs"]["verify"]["services"] = {
            "database": {"image": "postgres:latest"}
        }
        mutations.append(("job services", services))

        node_options = copy.deepcopy(parsed.data)
        node_options["jobs"]["verify"]["env"] = {
            "NODE_OPTIONS": "--require=/tmp/preload.js"
        }
        mutations.append(("job NODE_OPTIONS", node_options))

        extra_key = copy.deepcopy(parsed.data)
        extra_key["jobs"]["verify"]["continue-on-error"] = "true"
        mutations.append(("extra job key", extra_key))

        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(SystemExit):
                workflow.require_release_package_tag_gate(path, mutation)

    def test_release_lineage_rejects_side_branch_and_moved_tag_mutations(self) -> None:
        path = ROOT / ".github" / "workflows" / "verify.yml"
        parsed = workflow.parse_workflow(path)

        def named_step(
            document: dict[str, object], job_name: str, step_name: str
        ) -> dict[str, object]:
            return [
                step
                for step in document["jobs"][job_name]["steps"]
                if step.get("name") == step_name
            ][0]

        mutations: list[tuple[str, dict[str, object]]] = []

        side_branch = copy.deepcopy(parsed.data)
        step = named_step(
            side_branch, "verify", workflow.RELEASE_LINEAGE_STEP_NAME
        )
        step["run"] = step["run"].replace(
            "refs/remotes/origin/main", "refs/remotes/origin/release"
        )
        mutations.append(("side-branch ancestry", side_branch))

        moved_tag = copy.deepcopy(parsed.data)
        step = named_step(
            moved_tag,
            "publish-source-release-assets",
            workflow.RELEASE_PUBLISH_LINEAGE_STEP_NAME,
        )
        step["run"] = step["run"].replace(
            "+refs/tags/v4.0.4:refs/tags/v4.0.4",
            "+refs/tags/v4.0.4:refs/tags/v4.0.4-observed",
            1,
        )
        mutations.append(("moved-tag destination", moved_tag))

        missing_sha_binding = copy.deepcopy(parsed.data)
        step = named_step(
            missing_sha_binding, "verify", workflow.RELEASE_LINEAGE_STEP_NAME
        )
        step["run"] = step["run"].replace(
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"\n', "", 1
        )
        mutations.append(("missing GITHUB_SHA binding", missing_sha_binding))

        noncanonical_origin = copy.deepcopy(parsed.data)
        step = named_step(
            noncanonical_origin, "verify", workflow.RELEASE_LINEAGE_STEP_NAME
        )
        step["run"] = step["run"].replace(
            "https://github.com/jerseroman/"
            "Exo-Earth-Candidate-Population-Projection-Pipeline.git",
            "https://example.invalid/repository.git",
            1,
        )
        mutations.append(("noncanonical origin", noncanonical_origin))

        broadened_event = copy.deepcopy(parsed.data)
        named_step(
            broadened_event, "verify", workflow.RELEASE_PACKAGE_STEP_NAME
        )["if"] = "github.ref == 'refs/tags/v4.0.4'"
        mutations.append(("non-push tag condition", broadened_event))

        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(SystemExit):
                workflow.require_release_package_tag_gate(path, mutation)

    def test_four_file_envelope_rejects_partial_symlink_and_stale_mix(self) -> None:
        path = ROOT / ".github" / "workflows" / "verify.yml"
        parsed = workflow.parse_workflow(path)

        def named_step(
            document: dict[str, object], job_name: str, step_name: str
        ) -> dict[str, object]:
            return [
                step
                for step in document["jobs"][job_name]["steps"]
                if step.get("name") == step_name
            ][0]

        mutations: list[tuple[str, dict[str, object]]] = []

        missing_member = copy.deepcopy(parsed.data)
        upload = named_step(
            missing_member, "verify", workflow.RELEASE_STAGE_STEP_NAME
        )
        upload["with"]["path"] = upload["with"]["path"].replace(
            "${{ runner.temp }}/v404-source-release-stage/"
            "Exo-Earth-Candidate-Population-Projection-Pipeline-v4.0.4-results.zip.sha256\n",
            "",
            1,
        )
        mutations.append(("missing envelope member", missing_member))

        producer_symlink = copy.deepcopy(parsed.data)
        prepare = named_step(
            producer_symlink, "verify", workflow.RELEASE_PREPARE_STAGE_STEP_NAME
        )
        prepare["run"] = prepare["run"].replace(
            'test ! -L "$STAGE/PUBLIC_SHA256SUMS"', "true", 1
        )
        mutations.append(("producer symlink guard", producer_symlink))

        producer_clobber = copy.deepcopy(parsed.data)
        prepare = named_step(
            producer_clobber, "verify", workflow.RELEASE_PREPARE_STAGE_STEP_NAME
        )
        prepare["run"] = prepare["run"].replace(
            "cp --no-dereference --no-clobber",
            "cp --no-dereference",
            1,
        )
        mutations.append(("producer clobber", producer_clobber))

        consumer_symlink = copy.deepcopy(parsed.data)
        inventory = named_step(
            consumer_symlink,
            "publish-source-release-assets",
            workflow.RELEASE_INVENTORY_STEP_NAME,
        )
        inventory["run"] = inventory["run"].replace(
            'test ! -L "$RECEIVED/PUBLIC_SHA256SUMS"', "true", 1
        )
        mutations.append(("consumer symlink guard", consumer_symlink))

        ancestor_symlink = copy.deepcopy(parsed.data)
        fresh = named_step(
            ancestor_symlink,
            "publish-source-release-assets",
            workflow.RELEASE_FRESH_DESTINATION_STEP_NAME,
        )
        fresh["run"] = fresh["run"].replace(
            'test ! -L "$RUNNER_TEMP"', "true", 1
        )
        mutations.append(("ancestor symlink guard", ancestor_symlink))

        stale_dist = copy.deepcopy(parsed.data)
        download = stale_dist["jobs"]["publish-source-release-assets"]["steps"][4]
        download["with"]["path"] = "dist"
        mutations.append(("stale dist destination", stale_dist))

        missing_publisher_runtime = copy.deepcopy(parsed.data)
        missing_publisher_runtime["jobs"]["publish-source-release-assets"][
            "steps"
        ][1]["with"]["python-version"] = "3.11"
        mutations.append(("wrong publisher Python runtime", missing_publisher_runtime))

        unlocked_publisher_install = copy.deepcopy(parsed.data)
        install = named_step(
            unlocked_publisher_install,
            "publish-source-release-assets",
            workflow.RELEASE_PUBLISH_INSTALL_STEP_NAME,
        )
        install["run"] = install["run"].replace("--require-hashes ", "", 1)
        mutations.append(("unlocked publisher dependency install", unlocked_publisher_install))

        reused_destination = copy.deepcopy(parsed.data)
        fresh = named_step(
            reused_destination,
            "publish-source-release-assets",
            workflow.RELEASE_FRESH_DESTINATION_STEP_NAME,
        )
        fresh["run"] = fresh["run"].replace(
            'test ! -e "$RECEIVED"', "true", 1
        )
        mutations.append(("reused destination", reused_destination))

        partial_roundtrip = copy.deepcopy(parsed.data)
        roundtrip = named_step(
            partial_roundtrip,
            "publish-source-release-assets",
            workflow.RELEASE_FULL_ROUNDTRIP_STEP_NAME,
        )
        roundtrip["run"] = roundtrip["run"].replace(
            "  --results-checksum ", "  --ignored-results-checksum ", 1
        )
        mutations.append(("partial publisher roundtrip", partial_roundtrip))

        bytecode_enabled = copy.deepcopy(parsed.data)
        roundtrip = named_step(
            bytecode_enabled,
            "publish-source-release-assets",
            workflow.RELEASE_FULL_ROUNDTRIP_STEP_NAME,
        )
        roundtrip["run"] = roundtrip["run"].replace(
            "python -I -B ", "python ", 1
        )
        mutations.append(("non-isolated bytecode-enabled gate", bytecode_enabled))

        token_exposed_to_gate = copy.deepcopy(parsed.data)
        roundtrip = named_step(
            token_exposed_to_gate,
            "publish-source-release-assets",
            workflow.RELEASE_FULL_ROUNDTRIP_STEP_NAME,
        )
        roundtrip["env"] = {"GH_TOKEN": "${{ github.token }}"}
        mutations.append(("write token exposed to full gate", token_exposed_to_gate))

        for name, mutation in mutations:
            with self.subTest(name=name), self.assertRaises(SystemExit):
                workflow.require_release_package_tag_gate(path, mutation)

    def test_jj_audit_workflows_pin_and_validate_runner_parallelism(self) -> None:
        cases = {
            ".github/workflows/jj-tams-radial-convergence.yml": (
                '"$rundir/parameters"',
                "python research/jj-tams-convergence/tams_radial_convergence.py",
            ),
            ".github/workflows/jj-tams-metallicity-differential.yml": (
                "/tmp/jj-diff/parameters",
                'python "$GITHUB_WORKSPACE/research/jj-host-export/'
                'run_jj_export.py"',
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
                with self.assertRaises(SystemExit):
                    workflow._matching_python_invocations(
                        [command(f"python {expected}")], expected
                    )
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

            relative = f"python {expected}"
            cwd_mutations = (
                "cd /tmp",
                "pushd /tmp",
                "command cd /tmp",
                "builtin pushd /tmp",
            )
            for mutation in cwd_mutations:
                with (
                    self.subTest(expected=expected, mutation=mutation),
                    self.assertRaises(SystemExit),
                ):
                    workflow._matching_python_invocations(
                        [command(mutation + "\n" + relative)], expected
                    )
            with self.assertRaises(SystemExit):
                workflow._matching_python_invocations(
                    [command(relative, working_directory="/tmp")], expected
                )

            workspace = f'python "$GITHUB_WORKSPACE/{expected}"'
            matches = workflow._matching_python_invocations(
                [command("cd /tmp\n" + workspace)], expected
            )
            self.assertEqual(len(matches), 1)

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
            'python "$GITHUB_WORKSPACE/research/bryson-joint-posterior/'
            'run_hab2_joint_posterior.py" '
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
            'python "$GITHUB_WORKSPACE/research/bryson-joint-posterior/'
            'aggregate_hab2_joint_posterior.py" '
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
            'python "$GITHUB_WORKSPACE/scripts/verify_accepted_aggregate.py" '
            "--artifact-root /tmp/bryson-v4-posterior --branch constant "
            f"--pc-catalog {workflow.BRYSON_PC_CATALOG} "
            f"--stellar-catalog {workflow.BRYSON_STELLAR_CATALOG} "
            f"--expected-bryson-source-sha256 {workflow.BRYSON_SOURCE_SHA256}"
        )
        propagation = (
            'python "$GITHUB_WORKSPACE/research/bryson-joint-posterior/'
            'propagate_hab2_joint_posterior.py" '
            "--branch constant"
        )
        workflow.require_accepted_aggregate_guard(
            Path("synthetic.yml"), [command(accepted + "\n" + propagation)], "constant"
        )
        without_catalogs = accepted.replace(
            f"--pc-catalog {workflow.BRYSON_PC_CATALOG} ", ""
        ).replace(
            f"--stellar-catalog {workflow.BRYSON_STELLAR_CATALOG} ", ""
        )
        with self.assertRaises(SystemExit):
            workflow.require_accepted_aggregate_guard(
                Path("synthetic.yml"),
                [command(without_catalogs + "\n" + propagation)],
                "constant",
            )
        with self.assertRaises(SystemExit):
            workflow.require_accepted_aggregate_guard(
                Path("synthetic.yml"),
                [command(propagation + "\n" + accepted)],
                "constant",
            )

    def test_private_raw_chain_workflow_flow_is_exact_and_private(self) -> None:
        workflow_root = Path(workflow.__file__).resolve().parents[1] / ".github" / "workflows"
        for name in (
            "bryson-v4-corrected-production.yml",
            "bryson-v4-corrected-zero-extended.yml",
        ):
            with self.subTest(workflow=name):
                path = workflow_root / name
                parsed = workflow.parse_workflow(path)
                workflow.require_private_raw_chain_flow(
                    path, parsed.data, parsed.commands
                )

                public_aggregate = copy.deepcopy(parsed.data)
                public_aggregate["jobs"]["aggregate"]["if"] = "true"
                with self.assertRaises(SystemExit):
                    workflow.require_private_raw_chain_flow(
                        path, public_aggregate, parsed.commands
                    )

                long_retention = copy.deepcopy(parsed.data)
                private_upload = [
                    step
                    for step in long_retention["jobs"]["reconstruct-shards"]["steps"]
                    if isinstance(step, dict)
                    and "private-convergence-evidence"
                    in str(step.get("with", {}).get("name", ""))
                ][0]
                private_upload["with"]["retention-days"] = "30"
                with self.assertRaises(SystemExit):
                    workflow.require_private_raw_chain_flow(
                        path, long_retention, parsed.commands
                    )

                without_runner_binding = path.read_text(encoding="utf-8").replace(
                    '            --private-raw-chain-dir "$PRIVATE_EVIDENCE" \\\n',
                    "",
                    1,
                )
                changed = workflow.parse_workflow_text(
                    without_runner_binding, source=f"{name}:missing-raw-binding"
                )
                with self.assertRaises(SystemExit):
                    workflow.require_private_raw_chain_flow(
                        path, changed.data, changed.commands
                    )

    def test_catalog_replay_input_artifact_is_exact_and_precedes_verifier(self) -> None:
        workflow_root = Path(workflow.__file__).resolve().parents[1] / ".github" / "workflows"
        for name in (
            "bryson-v4-corrected-production.yml",
            "bryson-v4-corrected-zero-extended.yml",
        ):
            with self.subTest(workflow=name):
                path = workflow_root / name
                parsed = workflow.parse_workflow(path)
                workflow.require_catalog_replay_input_artifact(path, parsed.data)

                forged = copy.deepcopy(parsed.data)
                steps = forged["jobs"]["propagate"]["steps"]
                catalog_step = [
                    step
                    for step in steps
                    if isinstance(step, dict)
                    and step.get("with", {}).get("path")
                    == "/tmp/DR25-occurrence-public"
                ][0]
                catalog_step["with"]["name"] = "unbound-catalogs"
                with self.assertRaises(SystemExit):
                    workflow.require_catalog_replay_input_artifact(path, forged)

    def test_host_artifact_contract_guard_is_exact_and_repeated(self) -> None:
        download = (
            'gh run download "$HOST_RUN_ID" --repo "$GH_REPOSITORY" '
            "--name jj-g-host-export-padova-dr05-tams-canonical "
            "--dir /tmp/jj-hosts"
        )
        guard = (
            'python "$GITHUB_WORKSPACE/scripts/'
            'verify_host_artifact_contract.py" '
            "--mode verify "
            '--contract "$GITHUB_WORKSPACE/provenance/'
            'HOST_ARTIFACT_CONTRACT_v4_0_4.json" '
            "--artifact-root /tmp/jj-hosts"
        )
        propagation = (
            'python "$GITHUB_WORKSPACE/research/bryson-joint-posterior/'
            'propagate_hab2_joint_posterior.py" --branch constant'
        )
        path = Path("bryson-v4-corrected-production.yml")
        commands = [
            command(download + "\n" + guard),
            command(guard + "\n" + propagation, run_line=100),
        ]
        workflow.require_host_artifact_contract_guard(path, commands)

        rejected = (
            [command(download + "\n" + guard)],
            [
                command(download),
                command(
                    guard + "\n" + guard + "\n" + propagation,
                    run_line=100,
                ),
            ],
            [
                command(download + "\n" + guard),
                command(
                    guard.replace("--mode verify", "--mode qualify")
                    + "\n"
                    + propagation,
                    run_line=100,
                ),
            ],
            [
                command(download + "\n" + guard),
                command(propagation + "\n" + guard, run_line=100),
            ],
            [
                command(
                    download
                    + "\n"
                    + "echo "
                    + "a2b6f407c70c236f2be9a9084f53fe9ba461f06aa5f44d6caae11696467e5a28"
                    + "\n"
                    + guard
                ),
                command(guard + "\n" + propagation, run_line=100),
            ],
        )
        for case in rejected:
            with self.subTest(case=case), self.assertRaises(SystemExit):
                workflow.require_host_artifact_contract_guard(path, case)

    def test_metallicity_negative_artifact_gate_is_ordered_and_exact(self) -> None:
        path = Path("jj-tams-metallicity-differential.yml")
        producer = (
            'python "$GITHUB_WORKSPACE/research/jj-host-export/'
            'metallicity_tams_differential_sensitivity.py" '
            "--input /tmp/metallicity-host/jj_g_hosts_parent_prelogg_padova.csv "
            "--reference-tams $GITHUB_WORKSPACE/research/jj-host-export/"
            "reference-data/tams_parsec_danxhuber.txt "
            "--cache /tmp/parsec-metal-tracks "
            "--out $GITHUB_WORKSPACE/results/metallicity-audit "
            "--data-locks $GITHUB_WORKSPACE/provenance/DATA_LOCKS.json"
        )
        provenance = (
            "cp research/jj-host-export/PROVENANCE_METALLICITY_DIFFERENTIAL.md "
            "results/metallicity-audit/PROVENANCE_METALLICITY_DIFFERENTIAL.md"
        )
        verifier = (
            'python "$GITHUB_WORKSPACE/scripts/verify_metallicity_tams_audit.py" '
            "--artifact-root results/metallicity-audit "
            "--data-locks provenance/DATA_LOCKS.json"
        )
        accepted = [
            command(producer, run_line=10),
            command(provenance, run_line=20),
            command(verifier, run_line=30),
        ]
        workflow.require_metallicity_negative_artifact_gate(path, accepted)

        rejected = (
            [accepted[0], accepted[2]],
            [
                accepted[0],
                command(verifier, run_line=20),
                command(provenance, run_line=30),
            ],
            [
                command(producer.replace("metallicity-audit", "wrong-root"), run_line=10),
                accepted[1],
                accepted[2],
            ],
            [
                accepted[0],
                accepted[1],
                command(verifier + " --unexpected", run_line=30),
            ],
            [
                accepted[0],
                command("echo " + provenance, run_line=20),
                accepted[2],
            ],
        )
        for case in rejected:
            with self.subTest(case=case), self.assertRaises(SystemExit):
                workflow.require_metallicity_negative_artifact_gate(path, case)

    def test_unattested_age_cut_is_forbidden_in_reusable_workflows(self) -> None:
        path = ROOT / ".github" / "workflows" / "jj-g-host-export.yml"
        parsed = workflow.parse_workflow(path)
        workflow.require_no_unattested_age_cut_workflow(path, parsed.commands)

        rejected = (
            'python "$GITHUB_WORKSPACE/research/jj-host-export/'
            'age_cut_sensitivity.py" --out "$GITHUB_WORKSPACE/results/age-cut"',
            'python "$GITHUB_WORKSPACE/scripts/verify_age_cut_sensitivity.py" '
            '--artifact-root "$GITHUB_WORKSPACE/results/age-cut"',
            'cp -- AGE_CUT_SENSITIVITY.json results/jj/age-cut/',
            'cp -- age_cut_radial.csv results/jj/age-cut/',
            'cp -- JJ_SSP_INPUT_SHA256SUMS.txt results/jj/age-cut/',
            'cp -- SHA256SUMS_age_cut_sensitivity.txt results/jj/age-cut/',
        )
        for body in rejected:
            with self.subTest(body=body), self.assertRaises(SystemExit):
                workflow.require_no_unattested_age_cut_workflow(
                    path, [command(body)]
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
            'python "$GITHUB_WORKSPACE/scripts/verify_accepted_aggregate.py" '
            "--artifact-root /tmp/bryson-v4-posterior --branch constant "
            f"--pc-catalog {workflow.BRYSON_PC_CATALOG} "
            f"--stellar-catalog {workflow.BRYSON_STELLAR_CATALOG} "
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
