#!/usr/bin/env python3
"""Fail-closed GitHub Actions provenance and shell-safety policy."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import shlex
from pathlib import Path
from typing import Any, Callable

try:
    import yaml
    from yaml.constructor import ConstructorError
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
    from yaml.tokens import AliasToken, AnchorToken, TagToken
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by clean CI bootstrap
    raise SystemExit(
        "WORKFLOW SECURITY FAIL: PyYAML is required to parse workflow semantics"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
DATA_LOCKS = json.loads(
    (ROOT / "provenance" / "DATA_LOCKS.json").read_text(encoding="utf-8")
)
BRYSON_SOURCE_SHA256 = DATA_LOCKS["locks"]["bryson_rate_models_3d"][
    "expected_sha256"
]
BRYSON_PC_CATALOG = (
    "/tmp/DR25-occurrence-public/insolation/koiCatalogs/PCs_dr25_hab2.csv"
)
BRYSON_STELLAR_CATALOG = (
    "/tmp/DR25-occurrence-public/stellarCatalogs/"
    "dr25_stellar_berger2020_clean_hab2.txt"
)
MAX_WORKFLOW_BYTES = 1_000_000

PINNED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
}

PROTECTED_PYTHON_SCRIPTS = frozenset(
    {
        "scripts/verify_accepted_aggregate.py",
        "scripts/verify_age_cut_sensitivity.py",
        "scripts/verify_host_artifact_contract.py",
        "scripts/verify_metallicity_tams_audit.py",
        "scripts/verify_numerical_runtime.py",
        "research/bryson-joint-posterior/aggregate_hab2_joint_posterior.py",
        "research/bryson-joint-posterior/propagate_hab2_joint_posterior.py",
        "research/bryson-joint-posterior/run_hab2_joint_posterior.py",
        "research/jj-host-export/assert_canonical_tams.py",
        "research/jj-host-export/age_cut_sensitivity.py",
        "research/jj-host-export/bryson_model_form_sensitivity.py",
        "research/jj-host-export/export_raw_eligible.py",
        "research/jj-host-export/hz_boundary_sensitivity.py",
        "research/jj-host-export/occurrence_reference.py",
        "research/jj-host-export/promote_tams_provider.py",
        "research/jj-host-export/recalc_all_branches_tams.py",
        "research/jj-host-export/run_jj_export.py",
        "research/jj-host-export/metallicity_tams_differential_sensitivity.py",
        "research/jj-host-export/tams_ab_test.py",
        "research/jj-host-export/tams_reference.py",
    }
)
JJ_EXPORT_SCRIPT = "research/jj-host-export/run_jj_export.py"
JJ_EXPORT_INTEGRITY_LINES = (
    'JJ_EXPORT_WORKING_BLOB="$(git hash-object '
    '"$GITHUB_WORKSPACE/research/jj-host-export/run_jj_export.py")"',
    'JJ_EXPORT_TRACKED_BLOB="$(git rev-parse '
    'HEAD:research/jj-host-export/run_jj_export.py)"',
    '[[ "$JJ_EXPORT_WORKING_BLOB" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$JJ_EXPORT_TRACKED_BLOB" =~ ^[0-9a-f]{40}$ ]]',
    '[[ "$JJ_EXPORT_WORKING_BLOB" == "$JJ_EXPORT_TRACKED_BLOB" ]]',
)
EXPECTED_JJ_EXPORT_ARGV = {
    "jj-g-host-export.yml": (
        "python",
        f"$GITHUB_WORKSPACE/{JJ_EXPORT_SCRIPT}",
        "--jj-root",
        "/tmp/jjmodel-src",
        "--run-dir",
        "/tmp/jj-run",
        "--out",
        "$GITHUB_WORKSPACE/results/jj",
        "--iso",
        "Padova",
        "--expected-radial-step-kpc",
        "0.5",
    ),
    "jj-tams-metallicity-differential.yml": (
        "python",
        f"$GITHUB_WORKSPACE/{JJ_EXPORT_SCRIPT}",
        "--jj-root",
        "/tmp/jjmodel-src",
        "--run-dir",
        "/tmp/jj-diff",
        "--out",
        "/tmp/metallicity-host",
        "--iso",
        "Padova",
        "--expected-radial-step-kpc",
        "0.5",
    ),
}
AGE_CUT_PRODUCER_SCRIPT = "research/jj-host-export/age_cut_sensitivity.py"
AGE_CUT_VERIFIER_SCRIPT = "scripts/verify_age_cut_sensitivity.py"
AGE_CUT_ARTIFACT_FILES = (
    "AGE_CUT_SENSITIVITY.json",
    "age_cut_radial.csv",
    "JJ_SSP_INPUT_SHA256SUMS.txt",
    "SHA256SUMS_age_cut_sensitivity.txt",
)
APPROVED_EXPLICIT_SHELLS = frozenset(
    {"bash --noprofile --norc -e -o pipefail {0}"}
)
FORBIDDEN_SHELL_ENV_KEYS = frozenset({"BASH_ENV", "ENV", "SHELLOPTS"})
PROTECTED_EXECUTION_ENV_KEYS = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_ORIGIN_PATH",
        "GITHUB_WORKSPACE",
        "GITHUB_ENV",
        "GITHUB_PATH",
    }
)
PROTECTED_EXECUTION_ENV_PREFIXES = ("BASH_FUNC_", "LD_")
SHELL_COMMAND_REBINDERS = frozenset(
    {"alias", "unalias", "hash", "enable", "shopt"}
)
SHELL_COMMAND_WRAPPERS = frozenset({"command", "builtin"})
SHELL_COMMAND_INTRODUCERS = frozenset(
    {"if", "elif", "while", "until", "then", "else", "do", "!", "time"}
)

EXPECTED_NUMERICAL_ENV = {
    "NPY_DISABLE_CPU_FEATURES": (
        "AVX512F,AVX512CD,AVX512_SKX,"
        "AVX512_CLX,AVX512_CNL,AVX512_ICL"
    ),
    "OPENBLAS_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "PYTHONHASHSEED": "0",
}
EXPECTED_NUMERICAL_RUNTIME_OUTPUTS: dict[str, tuple[str | None, ...]] = {
    "bryson-v4-corrected-pilot.yml": ("numerical_runtime.json", None),
    "bryson-v4-corrected-production.yml": (
        "numerical_runtime.json",
        None,
        None,
    ),
    "bryson-v4-corrected-zero-extended.yml": (
        "numerical_runtime.json",
        None,
        None,
    ),
    "bryson-v4-measurement-tests.yml": (None,),
    "bryson-v4-propagate-constant.yml": (None,),
    "jj-g-host-export.yml": (
        "results/jj/NUMERICAL_RUNTIME_POLICY.json",
    ),
    "jj-tams-metallicity-differential.yml": (
        "results/metallicity-audit/NUMERICAL_RUNTIME_POLICY.json",
    ),
    "jj-tams-radial-convergence.yml": (
        "results/tams-convergence/NUMERICAL_RUNTIME_POLICY.json",
    ),
    "verify.yml": (None, None),
}
PRIVATE_REPOSITORY_JOB_IF = "${{ github.event.repository.private == true }}"
EXPECTED_WORKFLOW_JOBS: dict[str, tuple[str, ...]] = {
    "bryson-v4-corrected-pilot.yml": (
        "prepare-inputs",
        "pilot",
        "seed-stability",
    ),
    "bryson-v4-corrected-production.yml": (
        "prepare-inputs",
        "prepare-hosts",
        "reconstruct-shards",
        "aggregate",
        "propagate",
    ),
    "bryson-v4-corrected-zero-extended.yml": (
        "prepare-inputs",
        "prepare-hosts",
        "reconstruct-shards",
        "aggregate",
        "propagate",
    ),
    "bryson-v4-measurement-tests.yml": ("measurement-model",),
    "bryson-v4-propagate-constant.yml": ("propagate",),
    "jj-g-host-export.yml": ("jj-export",),
    "jj-tams-metallicity-differential.yml": ("audit",),
    "jj-tams-radial-convergence.yml": ("convergence",),
    "verify.yml": ("verify", "publish-source-release-assets"),
}
PUBLIC_JOB_WORKFLOWS = frozenset(
    {"bryson-v4-measurement-tests.yml", "verify.yml"}
)
RELEASE_PACKAGE_STEP_NAME = "Build deterministic license-cleared source package"
RELEASE_LINEAGE_STEP_NAME = "Bind v4.0.4 tag to exact main lineage"
RELEASE_PREPARE_STAGE_STEP_NAME = (
    "Prepare fresh exact v4.0.4 four-file release envelope"
)
RELEASE_STAGE_STEP_NAME = "Stage exact v4.0.4 four-file release envelope"
RELEASE_PUBLISH_LINEAGE_STEP_NAME = (
    "Rebind v4.0.4 tag to exact main lineage before publication"
)
RELEASE_FRESH_DESTINATION_STEP_NAME = (
    "Require a fresh four-file release envelope destination"
)
RELEASE_INVENTORY_STEP_NAME = (
    "Verify exact four-file release envelope inventory"
)
RELEASE_FULL_ROUNDTRIP_STEP_NAME = (
    "Reverify full v4.0.4 package roundtrip without write credentials"
)
RELEASE_PUBLISH_STEP_NAME = (
    "Attach and recheck exact v4.0.4 source release assets"
)
RELEASE_PUBLISH_INSTALL_STEP_NAME = (
    "Install locked dependencies for publisher verification"
)
RELEASE_PACKAGE_TAG_IF = (
    "github.event_name == 'push' && "
    "github.repository == "
    "'jerseroman/Exo-Earth-Candidate-Population-Projection-Pipeline' && "
    "github.ref == 'refs/tags/v4.0.4' && "
    "github.ref_type == 'tag' && github.ref_name == 'v4.0.4'"
)

GITHUB_EXPRESSION_RE = re.compile(r"\$\{\{")
PIP_INSTALL_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_.-])
    (?:
        (?:python(?:3(?:\.\d+)*)?|py)(?:\.exe)?\s+-m\s+pip
        |pip(?:3(?:\.\d+)*)?(?:\.exe)?
    )
    (?P<global_options>[^\n;&|]*?)
    \binstall\b
    (?P<arguments>[^\n;&|]*)
    """,
    re.IGNORECASE | re.VERBOSE,
)
GH_DOWNLOAD_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])gh\s+run\s+download\b", re.IGNORECASE
)
INSTALL_WORD_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])install(?![A-Za-z0-9_.-])", re.IGNORECASE
)
DYNAMIC_COMMAND_RE = re.compile(
    r'''(?mx)
    (?:^|[;&|]\s*)
    \s*(?:["']?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?["']?)\s+
    '''
)
DYNAMIC_EXECUTOR_RE = re.compile(
    r'''(?im)^\s*(?:command|env|exec|xargs)\b[^\n]*\$\{?[A-Za-z_]'''
)
SHELL_STRING_EXEC_RE = re.compile(r"(?im)^\s*(?:bash|sh)\s+-c\b")
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")
SET_PLUS_RE = re.compile(
    r"(?i)(?:^|[;&|(){}]\s*|\b(?:then|do)\s+)"
    r"(?:!\s+)?(?:(?:command|builtin)\s+)?set\s+\+"
)
TRAP_COMMAND_RE = re.compile(
    r"(?i)(?:^|[;&|(){}]\s*|\b(?:then|do)\s+)"
    r"(?:!\s+)?(?:(?:command|builtin)\s+)?trap\b"
)
INPUT_EXPRESSION_RE = re.compile(
    r"\$\{\{(?:(?!\}\}).)*\b(?:inputs|github\.event\.inputs)\b(?:(?!\}\}).)*\}\}",
    re.DOTALL,
)
EXACT_INPUT_BINDING_RE = re.compile(
    r"^\$\{\{\s*inputs\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$"
)
ENV_MUTATION_COMMAND_RE = re.compile(
    r"(?i)^(?:(?:command|builtin)\s+)?"
    r"(?:export|unset|env|declare|typeset|readonly|source|eval|read|printf\s+-v)\b"
    r"|^\.\s+"
)
CWD_MUTATION_COMMAND_RE = re.compile(
    r"(?i)^(?:(?:command|builtin)\s+)?(?:cd|pushd|popd)\b"
)


@dataclass(frozen=True)
class ShellCommand:
    """One semantic ``jobs.*.steps[*].run`` scalar."""

    run_line: int
    body_start_line: int
    scalar_style: str
    body: str
    step_name: str
    working_directory: str | None = None


@dataclass(frozen=True)
class ActionUse:
    """One semantic ``jobs.*.steps[*].uses`` scalar."""

    line: int
    value: str


@dataclass(frozen=True)
class ParsedWorkflow:
    data: dict[str, Any]
    commands: list[ShellCommand]
    actions: list[ActionUse]


@dataclass(frozen=True)
class LogicalShellLine:
    line_number: int
    text: str
    top_level: bool


class StrictBaseLoader(yaml.BaseLoader):
    """BaseLoader semantics with duplicate-key rejection."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


StrictBaseLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    StrictBaseLoader.construct_mapping,
)


def fail(message: str) -> None:
    raise SystemExit(f"WORKFLOW SECURITY FAIL: {message}")


def _validate_yaml_nodes(node: Node, source: str) -> None:
    if isinstance(node, MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, ScalarNode):
                fail(
                    f"{source}:{key_node.start_mark.line + 1} has a non-scalar "
                    "mapping key"
                )
            key = key_node.value
            if key in seen:
                fail(
                    f"{source}:{key_node.start_mark.line + 1} repeats YAML key "
                    f"{key!r}"
                )
            if key == "<<":
                fail(
                    f"{source}:{key_node.start_mark.line + 1} uses a YAML merge key"
                )
            seen.add(key)
            _validate_yaml_nodes(value_node, source)
    elif isinstance(node, SequenceNode):
        for value_node in node.value:
            _validate_yaml_nodes(value_node, source)


def _mapping_items(node: Node, source: str, context: str) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        fail(f"{source} {context} is not a YAML mapping")
    return {
        key_node.value: value_node
        for key_node, value_node in node.value
        if isinstance(key_node, ScalarNode)
    }


def parse_workflow_text(text: str, source: str = "<memory>") -> ParsedWorkflow:
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        fail(f"{source} exceeds the audited workflow size limit")
    try:
        for token in yaml.scan(text, Loader=yaml.BaseLoader):
            if isinstance(token, (AnchorToken, AliasToken)):
                fail(
                    f"{source}:{token.start_mark.line + 1} uses a YAML anchor or alias"
                )
            if isinstance(token, TagToken):
                fail(f"{source}:{token.start_mark.line + 1} uses an explicit YAML tag")
        root_node = yaml.compose(text, Loader=yaml.BaseLoader)
        data = yaml.load(text, Loader=StrictBaseLoader)
    except yaml.YAMLError as exc:
        fail(f"cannot parse {source} as strict YAML: {exc}")
    if root_node is None or not isinstance(root_node, MappingNode):
        fail(f"{source} root is not a YAML mapping")
    if not isinstance(data, dict):
        fail(f"{source} did not construct a workflow mapping")
    _validate_yaml_nodes(root_node, source)

    root = _mapping_items(root_node, source, "root")

    def default_working_directory(
        owner: dict[str, Node], context: str
    ) -> str | None:
        defaults_node = owner.get("defaults")
        if defaults_node is None:
            return None
        defaults = _mapping_items(defaults_node, source, f"{context} defaults")
        run_defaults_node = defaults.get("run")
        if run_defaults_node is None:
            return None
        run_defaults = _mapping_items(
            run_defaults_node, source, f"{context} run defaults"
        )
        directory_node = run_defaults.get("working-directory")
        if directory_node is None:
            return None
        if not isinstance(directory_node, ScalarNode):
            fail(
                f"{source}:{directory_node.start_mark.line + 1} default "
                "working-directory is not a scalar"
            )
        return directory_node.value

    workflow_working_directory = default_working_directory(root, "workflow")
    jobs_node = root.get("jobs")
    if jobs_node is None:
        fail(f"{source} has no jobs mapping")
    jobs = _mapping_items(jobs_node, source, "jobs")

    commands: list[ShellCommand] = []
    actions: list[ActionUse] = []
    for job_name, job_node in jobs.items():
        job = _mapping_items(job_node, source, f"job {job_name!r}")
        job_working_directory = (
            default_working_directory(job, f"job {job_name!r}")
            or workflow_working_directory
        )
        job_uses_node = job.get("uses")
        if job_uses_node is not None:
            if not isinstance(job_uses_node, ScalarNode):
                fail(
                    f"{source}:{job_uses_node.start_mark.line + 1} job uses is not a scalar"
                )
            actions.append(
                ActionUse(
                    line=job_uses_node.start_mark.line + 1,
                    value=job_uses_node.value,
                )
            )
        steps_node = job.get("steps")
        if steps_node is None:
            continue
        if not isinstance(steps_node, SequenceNode):
            fail(f"{source} job {job_name!r} steps is not a YAML sequence")
        for step_index, step_node in enumerate(steps_node.value):
            step = _mapping_items(
                step_node, source, f"job {job_name!r} step {step_index + 1}"
            )
            name_node = step.get("name")
            step_name = (
                name_node.value
                if isinstance(name_node, ScalarNode)
                else f"{job_name} step {step_index + 1}"
            )
            run_node = step.get("run")
            if run_node is not None:
                if not isinstance(run_node, ScalarNode):
                    fail(
                        f"{source}:{run_node.start_mark.line + 1} run is not a scalar"
                    )
                style = run_node.style if run_node.style in {"|", ">"} else "inline"
                working_directory_node = step.get("working-directory")
                if working_directory_node is not None and not isinstance(
                    working_directory_node, ScalarNode
                ):
                    fail(
                        f"{source}:{working_directory_node.start_mark.line + 1} "
                        "working-directory is not a scalar"
                    )
                commands.append(
                    ShellCommand(
                        run_line=run_node.start_mark.line + 1,
                        body_start_line=run_node.start_mark.line + 1,
                        scalar_style=style,
                        body=run_node.value,
                        step_name=step_name,
                        working_directory=(
                            working_directory_node.value
                            if isinstance(working_directory_node, ScalarNode)
                            else job_working_directory
                        ),
                    )
                )
            uses_node = step.get("uses")
            if uses_node is not None:
                if not isinstance(uses_node, ScalarNode):
                    fail(
                        f"{source}:{uses_node.start_mark.line + 1} uses is not a scalar"
                    )
                actions.append(
                    ActionUse(line=uses_node.start_mark.line + 1, value=uses_node.value)
                )
    return ParsedWorkflow(data=data, commands=commands, actions=actions)


def parse_workflow(path: Path) -> ParsedWorkflow:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read {path}: {exc}")
    return parse_workflow_text(text, path.name)


def shell_commands_from_text(text: str) -> list[ShellCommand]:
    return parse_workflow_text(text).commands


def shell_commands(path: Path) -> list[ShellCommand]:
    return parse_workflow(path).commands


def _strip_shell_comments(body: str) -> str:
    """Remove unquoted shell comments so comments cannot satisfy policy."""

    output: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    in_comment = False
    for character in body:
        if in_comment:
            if character == "\n":
                output.append(character)
                in_comment = False
                escaped = False
            continue
        if character == "\n":
            output.append(character)
            escaped = False
            continue
        if escaped:
            output.append(character)
            escaped = False
            continue
        if character == "\\" and not in_single:
            output.append(character)
            escaped = True
            continue
        if character == "'" and not in_double:
            in_single = not in_single
            output.append(character)
            continue
        if character == '"' and not in_single:
            in_double = not in_double
            output.append(character)
            continue
        if character == "#" and not in_single and not in_double:
            if not output or output[-1].isspace():
                in_comment = True
                continue
        output.append(character)
    return "".join(output)


def active_shell_text(command: ShellCommand) -> str:
    body = _strip_shell_comments(command.body)
    return re.sub(r"\\[ \t]*\n[ \t]*", " ", body)


def _logical_shell_lines(command: ShellCommand) -> list[LogicalShellLine]:
    """Return continuation-joined shell lines, excluding heredoc payloads."""

    body = _strip_shell_comments(command.body)
    filtered: list[tuple[int, str]] = []
    heredoc: str | None = None
    for offset, line in enumerate(body.splitlines()):
        line_number = command.body_start_line + offset
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        filtered.append((line_number, line))
        match = HEREDOC_RE.search(line)
        if match is not None:
            heredoc = match.group(1)
    if heredoc is not None:
        fail(
            f"run line {command.run_line} has an unterminated heredoc {heredoc!r}"
        )

    joined: list[tuple[int, str]] = []
    buffer = ""
    buffer_line = command.body_start_line
    for line_number, line in filtered:
        if not buffer:
            buffer_line = line_number
        stripped_right = line.rstrip()
        if stripped_right.endswith("\\"):
            buffer += stripped_right[:-1] + " "
            continue
        joined.append((buffer_line, buffer + line))
        buffer = ""
    if buffer:
        fail(f"run line {command.run_line} ends with a shell continuation")

    logical: list[LogicalShellLine] = []
    stack: list[str] = []
    for line_number, raw in joined:
        text = raw.strip()
        if not text:
            continue
        if re.fullmatch(r"fi", text):
            if stack and stack[-1] == "if":
                stack.pop()
        elif re.fullmatch(r"done", text):
            if stack and stack[-1] == "loop":
                stack.pop()
        elif re.fullmatch(r"esac", text):
            if stack and stack[-1] == "case":
                stack.pop()
        elif re.fullmatch(r"}", text):
            if stack and stack[-1] == "function":
                stack.pop()

        logical.append(
            LogicalShellLine(
                line_number=line_number,
                text=text,
                top_level=not stack,
            )
        )

        if re.match(r"^if\b.*(?:;|\s)then\s*$", text):
            stack.append("if")
        elif re.match(r"^(?:for|while|until|select)\b.*(?:;|\s)do\s*$", text):
            stack.append("loop")
        elif re.match(r"^case\b.*\bin\s*$", text):
            stack.append("case")
        elif re.match(
            r"^(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*(?:\(\s*\))?\s*\{\s*$",
            text,
        ):
            stack.append("function")
    if stack:
        fail(f"run line {command.run_line} has unbalanced shell control flow")
    return logical


def _shell_tokens(arguments: str) -> list[str] | None:
    lexer = shlex.shlex(arguments, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:
        return None


def _shell_syntax_tokens(text: str) -> list[str] | None:
    """Tokenize shell syntax sufficiently to detect command rebinding."""

    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|(){}")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:
        return None


def _forbidden_shell_command_rebinding(text: str) -> str | None:
    """Return the forbidden rebinding construct present in one shell line."""

    tokens = _shell_syntax_tokens(text)
    if tokens is None:
        return "unparseable shell syntax"

    command_expected = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token and all(character in ";&|(){}" for character in token):
            command_expected = True
            index += 1
            continue
        if token in SHELL_COMMAND_INTRODUCERS:
            command_expected = True
            index += 1
            continue
        if not command_expected:
            index += 1
            continue

        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]+\])?\+?=.*", token):
            index += 1
            continue

        command_index = index
        while (
            command_index < len(tokens)
            and tokens[command_index] in SHELL_COMMAND_WRAPPERS
        ):
            command_index += 1
            while (
                command_index < len(tokens)
                and tokens[command_index].startswith("-")
            ):
                command_index += 1
        if command_index >= len(tokens):
            return None

        command_name = tokens[command_index]
        if command_name == "function":
            return "shell function definition"
        if command_name in SHELL_COMMAND_REBINDERS:
            return f"shell command rebinder {command_name!r}"

        next_index = command_index + 1
        if (
            next_index < len(tokens)
            and tokens[next_index].startswith("()")
        ):
            return "shell function definition"

        command_expected = False
        index = command_index + 1
    return None


def _protected_python_path_violation(line: LogicalShellLine) -> str | None:
    """Reject protected-source mentions except canonical execution/integrity forms."""

    syntax_tokens = _shell_syntax_tokens(line.text)
    if syntax_tokens is None:
        return "unparseable shell syntax around a protected Python path"

    references: list[tuple[str, str]] = []
    for token in syntax_tokens:
        for script_path in PROTECTED_PYTHON_SCRIPTS:
            protected_name = script_path.rsplit("/", 1)[-1]
            basename_mention = re.search(
                rf"(?<![A-Za-z0-9_.-]){re.escape(protected_name)}"
                r"(?![A-Za-z0-9_.-])",
                token,
            )
            if script_path in token or basename_mention is not None:
                references.append((script_path, token))

    if not references:
        return None
    if line.text in JJ_EXPORT_INTEGRITY_LINES[:2]:
        return None
    if len(references) != 1:
        return "multiple or ambiguous protected Python path references"

    script_path, reference_token = references[0]
    expected_path = f"$GITHUB_WORKSPACE/{script_path}"
    argv = _argv(line)
    if (
        argv is None
        or len(argv) < 2
        or not re.fullmatch(
            r"(?:python(?:3(?:\.\d+)*)?|py)(?:\.exe)?", argv[0]
        )
        or argv[1] != expected_path
        or reference_token != expected_path
    ):
        return (
            f"non-canonical reference to protected Python source {script_path!r}; "
            f"only an absolute interpreter invocation of {expected_path!r} is allowed"
        )
    return None


def _locked_pip_install(
    arguments: str, global_options: str = ""
) -> tuple[bool, str]:
    if global_options.strip():
        return False, "pip global options before install are not approved"
    tokens = _shell_tokens(arguments)
    if tokens is None:
        return False, "pip arguments are not valid shell tokens"
    if "--upgrade" in tokens or "-U" in tokens:
        return False, "pip upgrade is forbidden in workflows"

    remaining = list(tokens)
    required_lock_flags = ("--only-binary=:all:", "--require-hashes")
    if all(remaining.count(flag) == 1 for flag in required_lock_flags):
        for flag in required_lock_flags:
            remaining.remove(flag)
        if (
            len(remaining) == 2
            and remaining[0] in {"-r", "--requirement"}
            and remaining[1] in {"requirements.txt", "./requirements.txt"}
        ):
            return True, "binary-only hash-locked requirements"
        if len(remaining) == 1 and remaining[0] in {
            "--requirement=requirements.txt",
            "--requirement=./requirements.txt",
        }:
            return True, "binary-only hash-locked requirements"

    remaining = list(tokens)
    required_editable_flags = ("--no-deps", "--no-build-isolation")
    if all(remaining.count(flag) == 1 for flag in required_editable_flags):
        for flag in required_editable_flags:
            remaining.remove(flag)
        if remaining in (["-e", "."], ["--editable", "."], ["--editable=."]):
            return True, "dependency-free, build-isolation-free editable install"

    return False, "install is not an approved closed installation form"


def audit_shell_command(path: Path, command: ShellCommand) -> int:
    if GITHUB_EXPRESSION_RE.search(command.body):
        fail(
            f"{path.name}:{command.run_line} interpolates a GitHub expression "
            "directly into shell; bind it through env"
        )
    body = active_shell_text(command)
    if re.search(r"(?im)^\s*(?:export\s+)?PIP_[A-Za-z0-9_]+\s*=", body):
        fail(f"{path.name}:{command.run_line} mutates pip through an environment variable")
    if (
        DYNAMIC_COMMAND_RE.search(body)
        or DYNAMIC_EXECUTOR_RE.search(body)
        or SHELL_STRING_EXEC_RE.search(body)
    ):
        fail(
            f"{path.name}:{command.run_line} uses a dynamic shell command path"
        )

    logical_lines = _logical_shell_lines(command)
    for line in logical_lines:
        normalized = _normalized_line(line)
        protected_path_violation = _protected_python_path_violation(line)
        if protected_path_violation is not None:
            fail(
                f"{path.name}:{line.line_number} uses {protected_path_violation}"
            )
        rebinding = _forbidden_shell_command_rebinding(line.text)
        if rebinding is not None:
            fail(
                f"{path.name}:{line.line_number} uses forbidden {rebinding}; "
                "the Python command path is immutable"
            )
        if ENV_MUTATION_COMMAND_RE.search(normalized):
            fail(
                f"{path.name}:{line.line_number} uses a shell environment-"
                "mutation command; workflow runtime policy is immutable"
            )
        forbidden_shell_environment_names = {
            *EXPECTED_NUMERICAL_ENV,
            "NPY_ENABLE_CPU_FEATURES",
            *(PROTECTED_EXECUTION_ENV_KEYS - {"GITHUB_WORKSPACE"}),
        }
        for name in forbidden_shell_environment_names:
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", line.text):
                fail(
                    f"{path.name}:{line.line_number} references protected runtime "
                    f"environment name {name!r} from shell"
                )
        for prefix in PROTECTED_EXECUTION_ENV_PREFIXES:
            if re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(prefix)}",
                line.text,
            ):
                fail(
                    f"{path.name}:{line.line_number} references protected runtime "
                    f"environment prefix {prefix!r} from shell"
                )
        if re.search(
            r"(?<![A-Za-z0-9_])GITHUB_WORKSPACE\s*=", line.text
        ):
            fail(
                f"{path.name}:{line.line_number} attempts to overwrite "
                "GITHUB_WORKSPACE from shell"
            )
        if SET_PLUS_RE.search(line.text):
            fail(
                f"{path.name}:{line.line_number} disables shell options with "
                "set +...; fail-fast shell semantics are mandatory"
            )
        if TRAP_COMMAND_RE.search(line.text):
            fail(
                f"{path.name}:{line.line_number} installs or changes a shell trap; "
                "ERR handling must remain immutable"
            )
    matches: list[tuple[LogicalShellLine, re.Match[str]]] = []
    for line in logical_lines:
        line_matches = list(PIP_INSTALL_RE.finditer(line.text))
        install_words = list(INSTALL_WORD_RE.finditer(line.text))
        if line_matches:
            match = line_matches[0]
            if (
                len(line_matches) != 1
                or match.span() != (0, len(line.text))
                or not line.top_level
                or _has_shell_control(line.text)
            ):
                fail(
                    f"{path.name}:{line.line_number} must express pip install "
                    "as one complete, unconditional command with no shell-control "
                    "prefix or suffix"
                )
            matches.append((line, match))
        for install_word in install_words:
            if not any(
                match.start() <= install_word.start() < match.end()
                for match in line_matches
            ):
                fail(
                    f"{path.name}:{line.line_number} contains a dynamically "
                    "assembled or non-approved install command"
                )
    if matches and command.working_directory is not None:
        fail(
            f"{path.name}:{command.run_line} runs pip from a step-level "
            "working-directory"
        )
    for line, match in matches:
        locked, reason = _locked_pip_install(
            match.group("arguments"), match.group("global_options")
        )
        if not locked:
            fail(
                f"{path.name}:{command.run_line} contains an unlocked pip install "
                f"({reason}): {match.group(0).strip()!r}"
            )
        if reason == "binary-only hash-locked requirements":
            top_level = [item for item in logical_lines if item.top_level]
            if (
                not top_level
                or line != top_level[0]
                or not re.match(
                    r"^(?:python(?:3(?:\.\d+)*)?|py)(?:\.exe)?\s+-m\s+pip\s+install\b",
                    top_level[0].text,
                    re.IGNORECASE,
                )
            ):
                fail(
                    f"{path.name}:{command.run_line} must install the repository "
                    "lock as the first executable command in its step"
                )
    return len(matches)


def validate_action_uses(path: Path, actions: list[ActionUse]) -> set[str]:
    observed: set[str] = set()
    for action_use in actions:
        value = action_use.value
        if value.startswith("./"):
            fail(
                f"{path.name}:{action_use.line} uses a local action outside the "
                "closed external-action policy"
            )
        if "@" not in value:
            fail(f"{path.name}:{action_use.line} action is not SHA-pinned: {value!r}")
        action, ref = value.rsplit("@", 1)
        expected = PINNED_ACTIONS.get(action)
        if expected is None:
            fail(f"{path.name}:{action_use.line} uses unreviewed action {action!r}")
        if ref != expected:
            fail(
                f"{path.name}:{action_use.line} action {action!r} is not pinned "
                f"to audited SHA {expected}: {ref!r}"
            )
        observed.add(action)
    return observed


def _walk_mappings(value: Any):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk_mappings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_mappings(nested)


def validate_workflow_environment(
    path: Path,
    data: dict[str, Any],
    allowed_input_bindings: set[tuple[str, str]],
) -> None:
    observed_input_bindings: set[tuple[str, str]] = set()
    for mapping in _walk_mappings(data):
        for key, value in mapping.items():
            if isinstance(key, str) and key.startswith("PIP_"):
                fail(f"{path.name} defines forbidden pip environment key {key!r}")
            if key in FORBIDDEN_SHELL_ENV_KEYS:
                fail(
                    f"{path.name} defines forbidden shell environment key {key!r}"
                )
            if key == "continue-on-error" and value != "false":
                fail(
                    f"{path.name} enables or dynamically controls continue-on-error: "
                    f"{value!r}"
                )
            if key == "shell" and value not in APPROVED_EXPLICIT_SHELLS:
                fail(f"{path.name} uses an unapproved explicit shell: {value!r}")
            if not isinstance(value, str):
                continue
            if INPUT_EXPRESSION_RE.search(value) is None:
                continue
            binding = EXACT_INPUT_BINDING_RE.fullmatch(value)
            if binding is None or not isinstance(key, str):
                fail(
                    f"{path.name} contains a non-canonical workflow-input binding: "
                    f"{key!r}={value!r}"
                )
            observed_input_bindings.add((key, binding.group(1)))
    if observed_input_bindings != allowed_input_bindings:
        fail(
            f"{path.name} workflow-input binding set changed: "
            f"observed={sorted(observed_input_bindings)}, "
            f"expected={sorted(allowed_input_bindings)}"
        )


def require_numerical_runtime_environment(
    path: Path, data: dict[str, Any]
) -> None:
    """Require one immutable workflow-level numerical environment."""

    expected_env = dict(EXPECTED_NUMERICAL_ENV)
    if path.name == "verify.yml":
        expected_env["PYTHONDONTWRITEBYTECODE"] = "1"
    top_level_env = data.get("env")
    if top_level_env != expected_env:
        fail(
            f"{path.name} numerical runtime environment changed: "
            f"observed={top_level_env!r}, expected={expected_env!r}"
        )

    protected_names = {
        *EXPECTED_NUMERICAL_ENV,
        "PYTHONDONTWRITEBYTECODE",
        "NPY_ENABLE_CPU_FEATURES",
        *PROTECTED_EXECUTION_ENV_KEYS,
    }
    for mapping in _walk_mappings(data):
        if mapping is top_level_env:
            continue
        overlap = protected_names.intersection(mapping)
        if overlap:
            fail(
                f"{path.name} overrides or rebinds protected numerical runtime "
                f"keys below workflow scope: {sorted(overlap)!r}"
            )
        prefixed = sorted(
            key
            for key in mapping
            if isinstance(key, str)
            and key.startswith(PROTECTED_EXECUTION_ENV_PREFIXES)
        )
        if prefixed:
            fail(
                f"{path.name} defines protected execution-environment prefixes "
                f"below workflow scope: {prefixed!r}"
            )


def require_workflow_execution_conditions(
    path: Path, data: dict[str, Any]
) -> None:
    """Pin audited job identity and forbid suppression of individual steps."""

    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        fail(f"{path.name} has no jobs mapping")
    expected_jobs = EXPECTED_WORKFLOW_JOBS.get(path.name)
    if expected_jobs is None or tuple(jobs) != expected_jobs:
        fail(
            f"{path.name} audited job set/order changed: observed={tuple(jobs)!r}, "
            f"expected={expected_jobs!r}"
        )

    public_jobs = path.name in PUBLIC_JOB_WORKFLOWS
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            fail(f"{path.name} job {job_name!r} is not a mapping")
        if public_jobs:
            expected_job_condition = (
                RELEASE_PACKAGE_TAG_IF
                if path.name == "verify.yml"
                and job_name == "publish-source-release-assets"
                else None
            )
            if expected_job_condition is None and "if" in job:
                fail(
                    f"{path.name} public audit job {job_name!r} must not define if"
                )
            if expected_job_condition is not None and job.get("if") != expected_job_condition:
                fail(
                    f"{path.name} release publisher job must use the exact tag gate"
                )
        elif job.get("if") != PRIVATE_REPOSITORY_JOB_IF:
            fail(
                f"{path.name} job {job_name!r} must use the exact private-"
                "repository execution condition"
            )
        steps = job.get("steps")
        if not isinstance(steps, list):
            fail(f"{path.name} job {job_name!r} has no explicit steps list")
        conditional_steps = 0
        for step_index, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                fail(
                    f"{path.name} job {job_name!r} step {step_index} is not a mapping"
                )
            if "if" in step:
                if (
                    path.name != "verify.yml"
                    or job_name != "verify"
                    or step.get("name")
                    not in {
                        RELEASE_LINEAGE_STEP_NAME,
                        RELEASE_PACKAGE_STEP_NAME,
                        RELEASE_PREPARE_STAGE_STEP_NAME,
                        RELEASE_STAGE_STEP_NAME,
                    }
                    or step.get("if") != RELEASE_PACKAGE_TAG_IF
                ):
                    fail(
                        f"{path.name} job {job_name!r} step {step_index} uses an "
                        "unapproved conditional execution gate"
                    )
                conditional_steps += 1
        expected_conditional_steps = (
            4 if path.name == "verify.yml" and job_name == "verify" else 0
        )
        if conditional_steps != expected_conditional_steps:
            fail(
                f"{path.name} job {job_name!r} release-condition count changed"
            )


def require_release_package_tag_gate(path: Path, data: dict[str, Any]) -> None:
    """Keep ordinary PR/push verification green and release packaging fail-closed."""

    if path.name != "verify.yml":
        return
    trigger = data.get("on")
    expected_trigger = {
        "push": {"branches": ["main"], "tags": ["v4.0.4"]},
        "pull_request": "",
        "workflow_dispatch": "",
    }
    if trigger != expected_trigger:
        fail(
            f"{path.name} trigger set changed: observed={trigger!r}, "
            f"expected={expected_trigger!r}"
        )
    if data.get("permissions") != {"contents": "read"}:
        fail(f"{path.name} workflow-level permissions must be contents: read")
    jobs = data.get("jobs")
    verify_job = jobs.get("verify") if isinstance(jobs, dict) else None
    if (
        not isinstance(verify_job, dict)
        or set(verify_job) != {"permissions", "runs-on", "timeout-minutes", "steps"}
        or verify_job.get("permissions") != {"contents": "read"}
        or verify_job.get("runs-on") != "ubuntu-22.04"
        or verify_job.get("timeout-minutes") != "30"
    ):
        fail(
            f"{path.name} verify job must have the exact read-only Ubuntu 22.04 "
            "schema and 30-minute timeout"
        )
    steps = verify_job.get("steps") if isinstance(verify_job, dict) else None
    if not isinstance(steps, list) or len(steps) != 8:
        fail(f"{path.name} exact verify step set/order changed")

    def exact_body(raw: Any, expected_lines: tuple[str, ...], name: str) -> None:
        expected = "\n".join(expected_lines) + "\n"
        if raw != expected:
            fail(f"{path.name} {name} exact shell body changed")

    checkout_ref = "actions/checkout@" + PINNED_ACTIONS["actions/checkout"]
    verify_checkout = {
        "uses": checkout_ref,
        "with": {"fetch-depth": "0"},
    }
    checkout_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("uses") == checkout_ref
    ]
    if (
        len(checkout_steps) != 1
        or checkout_steps[0] != verify_checkout
        or steps[0] != verify_checkout
    ):
        fail(
            f"{path.name} release lineage requires one full-history checkout"
        )
    lineage_step = steps[1]
    if (
        not isinstance(lineage_step, dict)
        or set(lineage_step) != {"name", "if", "run"}
        or lineage_step.get("name") != RELEASE_LINEAGE_STEP_NAME
        or lineage_step.get("if") != RELEASE_PACKAGE_TAG_IF
    ):
        fail(f"{path.name} exact release-lineage preflight changed")
    lineage_body = (
        'test "$GITHUB_EVENT_NAME" = "push"',
        'test "$GITHUB_SERVER_URL" = "https://github.com"',
        'test "$GITHUB_REPOSITORY" = "jerseroman/'
        'Exo-Earth-Candidate-Population-Projection-Pipeline"',
        'test "$GITHUB_REF" = "refs/tags/v4.0.4"',
        'test "$GITHUB_REF_TYPE" = "tag"',
        'test "$GITHUB_REF_NAME" = "v4.0.4"',
        '[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$(git remote get-url origin)" = "https://github.com/jerseroman/'
        'Exo-Earth-Candidate-Population-Projection-Pipeline.git"',
        "git fetch --force --no-tags origin \\",
        "  '+refs/tags/v4.0.4:refs/tags/v4.0.4' \\",
        "  '+refs/heads/main:refs/remotes/origin/main'",
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        'test "$(git rev-parse --verify \'refs/tags/v4.0.4^{commit}\')" = "$GITHUB_SHA"',
        'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
    )
    exact_body(lineage_step.get("run"), lineage_body, RELEASE_LINEAGE_STEP_NAME)

    setup_ref = "actions/setup-python@" + PINNED_ACTIONS["actions/setup-python"]
    if steps[2] != {
        "uses": setup_ref,
        "with": {"python-version": "3.10", "cache": "pip"},
    }:
        fail(f"{path.name} exact setup-python step changed")
    if (
        not isinstance(steps[3], dict)
        or set(steps[3]) != {"name", "run"}
        or steps[3].get("name") != "Install declared compatible dependencies"
    ):
        fail(f"{path.name} exact dependency-install step schema changed")
    exact_body(
        steps[3].get("run"),
        (
            "python -m pip install --require-hashes --only-binary=:all: -r requirements.txt",
            "python -m pip check",
            'python "$GITHUB_WORKSPACE/scripts/verify_numerical_runtime.py"',
        ),
        "dependency-install step",
    )
    if steps[4] != {
        "name": "Run software-only acceptance suite",
        "run": "make verify",
    }:
        fail(f"{path.name} exact acceptance-suite step changed")
    matches = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == RELEASE_PACKAGE_STEP_NAME
    ]
    if len(matches) != 1:
        fail(f"{path.name} must contain exactly one release-package step")
    step = matches[0]
    if step is not steps[5]:
        fail(f"{path.name} release-package step order changed")
    if step.get("if") != RELEASE_PACKAGE_TAG_IF:
        fail(f"{path.name} release-package step is not tag-only")
    if step.get("env") != {"GH_TOKEN": "${{ github.token }}"}:
        fail(f"{path.name} release-package step does not use the exact read token")
    if set(step) != {"name", "if", "env", "run"}:
        fail(f"{path.name} release-package step mapping changed")

    def exact_profile(raw: Any, name: str) -> tuple[str, ...]:
        if not isinstance(raw, str):
            fail(f"{path.name} {name} has no shell body")
        command = ShellCommand(
            run_line=1,
            body_start_line=1,
            scalar_style="|",
            body=raw,
            step_name=name,
            working_directory=None,
        )
        lines = _logical_shell_lines(command)
        if any(not line.top_level or _has_shell_control(line.text) for line in lines):
            fail(f"{path.name} {name} is not an unconditional logical-command profile")
        return tuple(_normalize_shell_whitespace(line.text) for line in lines)

    results_archive = (
        "Exo-Earth-Candidate-Population-Projection-Pipeline-v4.0.4-results.zip"
    )
    results_checksum = results_archive + ".sha256"
    source_archive = (
        "exo-earth-candidate-population-projection-pipeline-4.0.4-source.zip"
    )
    expected_build_profile = (
        "mkdir -p dist",
        "gh release download v4.0.4 "
        f"--pattern '{results_archive}' --pattern '{results_checksum}' --dir dist",
        "make public-package",
        f"test -f dist/{source_archive}",
        "test -f dist/PUBLIC_SHA256SUMS",
        "python -I -B \"$GITHUB_WORKSPACE/scripts/verify_public_package_roundtrip.py\" "
        f"--archive \"$GITHUB_WORKSPACE/dist/{source_archive}\" "
        "--source-checksum \"$GITHUB_WORKSPACE/dist/PUBLIC_SHA256SUMS\" "
        f"--results-archive \"$GITHUB_WORKSPACE/dist/{results_archive}\" "
        f"--results-checksum \"$GITHUB_WORKSPACE/dist/{results_checksum}\"",
    )
    observed_build_profile = exact_profile(step.get("run"), RELEASE_PACKAGE_STEP_NAME)
    if observed_build_profile != expected_build_profile:
        fail(
            f"{path.name} release-package executable profile changed: "
            f"observed={observed_build_profile!r}"
        )

    prepare_step = steps[6]
    if (
        not isinstance(prepare_step, dict)
        or set(prepare_step) != {"name", "if", "run"}
        or prepare_step.get("name") != RELEASE_PREPARE_STAGE_STEP_NAME
        or prepare_step.get("if") != RELEASE_PACKAGE_TAG_IF
    ):
        fail(f"{path.name} exact four-file envelope preparation changed")
    exact_body(
        prepare_step.get("run"),
        (
            'STAGE="$RUNNER_TEMP/v404-source-release-stage"',
            'test -d "$RUNNER_TEMP"',
            'test ! -L "$RUNNER_TEMP"',
            'test ! -e "$STAGE"',
            'test ! -L "$STAGE"',
            'mkdir -m 0700 "$STAGE"',
            'test -d "$GITHUB_WORKSPACE/dist"',
            'test ! -L "$GITHUB_WORKSPACE/dist"',
            f'test -f "$GITHUB_WORKSPACE/dist/{source_archive}"',
            f'test ! -L "$GITHUB_WORKSPACE/dist/{source_archive}"',
            'test -f "$GITHUB_WORKSPACE/dist/PUBLIC_SHA256SUMS"',
            'test ! -L "$GITHUB_WORKSPACE/dist/PUBLIC_SHA256SUMS"',
            f'test -f "$GITHUB_WORKSPACE/dist/{results_archive}"',
            f'test ! -L "$GITHUB_WORKSPACE/dist/{results_archive}"',
            f'test -f "$GITHUB_WORKSPACE/dist/{results_checksum}"',
            f'test ! -L "$GITHUB_WORKSPACE/dist/{results_checksum}"',
            "cp --no-dereference --no-clobber \\",
            f'  "$GITHUB_WORKSPACE/dist/{source_archive}" \\',
            f'  "$STAGE/{source_archive}"',
            "cp --no-dereference --no-clobber \\",
            '  "$GITHUB_WORKSPACE/dist/PUBLIC_SHA256SUMS" \\',
            '  "$STAGE/PUBLIC_SHA256SUMS"',
            "cp --no-dereference --no-clobber \\",
            f'  "$GITHUB_WORKSPACE/dist/{results_archive}" \\',
            f'  "$STAGE/{results_archive}"',
            "cp --no-dereference --no-clobber \\",
            f'  "$GITHUB_WORKSPACE/dist/{results_checksum}" \\',
            f'  "$STAGE/{results_checksum}"',
            'test -d "$STAGE"',
            'test ! -L "$STAGE"',
            f'test -f "$STAGE/{source_archive}"',
            f'test ! -L "$STAGE/{source_archive}"',
            'test -f "$STAGE/PUBLIC_SHA256SUMS"',
            'test ! -L "$STAGE/PUBLIC_SHA256SUMS"',
            f'test -f "$STAGE/{results_archive}"',
            f'test ! -L "$STAGE/{results_archive}"',
            f'test -f "$STAGE/{results_checksum}"',
            f'test ! -L "$STAGE/{results_checksum}"',
            "find -P \"$STAGE\" -mindepth 1 -maxdepth 1 -printf '%f\\n' | "
            'LC_ALL=C sort > "$RUNNER_TEMP/v404-source-release-stage.inventory"',
            f"printf '%s\\n' {results_archive} {results_checksum} "
            f"PUBLIC_SHA256SUMS {source_archive} | cmp -s - "
            '"$RUNNER_TEMP/v404-source-release-stage.inventory"',
        ),
        RELEASE_PREPARE_STAGE_STEP_NAME,
    )

    upload_ref = "actions/upload-artifact@" + PINNED_ACTIONS["actions/upload-artifact"]
    stage_matches = [
        candidate
        for candidate in steps
        if isinstance(candidate, dict)
        and candidate.get("name") == RELEASE_STAGE_STEP_NAME
    ]
    expected_stage = {
        "name": RELEASE_STAGE_STEP_NAME,
        "if": RELEASE_PACKAGE_TAG_IF,
        "uses": upload_ref,
        "with": {
            "name": "v4.0.4-four-file-release-envelope",
            "path": (
                f"${{{{ runner.temp }}}}/v404-source-release-stage/{source_archive}\n"
                "${{ runner.temp }}/v404-source-release-stage/PUBLIC_SHA256SUMS\n"
                f"${{{{ runner.temp }}}}/v404-source-release-stage/{results_archive}\n"
                f"${{{{ runner.temp }}}}/v404-source-release-stage/{results_checksum}\n"
            ),
            "if-no-files-found": "error",
            "retention-days": "1",
        },
    }
    if stage_matches != [expected_stage] or steps[7] != expected_stage:
        fail(f"{path.name} exact four-file envelope staging step changed")

    publisher = jobs.get("publish-source-release-assets") if isinstance(jobs, dict) else None
    if not isinstance(publisher, dict):
        fail(f"{path.name} lacks the source-release publisher job")
    if (
        publisher.get("if") != RELEASE_PACKAGE_TAG_IF
        or publisher.get("needs") != "verify"
        or publisher.get("permissions") != {"contents": "write"}
        or publisher.get("runs-on") != "ubuntu-22.04"
        or publisher.get("timeout-minutes") != "10"
        or set(publisher)
        != {"if", "needs", "permissions", "runs-on", "timeout-minutes", "steps"}
    ):
        fail(f"{path.name} source-release publisher privilege boundary changed")
    publish_steps = publisher.get("steps")
    if not isinstance(publish_steps, list) or len(publish_steps) != 9:
        fail(f"{path.name} source-release publisher steps changed")
    publisher_checkout = {
        "uses": checkout_ref,
        "with": {"fetch-depth": "0", "persist-credentials": "false"},
    }
    if publish_steps[0] != publisher_checkout:
        fail(f"{path.name} source-release publisher checkout changed")

    publisher_setup = {
        "uses": setup_ref,
        "with": {"python-version": "3.10", "cache": "pip"},
    }
    if publish_steps[1] != publisher_setup:
        fail(f"{path.name} source-release publisher setup-python changed")
    publisher_install = publish_steps[2]
    if (
        not isinstance(publisher_install, dict)
        or set(publisher_install) != {"name", "run"}
        or publisher_install.get("name") != RELEASE_PUBLISH_INSTALL_STEP_NAME
    ):
        fail(f"{path.name} publisher dependency-install schema changed")
    exact_body(
        publisher_install.get("run"),
        (
            "python -m pip install --require-hashes --only-binary=:all: -r requirements.txt",
            "python -m pip check",
            'python "$GITHUB_WORKSPACE/scripts/verify_numerical_runtime.py"',
        ),
        RELEASE_PUBLISH_INSTALL_STEP_NAME,
    )

    publisher_lineage = publish_steps[7]
    if (
        not isinstance(publisher_lineage, dict)
        or set(publisher_lineage) != {"name", "run"}
        or publisher_lineage.get("name") != RELEASE_PUBLISH_LINEAGE_STEP_NAME
    ):
        fail(f"{path.name} publisher release-lineage preflight changed")
    exact_body(
        publisher_lineage.get("run"),
        lineage_body,
        RELEASE_PUBLISH_LINEAGE_STEP_NAME,
    )

    fresh_destination = publish_steps[3]
    if (
        not isinstance(fresh_destination, dict)
        or set(fresh_destination) != {"name", "run"}
        or fresh_destination.get("name") != RELEASE_FRESH_DESTINATION_STEP_NAME
    ):
        fail(f"{path.name} publisher fresh-destination guard changed")
    exact_body(
        fresh_destination.get("run"),
        (
            'RECEIVED="$RUNNER_TEMP/v404-source-release-received"',
            'test -d "$RUNNER_TEMP"',
            'test ! -L "$RUNNER_TEMP"',
            'test ! -e "$RECEIVED"',
            'test ! -L "$RECEIVED"',
        ),
        RELEASE_FRESH_DESTINATION_STEP_NAME,
    )

    download_ref = "actions/download-artifact@" + PINNED_ACTIONS["actions/download-artifact"]
    publisher_download = {
        "uses": download_ref,
        "with": {
            "name": "v4.0.4-four-file-release-envelope",
            "path": "${{ runner.temp }}/v404-source-release-received",
        },
    }
    if publish_steps[4] != publisher_download:
        fail(f"{path.name} source-release publisher transport changed")

    inventory_step = publish_steps[5]
    if (
        not isinstance(inventory_step, dict)
        or set(inventory_step) != {"name", "run"}
        or inventory_step.get("name") != RELEASE_INVENTORY_STEP_NAME
    ):
        fail(f"{path.name} exact received-envelope inventory guard changed")
    exact_body(
        inventory_step.get("run"),
        (
            'RECEIVED="$RUNNER_TEMP/v404-source-release-received"',
            'test -d "$RECEIVED"',
            'test ! -L "$RECEIVED"',
            f'test -f "$RECEIVED/{source_archive}"',
            f'test ! -L "$RECEIVED/{source_archive}"',
            'test -f "$RECEIVED/PUBLIC_SHA256SUMS"',
            'test ! -L "$RECEIVED/PUBLIC_SHA256SUMS"',
            f'test -f "$RECEIVED/{results_archive}"',
            f'test ! -L "$RECEIVED/{results_archive}"',
            f'test -f "$RECEIVED/{results_checksum}"',
            f'test ! -L "$RECEIVED/{results_checksum}"',
            "find -P \"$RECEIVED\" -mindepth 1 -maxdepth 1 -printf '%f\\n' | "
            'LC_ALL=C sort > "$RUNNER_TEMP/v404-source-release-received.inventory"',
            f"printf '%s\\n' {results_archive} {results_checksum} "
            f"PUBLIC_SHA256SUMS {source_archive} | cmp -s - "
            '"$RUNNER_TEMP/v404-source-release-received.inventory"',
        ),
        RELEASE_INVENTORY_STEP_NAME,
    )

    full_roundtrip_step = publish_steps[6]
    if (
        not isinstance(full_roundtrip_step, dict)
        or set(full_roundtrip_step) != {"name", "run"}
        or full_roundtrip_step.get("name") != RELEASE_FULL_ROUNDTRIP_STEP_NAME
    ):
        fail(f"{path.name} credential-free full roundtrip step changed")
    expected_full_roundtrip_profile = (
        "python -I -B \"$GITHUB_WORKSPACE/scripts/verify_public_package_roundtrip.py\" "
        f"--archive \"$RUNNER_TEMP/v404-source-release-received/{source_archive}\" "
        "--source-checksum \"$RUNNER_TEMP/v404-source-release-received/"
        "PUBLIC_SHA256SUMS\" "
        f"--results-archive \"$RUNNER_TEMP/v404-source-release-received/{results_archive}\" "
        f"--results-checksum \"$RUNNER_TEMP/v404-source-release-received/{results_checksum}\"",
    )
    observed_full_roundtrip_profile = exact_profile(
        full_roundtrip_step.get("run"), RELEASE_FULL_ROUNDTRIP_STEP_NAME
    )
    if observed_full_roundtrip_profile != expected_full_roundtrip_profile:
        fail(
            f"{path.name} credential-free full package roundtrip changed: "
            f"observed={observed_full_roundtrip_profile!r}"
        )

    publish_step = publish_steps[8]
    if (
        not isinstance(publish_step, dict)
        or set(publish_step) != {"name", "env", "run"}
        or publish_step.get("name") != RELEASE_PUBLISH_STEP_NAME
        or publish_step.get("env") != {"GH_TOKEN": "${{ github.token }}"}
    ):
        fail(f"{path.name} source-release publication step changed")
    exact_body(
        publish_step.get("run"),
        (
            'test ! -e "$RUNNER_TEMP/v404-source-release-recheck"',
            'test ! -L "$RUNNER_TEMP/v404-source-release-recheck"',
            "python -I -B \"$GITHUB_WORKSPACE/scripts/verify_public_package_roundtrip.py\" \\",
            "  --publish-v404-source-assets \\",
            f'  --archive "$RUNNER_TEMP/v404-source-release-received/{source_archive}" \\',
            '  --source-checksum "$RUNNER_TEMP/v404-source-release-received/'
            'PUBLIC_SHA256SUMS" \\',
            '  --download-dir "$RUNNER_TEMP/v404-source-release-recheck"',
        ),
        RELEASE_PUBLISH_STEP_NAME,
    )


def require_dispatch_input(
    path: Path, data: dict[str, Any], input_name: str
) -> None:
    on = data.get("on")
    dispatch = on.get("workflow_dispatch") if isinstance(on, dict) else None
    inputs = dispatch.get("inputs") if isinstance(dispatch, dict) else None
    entry = inputs.get(input_name) if isinstance(inputs, dict) else None
    if not isinstance(entry, dict):
        fail(f"{path.name} must declare dispatch input {input_name!r}")
    if entry.get("required") != "true":
        fail(f"{path.name} input {input_name!r} is not required")
    if entry.get("type") != "string":
        fail(f"{path.name} input {input_name!r} is not typed as string")


def _require_unique_mapping_binding(
    path: Path,
    data: dict[str, Any],
    env_name: str,
    expected_value: str,
    description: str,
) -> None:
    observed = [mapping[env_name] for mapping in _walk_mappings(data) if env_name in mapping]
    if observed != [expected_value]:
        fail(
            f"{path.name} must bind {env_name!r} exactly once to "
            f"{expected_value!r}; observed={observed!r} ({description})"
        )


def require_env_input_binding(
    path: Path,
    data: dict[str, Any],
    env_name: str,
    input_name: str,
) -> None:
    _require_unique_mapping_binding(
        path,
        data,
        env_name,
        f"${{{{ inputs.{input_name} }}}}",
        "workflow input",
    )


def require_env_literal_binding(
    path: Path, data: dict[str, Any], env_name: str, value: str
) -> None:
    _require_unique_mapping_binding(path, data, env_name, value, "literal policy")


def _normalize_shell_whitespace(text: str) -> str:
    """Collapse layout whitespace without changing quoted argument contents."""

    output: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    pending_space = False
    for character in text.strip():
        if escaped:
            if pending_space:
                output.append(" ")
                pending_space = False
            output.append(character)
            escaped = False
            continue
        if character == "\\" and not in_single:
            if pending_space:
                output.append(" ")
                pending_space = False
            output.append(character)
            escaped = True
            continue
        if character == "'" and not in_double:
            if pending_space:
                output.append(" ")
                pending_space = False
            in_single = not in_single
            output.append(character)
            continue
        if character == '"' and not in_single:
            if pending_space:
                output.append(" ")
                pending_space = False
            in_double = not in_double
            output.append(character)
            continue
        if character.isspace() and not in_single and not in_double:
            pending_space = bool(output)
            continue
        if pending_space:
            output.append(" ")
            pending_space = False
        output.append(character)
    return "".join(output)


def _normalized_line(line: LogicalShellLine) -> str:
    return _normalize_shell_whitespace(line.text)


def _has_shell_control(text: str) -> bool:
    in_single = False
    in_double = False
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if escaped:
            escaped = False
        elif character == "\\" and not in_single:
            escaped = True
        elif character == "'" and not in_double:
            in_single = not in_single
        elif character == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double and character in ";|&":
            return True
        index += 1
    return False


def _argv(line: LogicalShellLine) -> list[str] | None:
    if not line.top_level or _has_shell_control(line.text):
        return None
    try:
        return shlex.split(line.text, posix=True)
    except ValueError:
        return None


def _python_invocation(
    line: LogicalShellLine, script_path: str
) -> list[str] | None:
    if script_path not in PROTECTED_PYTHON_SCRIPTS:
        fail(f"internal policy references an unapproved protected script: {script_path!r}")
    tokens = _argv(line)
    if tokens is None or len(tokens) < 2:
        return None
    if not re.fullmatch(r"(?:python(?:3(?:\.\d+)*)?|py)(?:\.exe)?", tokens[0]):
        return None
    invoked_path = tokens[1]
    allowed_invocations = {f"$GITHUB_WORKSPACE/{script_path}"}
    if invoked_path not in allowed_invocations:
        protected_name = script_path.rsplit("/", 1)[-1]
        invoked_name = invoked_path.replace("\\", "/").rsplit("/", 1)[-1]
        if invoked_name == protected_name:
            fail(
                f"line {line.line_number} invokes protected script "
                f"{protected_name!r} through non-allowlisted path {invoked_path!r}; "
                f"expected one of {sorted(allowed_invocations)!r}"
            )
        return None
    return tokens


def _option_values(tokens: list[str], flag: str) -> list[str | None]:
    values: list[str | None] = []
    for index, token in enumerate(tokens):
        if token == flag:
            if index + 1 < len(tokens) and not tokens[index + 1].startswith("--"):
                values.append(tokens[index + 1])
            else:
                values.append(None)
        elif token.startswith(flag + "="):
            values.append(token[len(flag) + 1 :])
    return values


def _options_match(
    tokens: list[str], expected: dict[str, str | None]
) -> tuple[bool, str]:
    for flag, value in expected.items():
        observed = _option_values(tokens, flag)
        wanted = [value]
        if observed != wanted:
            return False, f"{flag}={observed!r}, expected {wanted!r}"
    return True, "approved options"


def _has_prior_unconditional_terminator(
    lines: list[LogicalShellLine], target: LogicalShellLine
) -> bool:
    for line in lines:
        if line is target:
            break
        if not line.top_level:
            continue
        text = _normalized_line(line)
        if re.match(r"^(?:exit(?:\s+0)?|return(?:\s+0)?|exec\b)", text):
            return True
    return False


def _has_prior_cwd_mutator(
    lines: list[LogicalShellLine], target: LogicalShellLine
) -> bool:
    for line in lines:
        if line is target:
            break
        if line.top_level and CWD_MUTATION_COMMAND_RE.search(_normalized_line(line)):
            return True
    return False


def _matching_python_invocations(
    commands: list[ShellCommand], script_path: str
) -> list[tuple[ShellCommand, LogicalShellLine, list[str]]]:
    matches: list[tuple[ShellCommand, LogicalShellLine, list[str]]] = []
    for command in commands:
        lines = _logical_shell_lines(command)
        for line in lines:
            tokens = _python_invocation(line, script_path)
            if tokens is None:
                continue
            if _has_prior_unconditional_terminator(lines, line):
                fail(
                    f"run line {command.run_line} places {script_path} after an "
                    "unconditional shell terminator"
                )
            if tokens[1] == script_path:
                if command.working_directory is not None:
                    fail(
                        f"run line {command.run_line} invokes protected relative "
                        f"script {script_path!r} with working-directory="
                        f"{command.working_directory!r}"
                    )
                if _has_prior_cwd_mutator(lines, line):
                    fail(
                        f"run line {command.run_line} invokes protected relative "
                        f"script {script_path!r} after changing the working directory"
                    )
            matches.append((command, line, tokens))
    return matches


def _require_single_python_invocation(
    path: Path,
    commands: list[ShellCommand],
    description: str,
    script_path: str,
    expected_options: dict[str, str | None],
) -> tuple[ShellCommand, LogicalShellLine, list[str]]:
    matches = _matching_python_invocations(commands, script_path)
    if len(matches) != 1:
        fail(
            f"{path.name} must execute exactly one {description}; found "
            f"{len(matches)} top-level invocations"
        )
    command, line, tokens = matches[0]
    valid, reason = _options_match(tokens, expected_options)
    if not valid:
        fail(f"{path.name}:{line.line_number} has an invalid {description}: {reason}")
    return command, line, tokens


def _contains_control_construct(lines: list[LogicalShellLine]) -> bool:
    return any(
        re.match(
            r"^(?:if|elif|else|fi|case|esac|for|while|until|select|done|function)\b",
            line.text,
        )
        for line in lines
    )


def _require_exact_lines_in_one_block(
    path: Path,
    commands: list[ShellCommand],
    description: str,
    expected_lines: tuple[str, ...],
) -> ShellCommand:
    normalized_expected = tuple(
        _normalize_shell_whitespace(line) for line in expected_lines
    )
    closest_line: int | None = None
    closest_missing: list[str] = list(normalized_expected)
    for command in commands:
        lines = _logical_shell_lines(command)
        if _contains_control_construct(lines):
            continue
        actual = [
            _normalized_line(line)
            for line in lines
            if line.top_level
        ]
        cursor = 0
        missing: list[str] = []
        for expected in normalized_expected:
            try:
                cursor = actual.index(expected, cursor) + 1
            except ValueError:
                missing.append(expected)
        if not missing:
            return command
        if len(missing) < len(closest_missing):
            closest_line = command.run_line
            closest_missing = missing
    location = f" near run line {closest_line}" if closest_line is not None else ""
    fail(
        f"{path.name} lacks an executable {description}{location}; "
        f"missing exact lines {closest_missing!r}"
    )


def require_artifact_provenance(
    path: Path,
    data: dict[str, Any],
    commands: list[ShellCommand],
    *,
    input_stem: str,
    env_stem: str,
    expected_workflow_env: str,
    expected_workflow_path: str,
) -> None:
    run_id_input = f"{input_stem}_run_id"
    run_sha_input = f"{input_stem}_run_sha"
    run_id_env = f"{env_stem}_RUN_ID"
    run_sha_env = f"{env_stem}_RUN_SHA"
    require_dispatch_input(path, data, run_id_input)
    require_dispatch_input(path, data, run_sha_input)
    require_env_input_binding(path, data, run_id_env, run_id_input)
    require_env_input_binding(path, data, run_sha_env, run_sha_input)
    require_env_literal_binding(
        path, data, expected_workflow_env, expected_workflow_path
    )

    if input_stem == "host":
        artifact_name = "jj-g-host-export-padova-dr05-tams-canonical"
        artifact_dir = "/tmp/jj-hosts"
    elif input_stem == "production":
        artifact_name = "bryson-v4-corrected-posterior-constant"
        artifact_dir = "/tmp/bryson-v4-posterior"
    else:  # pragma: no cover - policy call sites are closed above
        fail(f"unsupported artifact provenance stem {input_stem!r}")

    json_path = f"/tmp/{input_stem}-run.json"
    label = input_stem
    expected_lines = (
        f'[[ "${run_id_env}" =~ ^[1-9][0-9]*$ ]] || '
        f"{{ echo 'Invalid {label} run ID' >&2; exit 1; }}",
        f'[[ "${run_sha_env}" =~ ^[0-9a-f]{{40}}$ ]] || '
        f"{{ echo 'Invalid {label} run SHA' >&2; exit 1; }}",
        f'gh api "repos/${{GH_REPOSITORY}}/actions/runs/${{{run_id_env}}}" > {json_path}',
        f'jq -e --arg workflow "${expected_workflow_env}" '
        f'--arg sha "${run_sha_env}" '
        "'.status == \"completed\" and .conclusion == \"success\" and "
        ".event == \"workflow_dispatch\" and .path == $workflow and "
        f".head_sha == $sha' {json_path} > /dev/null",
        f'gh run download "${run_id_env}" --repo "$GH_REPOSITORY" '
        f"--name {artifact_name} --dir {artifact_dir}",
    )
    _require_exact_lines_in_one_block(
        path,
        commands,
        f"{input_stem} artifact provenance guard",
        expected_lines,
    )


def require_posterior_manifest_guard(
    path: Path, data: dict[str, Any], commands: list[ShellCommand]
) -> None:
    input_name = "posterior_manifest_sha256"
    env_name = "POSTERIOR_MANIFEST_SHA256"
    manifest = "SHA256SUMS_constant_aggregate.txt"
    require_dispatch_input(path, data, input_name)
    require_env_input_binding(path, data, env_name, input_name)
    expected_lines = (
        f'[[ "${env_name}" =~ ^[0-9a-f]{{64}}$ ]] || '
        "{ echo 'Invalid posterior manifest SHA-256' >&2; exit 1; }",
        f'echo "${env_name}  /tmp/bryson-v4-posterior/{manifest}" '
        "| sha256sum --check",
    )
    command = _require_exact_lines_in_one_block(
        path,
        commands,
        "independent posterior-manifest SHA-256 guard",
        expected_lines,
    )
    command_lines = _logical_shell_lines(command)
    manifest_check = _normalize_shell_whitespace(expected_lines[1])
    manifest_line = next(
        line
        for line in command_lines
        if line.top_level and _normalized_line(line) == manifest_check
    )
    valid_invocations = _matching_python_invocations(
        [command], "scripts/verify_accepted_aggregate.py"
    )
    if len(valid_invocations) != 1:
        fail(
            f"{path.name}:{command.run_line} must execute exactly one accepted "
            "aggregate verifier in the manifest guard"
        )
    _, line, tokens = valid_invocations[0]
    if line.line_number <= manifest_line.line_number:
        fail(
            f"{path.name}:{line.line_number} verifies aggregate acceptance before "
            "the independent posterior manifest check"
        )
    valid, reason = _options_match(
        tokens,
        {
            "--artifact-root": "/tmp/bryson-v4-posterior",
            "--branch": "constant",
            "--pc-catalog": BRYSON_PC_CATALOG,
            "--stellar-catalog": BRYSON_STELLAR_CATALOG,
            "--expected-bryson-source-sha256": BRYSON_SOURCE_SHA256,
        },
    )
    if not valid:
        fail(f"{path.name}:{line.line_number} has an invalid aggregate guard: {reason}")


def require_host_artifact_contract_guard(
    path: Path, commands: list[ShellCommand]
) -> None:
    """Require exact host-contract gates after import and before consumption."""

    script_path = "scripts/verify_host_artifact_contract.py"
    contract_path = (
        "$GITHUB_WORKSPACE/provenance/"
        "HOST_ARTIFACT_CONTRACT_v4_0_4.json"
    )
    guards = _matching_python_invocations(commands, script_path)
    expected_count = (
        2
        if path.name
        in {
            "bryson-v4-corrected-production.yml",
            "bryson-v4-corrected-zero-extended.yml",
        }
        else 1
    )
    if len(guards) != expected_count:
        fail(
            f"{path.name} must execute exactly {expected_count} "
            f"host-artifact contract verifier(s); found {len(guards)}"
        )
    expected_tail = [
        "--mode",
        "verify",
        "--contract",
        contract_path,
        "--artifact-root",
        "/tmp/jj-hosts",
    ]
    for _, guard_line, tokens in guards:
        valid, reason = _options_match(
            tokens,
            {
                "--mode": "verify",
                "--contract": contract_path,
                "--artifact-root": "/tmp/jj-hosts",
            },
        )
        if not valid or tokens[2:] != expected_tail:
            fail(
                f"{path.name}:{guard_line.line_number} host-contract "
                f"verifier argv changed: {tokens[2:]!r}; {reason}"
            )

    host_downloads: list[tuple[ShellCommand, LogicalShellLine]] = []
    for command in commands:
        for line in _logical_shell_lines(command):
            argv = _argv(line)
            if (
                argv is not None
                and argv[:4]
                == ["gh", "run", "download", "$HOST_RUN_ID"]
                and "jj-g-host-export-padova-dr05-tams-canonical" in argv
            ):
                host_downloads.append((command, line))
    if len(host_downloads) != 1:
        fail(
            f"{path.name} must contain one canonical host download before "
            f"contract verification; found {len(host_downloads)}"
        )
    download_command, download_line = host_downloads[0]
    download_position = (
        download_command.run_line,
        download_line.line_number,
    )
    guard_positions = [
        (command.run_line, line.line_number)
        for command, line, _ in guards
    ]
    if download_position >= min(guard_positions):
        fail(f"{path.name} verifies the host artifact before downloading it")
    if not any(
        command is download_command
        and (command.run_line, line.line_number) > download_position
        for command, line, _ in guards
    ):
        fail(
            f"{path.name} does not verify the downloaded host artifact "
            "inside its provenance-checked import step"
        )

    obsolete_tokens = (
        "sha256sum --check SHA256SUMS_padova.txt",
        "a2b6f407c70c236f2be9a9084f53fe9ba461f06aa5f44d6caae11696467e5a28",
        "bc38c3d42422b20b57ea433dff12b394881167318ac8e0ad77dd894b429474cd",
    )
    active = "\n".join(active_shell_text(command) for command in commands)
    for token in obsolete_tokens:
        if token in active:
            fail(
                f"{path.name} retains an obsolete inline host gate: {token}"
            )

    propagation = _matching_python_invocations(
        commands,
        "research/bryson-joint-posterior/"
        "propagate_hab2_joint_posterior.py",
    )
    if propagation:
        if len(propagation) != 1:
            fail(
                f"{path.name} must contain exactly one host consumer; "
                f"found {len(propagation)}"
            )
        consumer_command, consumer_line, _ = propagation[0]
        consumer_position = (
            consumer_command.run_line,
            consumer_line.line_number,
        )
        prior_guards = [
            (command, line)
            for command, line, _ in guards
            if (command.run_line, line.line_number) < consumer_position
        ]
        if not prior_guards:
            fail(
                f"{path.name} consumes hosts before exact contract acceptance"
            )
        if path.name != "bryson-v4-propagate-constant.yml":
            if not any(command is consumer_command for command, _ in prior_guards):
                fail(
                    f"{path.name} does not reverify the transferred host "
                    "artifact in the consumer step"
                )


def require_accepted_aggregate_guard(
    path: Path, commands: list[ShellCommand], branch: str
) -> None:
    accepted_command, accepted_line, _ = _require_single_python_invocation(
        path,
        commands,
        "accepted aggregate verifier",
        "scripts/verify_accepted_aggregate.py",
        {
            "--artifact-root": "/tmp/bryson-v4-posterior",
            "--branch": branch,
            "--pc-catalog": BRYSON_PC_CATALOG,
            "--stellar-catalog": BRYSON_STELLAR_CATALOG,
            "--expected-bryson-source-sha256": BRYSON_SOURCE_SHA256,
        },
    )
    propagation_matches = _matching_python_invocations(
        commands,
        "research/bryson-joint-posterior/propagate_hab2_joint_posterior.py",
    )
    if len(propagation_matches) != 1:
        fail(
            f"{path.name} must execute exactly one posterior propagation; found "
            f"{len(propagation_matches)} top-level invocations"
        )
    propagation_command, propagation_line, propagation_tokens = propagation_matches[0]
    valid, reason = _options_match(propagation_tokens, {"--branch": branch})
    if not valid:
        fail(
            f"{path.name}:{propagation_line.line_number} has invalid propagation "
            f"branch provenance: {reason}"
        )
    accepted_position = (accepted_command.run_line, accepted_line.line_number)
    propagation_position = (
        propagation_command.run_line,
        propagation_line.line_number,
    )
    if accepted_position >= propagation_position:
        fail(
            f"{path.name} executes posterior propagation before aggregate acceptance"
        )


def require_production_aggregate_profile(
    path: Path, commands: list[ShellCommand]
) -> None:
    profile = (
        "v4.0.4-zero-extended"
        if path.name == "bryson-v4-corrected-zero-extended.yml"
        else "v4.0.4-production"
    )
    _require_single_python_invocation(
        path,
        commands,
        "v4.0.4 production aggregate profile",
        "research/bryson-joint-posterior/aggregate_hab2_joint_posterior.py",
        {
            "--expected-shards": "16",
            "--trials-per-shard": "25",
            "--walkers": "16",
            "--steps": "3000",
            "--runner-thin": "20",
            "--samples-per-realization": "1024",
            "--require-all-converged": None,
            "--acceptance-profile": profile,
            "--minimum-ess-per-realization": "1000",
            "--cluster-bootstrap-replicates": "1000",
            "--inner-chain-batches": "8",
            "--maximum-outer-q50-mcse-fraction": "0.10",
            "--maximum-inner-q50-mcse-fraction": "0.05",
            "--expected-bryson-source-sha256": BRYSON_SOURCE_SHA256,
        },
    )


def require_private_raw_chain_flow(
    path: Path,
    data: dict[str, Any],
    commands: list[ShellCommand],
) -> None:
    """Require the private-only raw-chain handoff into production aggregation."""

    profiles = {
        "bryson-v4-corrected-production.yml": {
            "assignment": (
                'PRIVATE_EVIDENCE="/tmp/bryson-v4-private-evidence-'
                '$BRANCH-$SHARD"'
            ),
            "upload_name": (
                "bryson-v4-private-convergence-evidence-"
                "${{ matrix.branch }}-${{ matrix.shard }}"
            ),
            "upload_path": (
                "/tmp/bryson-v4-private-evidence-"
                "${{ matrix.branch }}-${{ matrix.shard }}/"
            ),
            "download_pattern": (
                "bryson-v4-private-convergence-evidence-"
                "${{ matrix.branch }}-*"
            ),
        },
        "bryson-v4-corrected-zero-extended.yml": {
            "assignment": (
                'PRIVATE_EVIDENCE="/tmp/bryson-v4-private-evidence-'
                'zero-$SHARD"'
            ),
            "upload_name": (
                "bryson-v4-private-convergence-evidence-zero-"
                "${{ matrix.shard }}"
            ),
            "upload_path": (
                "/tmp/bryson-v4-private-evidence-zero-"
                "${{ matrix.shard }}/"
            ),
            "download_pattern": "bryson-v4-private-convergence-evidence-zero-*",
        },
    }
    expected = profiles.get(path.name)
    if expected is None:
        fail(f"private raw-chain policy applied to unsupported workflow {path.name}")
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        fail(f"{path.name} has no jobs mapping")
    for job_name in ("reconstruct-shards", "aggregate"):
        job = jobs.get(job_name)
        if not isinstance(job, dict) or job.get("if") != PRIVATE_REPOSITORY_JOB_IF:
            fail(
                f"{path.name} private raw-chain job {job_name!r} is not "
                "fail-closed to a private repository"
            )

    expected_assignment = _normalize_shell_whitespace(str(expected["assignment"]))
    assignment_commands = [
        command
        for command in commands
        for line in _logical_shell_lines(command)
        if line.top_level and _normalized_line(line) == expected_assignment
    ]
    if len(assignment_commands) != 1:
        fail(
            f"{path.name} must assign its private raw-chain directory exactly once"
        )
    runner_command, _runner_line, _runner_tokens = _require_single_python_invocation(
        path,
        commands,
        "raw-chain-producing Bryson runner",
        "research/bryson-joint-posterior/run_hab2_joint_posterior.py",
        {"--private-raw-chain-dir": "$PRIVATE_EVIDENCE"},
    )
    if assignment_commands[0] is not runner_command:
        fail(
            f"{path.name} does not bind the private raw-chain directory in the "
            "runner step"
        )
    _require_single_python_invocation(
        path,
        commands,
        "raw-chain-auditing aggregate",
        "research/bryson-joint-posterior/aggregate_hab2_joint_posterior.py",
        {"--private-raw-chain-root": "/tmp/bryson-v4-private-evidence"},
    )

    upload_use = "actions/upload-artifact@" + PINNED_ACTIONS["actions/upload-artifact"]
    download_use = (
        "actions/download-artifact@" + PINNED_ACTIONS["actions/download-artifact"]
    )
    reconstruct_steps = jobs["reconstruct-shards"].get("steps")
    aggregate_steps = jobs["aggregate"].get("steps")
    if not isinstance(reconstruct_steps, list) or not isinstance(aggregate_steps, list):
        fail(f"{path.name} private raw-chain jobs lack explicit steps")
    expected_upload = {
        "name": expected["upload_name"],
        "path": expected["upload_path"],
        "if-no-files-found": "error",
        "retention-days": "1",
        "compression-level": "0",
    }
    expected_download = {
        "pattern": expected["download_pattern"],
        "path": "/tmp/bryson-v4-private-evidence",
    }
    uploads = [
        step
        for step in reconstruct_steps
        if isinstance(step, dict)
        and step.get("uses") == upload_use
        and isinstance(step.get("with"), dict)
        and "private-convergence-evidence" in str(step["with"].get("name", ""))
    ]
    downloads = [
        step
        for step in aggregate_steps
        if isinstance(step, dict)
        and step.get("uses") == download_use
        and isinstance(step.get("with"), dict)
        and "private-convergence-evidence" in str(
            step["with"].get("pattern", "")
        )
    ]
    if len(uploads) != 1 or uploads[0].get("with") != expected_upload:
        fail(f"{path.name} private convergence-evidence upload is not exact")
    if len(downloads) != 1 or downloads[0].get("with") != expected_download:
        fail(f"{path.name} private convergence-evidence download is not exact")
    if "raw" in str(expected["upload_name"]).lower():
        fail(f"{path.name} exposes raw-chain semantics in its artifact name")


def require_catalog_replay_input_artifact(path: Path, data: dict[str, Any]) -> None:
    """Require locked catalogs to arrive before the accepted replay gate."""

    artifact_names = {
        "bryson-v4-corrected-production.yml": (
            "bryson-v4-corrected-production-inputs-${{ matrix.branch }}"
        ),
        "bryson-v4-corrected-zero-extended.yml": (
            "bryson-v4-corrected-zero-extended-inputs"
        ),
    }
    expected_name = artifact_names.get(path.name)
    if expected_name is None:
        fail(f"catalog replay artifact policy applied to {path.name}")
    jobs = data.get("jobs")
    propagate = jobs.get("propagate") if isinstance(jobs, dict) else None
    steps = propagate.get("steps") if isinstance(propagate, dict) else None
    if not isinstance(steps, list):
        fail(f"{path.name} propagate job has no explicit steps")
    download_use = (
        "actions/download-artifact@" + PINNED_ACTIONS["actions/download-artifact"]
    )
    expected_with = {
        "name": expected_name,
        "path": "/tmp/DR25-occurrence-public",
    }
    downloads = [
        (index, step)
        for index, step in enumerate(steps)
        if isinstance(step, dict)
        and step.get("uses") == download_use
        and step.get("with") == expected_with
    ]
    accepted_steps = [
        index
        for index, step in enumerate(steps)
        if isinstance(step, dict)
        and "scripts/verify_accepted_aggregate.py" in str(step.get("run", ""))
    ]
    if len(downloads) != 1 or len(accepted_steps) != 1:
        fail(f"{path.name} lacks an exact catalog-transfer/replay step pair")
    if downloads[0][0] >= accepted_steps[0]:
        fail(f"{path.name} verifies catalog replay before downloading catalogs")


def require_numerical_environment_capture(
    path: Path, commands: list[ShellCommand]
) -> None:
    _require_exact_lines_in_one_block(
        path,
        commands,
        "complete numerical-environment capture",
        (
            "python --version",
            "python -m pip --version",
            "python -m pip freeze --all | sort",
            "} > numerical_environment.txt",
        ),
    )


def _locked_requirements_install(line: LogicalShellLine) -> bool:
    tokens = _argv(line)
    if tokens is None:
        return False
    if (
        len(tokens) >= 5
        and re.fullmatch(r"(?:python(?:3(?:\.\d+)*)?|py)(?:\.exe)?", tokens[0])
        and tokens[1:4] == ["-m", "pip", "install"]
    ):
        arguments = tokens[4:]
    elif (
        len(tokens) >= 2
        and re.fullmatch(r"pip(?:3(?:\.\d+)*)?(?:\.exe)?", tokens[0])
        and tokens[1] == "install"
    ):
        arguments = tokens[2:]
    else:
        return False
    approved, reason = _locked_pip_install(
        " ".join(shlex.quote(token) for token in arguments)
    )
    return approved and reason == "binary-only hash-locked requirements"


def _is_exact_pip_check(line: LogicalShellLine) -> bool:
    tokens = _argv(line)
    return bool(
        tokens
        and len(tokens) == 4
        and re.fullmatch(r"(?:python(?:3(?:\.\d+)*)?|py)(?:\.exe)?", tokens[0])
        and tokens[1:] == ["-m", "pip", "check"]
    )


def require_numerical_runtime_verification(
    path: Path, commands: list[ShellCommand]
) -> None:
    """Gate every locked numerical environment before a consumer can run."""

    expected_outputs = EXPECTED_NUMERICAL_RUNTIME_OUTPUTS.get(path.name)
    if expected_outputs is None:
        fail(f"{path.name} has no audited numerical-runtime invocation profile")

    observed_outputs: list[str | None] = []
    for command in commands:
        lines = _logical_shell_lines(command)
        install_indexes = [
            index
            for index, line in enumerate(lines)
            if _locked_requirements_install(line)
        ]
        runtime_matches = _matching_python_invocations(
            [command], "scripts/verify_numerical_runtime.py"
        )

        if not install_indexes:
            if runtime_matches:
                fail(
                    f"{path.name}:{command.run_line} executes the numerical-runtime "
                    "verifier outside its locked requirements installation step"
                )
            continue
        if len(install_indexes) != 1:
            fail(
                f"{path.name}:{command.run_line} must contain exactly one locked "
                f"requirements install; found {len(install_indexes)}"
            )
        if len(runtime_matches) != 1:
            fail(
                f"{path.name}:{command.run_line} must contain exactly one "
                f"numerical-runtime verifier after installation; found "
                f"{len(runtime_matches)}"
            )

        check_indexes = [
            index for index, line in enumerate(lines) if _is_exact_pip_check(line)
        ]
        if len(check_indexes) != 1:
            fail(
                f"{path.name}:{command.run_line} must contain exactly one exact "
                f"python -m pip check; found {len(check_indexes)}"
            )

        _, runtime_line, runtime_tokens = runtime_matches[0]
        runtime_indexes = [
            index
            for index, line in enumerate(lines)
            if line.line_number == runtime_line.line_number
            and _python_invocation(line, "scripts/verify_numerical_runtime.py")
            is not None
        ]
        if len(runtime_indexes) != 1:
            fail(
                f"{path.name}:{runtime_line.line_number} numerical-runtime "
                "verifier position is ambiguous"
            )

        install_index = install_indexes[0]
        check_index = check_indexes[0]
        runtime_index = runtime_indexes[0]
        if check_index != install_index + 1 or runtime_index != check_index + 1:
            fail(
                f"{path.name}:{command.run_line} must execute locked install, "
                "pip check, and numerical-runtime verification consecutively"
            )

        arguments = runtime_tokens[2:]
        if not arguments:
            observed_outputs.append(None)
        elif len(arguments) == 2 and arguments[0] == "--output":
            output = arguments[1]
            output_path = Path(output)
            if (
                output_path.is_absolute()
                or ".." in output_path.parts
                or output_path.suffix.lower() != ".json"
            ):
                fail(
                    f"{path.name}:{runtime_line.line_number} has unsafe numerical "
                    f"runtime report path {output!r}"
                )
            observed_outputs.append(output)
        else:
            fail(
                f"{path.name}:{runtime_line.line_number} numerical-runtime "
                f"verifier arguments changed: {arguments!r}"
            )

    if tuple(observed_outputs) != expected_outputs:
        fail(
            f"{path.name} numerical-runtime invocation matrix changed: "
            f"observed={tuple(observed_outputs)!r}, expected={expected_outputs!r}"
        )


def require_metallicity_negative_artifact_gate(
    path: Path, commands: list[ShellCommand]
) -> None:
    if path.name != "jj-tams-metallicity-differential.yml":
        fail("metallicity artifact policy applied to the wrong workflow")

    producer_options = {
        "--input": "/tmp/metallicity-host/jj_g_hosts_parent_prelogg_padova.csv",
        "--reference-tams": (
            "$GITHUB_WORKSPACE/research/jj-host-export/reference-data/"
            "tams_parsec_danxhuber.txt"
        ),
        "--cache": "/tmp/parsec-metal-tracks",
        "--out": "$GITHUB_WORKSPACE/results/metallicity-audit",
        "--data-locks": "$GITHUB_WORKSPACE/provenance/DATA_LOCKS.json",
    }
    producer_command, producer_line, producer_tokens = _require_single_python_invocation(
        path,
        commands,
        "metallicity-TAMS negative-artifact producer",
        "research/jj-host-export/metallicity_tams_differential_sensitivity.py",
        producer_options,
    )
    verifier_options = {
        "--artifact-root": "results/metallicity-audit",
        "--data-locks": "provenance/DATA_LOCKS.json",
    }
    verifier_command, verifier_line, verifier_tokens = _require_single_python_invocation(
        path,
        commands,
        "metallicity-TAMS exact-artifact verifier",
        "scripts/verify_metallicity_tams_audit.py",
        verifier_options,
    )
    exact_profiles = (
        (
            producer_line,
            producer_tokens,
            "research/jj-host-export/metallicity_tams_differential_sensitivity.py",
            producer_options,
        ),
        (
            verifier_line,
            verifier_tokens,
            "scripts/verify_metallicity_tams_audit.py",
            verifier_options,
        ),
    )
    for line, tokens, script, options in exact_profiles:
        if tokens[:2] != ["python", f"$GITHUB_WORKSPACE/{script}"] or len(
            tokens
        ) != 2 + 2 * len(options):
            fail(
                f"{path.name}:{line.line_number} has additional or non-canonical "
                f"arguments for protected script {script!r}: {tokens!r}"
            )
    provenance_copy = (
        "cp research/jj-host-export/PROVENANCE_METALLICITY_DIFFERENTIAL.md "
        "results/metallicity-audit/PROVENANCE_METALLICITY_DIFFERENTIAL.md"
    )
    copy_command = _require_exact_lines_in_one_block(
        path,
        commands,
        "static metallicity provenance copy",
        (provenance_copy,),
    )
    normalized_copy = _normalize_shell_whitespace(provenance_copy)
    copy_count = sum(
        _normalized_line(line) == normalized_copy
        for command in commands
        for line in _logical_shell_lines(command)
        if line.top_level
    )
    if copy_count != 1:
        fail(
            f"{path.name} must copy static metallicity provenance exactly once; "
            f"found {copy_count}"
        )
    if not (
        producer_command.run_line
        < copy_command.run_line
        < verifier_command.run_line
    ):
        fail(
            f"{path.name} must produce the metallicity audit, copy static "
            "provenance, then verify the exact artifact"
        )


def require_no_unattested_age_cut_workflow(
    path: Path, commands: list[ShellCommand]
) -> None:
    """Keep release-specific age evidence behind the signed local contract."""

    forbidden_scripts = (AGE_CUT_PRODUCER_SCRIPT, AGE_CUT_VERIFIER_SCRIPT)
    for script in forbidden_scripts:
        matches = _matching_python_invocations(commands, script)
        if matches:
            fail(
                f"{path.name} invokes {script!r} without the release-specific "
                "two-repetition signed qualification contract"
            )

    forbidden_markers = (
        "results/age-cut",
        "results/jj/age-cut",
        *AGE_CUT_ARTIFACT_FILES,
    )
    for command in commands:
        for line in _logical_shell_lines(command):
            if any(marker in line.text for marker in forbidden_markers):
                fail(
                    f"{path.name}:{line.line_number} stages unqualified age-cut "
                    "evidence inside a reusable workflow"
                )


def require_exact_jj_export_profile(
    path: Path, commands: list[ShellCommand]
) -> None:
    """Require an exact JJ runner argv immediately after tracked-blob proof."""

    expected_argv = EXPECTED_JJ_EXPORT_ARGV.get(path.name)
    matches = _matching_python_invocations(commands, JJ_EXPORT_SCRIPT)
    if expected_argv is None:
        if matches:
            fail(
                f"{path.name} invokes the JJ export runner outside its two "
                "approved workflows"
            )
        return
    if len(matches) != 1:
        fail(
            f"{path.name} must execute exactly one JJ export runner; found "
            f"{len(matches)}"
        )

    command, invocation_line, tokens = matches[0]
    if tuple(tokens) != expected_argv:
        fail(
            f"{path.name}:{invocation_line.line_number} JJ export argv changed: "
            f"observed={tuple(tokens)!r}, expected={expected_argv!r}"
        )

    lines = _logical_shell_lines(command)
    invocation_indexes = [
        index for index, line in enumerate(lines) if line == invocation_line
    ]
    if len(invocation_indexes) != 1:
        fail(f"{path.name} has an ambiguous JJ export invocation position")
    invocation_index = invocation_indexes[0]
    guard_count = len(JJ_EXPORT_INTEGRITY_LINES)
    if invocation_index < guard_count or tuple(
        line.text
        for line in lines[invocation_index - guard_count : invocation_index]
    ) != JJ_EXPORT_INTEGRITY_LINES:
        fail(
            f"{path.name}:{invocation_line.line_number} must execute the exact "
            "tracked-blob JJ source guard immediately before export"
        )

    all_lines = [
        line.text
        for candidate in commands
        for line in _logical_shell_lines(candidate)
    ]
    duplicate_guards = {
        expected: all_lines.count(expected)
        for expected in JJ_EXPORT_INTEGRITY_LINES
        if all_lines.count(expected) != 1
    }
    if duplicate_guards:
        fail(
            f"{path.name} JJ tracked-blob guard count changed: "
            f"{duplicate_guards!r}"
        )


def require_production_candidate_status(
    path: Path, commands: list[ShellCommand]
) -> None:
    _require_single_python_invocation(
        path,
        commands,
        "standalone Bryson runner",
        "research/bryson-joint-posterior/run_hab2_joint_posterior.py",
        {"--run-status": "production_candidate"},
    )


def require_exact_external_downloads(
    path: Path,
    commands: list[ShellCommand],
    expected: tuple[tuple[str, ...], ...],
) -> None:
    """Require the complete ordered argv set for cross-workflow downloads."""

    observed: list[tuple[str, ...]] = []
    for command in commands:
        for line in _logical_shell_lines(command):
            if GH_DOWNLOAD_RE.search(line.text) is None:
                continue
            tokens = _argv(line)
            if tokens is None or tokens[:3] != ["gh", "run", "download"]:
                fail(
                    f"{path.name}:{line.line_number} must express gh run download "
                    "as one complete, unconditional command with no shell-control "
                    "prefix or suffix"
                )
            observed.append(tuple(tokens))
    if tuple(observed) != expected:
        fail(
            f"{path.name} external-download argv/count/order changed: "
            f"observed={observed!r}, expected={list(expected)!r}"
        )


def main() -> None:
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    if not paths:
        fail("no workflow files found")
    observed_workflow_names = {path.name for path in paths}
    expected_workflow_names = set(EXPECTED_NUMERICAL_RUNTIME_OUTPUTS)
    if observed_workflow_names != expected_workflow_names:
        fail(
            "audited workflow set changed: "
            f"observed={sorted(observed_workflow_names)!r}, "
            f"expected={sorted(expected_workflow_names)!r}"
        )

    shell_count = 0
    block_count = 0
    inline_count = 0
    install_count = 0
    action_count = 0
    observed_actions: set[str] = set()
    parsed_by_path: dict[Path, ParsedWorkflow] = {}
    allowed_input_bindings = {
        "bryson-v4-corrected-production.yml": {
            ("HOST_RUN_ID", "host_run_id"),
            ("HOST_RUN_SHA", "host_run_sha"),
        },
        "bryson-v4-corrected-zero-extended.yml": {
            ("HOST_RUN_ID", "host_run_id"),
            ("HOST_RUN_SHA", "host_run_sha"),
        },
        "bryson-v4-propagate-constant.yml": {
            ("PRODUCTION_RUN_ID", "production_run_id"),
            ("PRODUCTION_RUN_SHA", "production_run_sha"),
            ("POSTERIOR_MANIFEST_SHA256", "posterior_manifest_sha256"),
            ("HOST_RUN_ID", "host_run_id"),
            ("HOST_RUN_SHA", "host_run_sha"),
        },
    }
    for path in paths:
        parsed = parse_workflow(path)
        parsed_by_path[path] = parsed
        validate_workflow_environment(
            path,
            parsed.data,
            allowed_input_bindings.get(path.name, set()),
        )
        require_workflow_execution_conditions(path, parsed.data)
        require_release_package_tag_gate(path, parsed.data)
        require_numerical_runtime_environment(path, parsed.data)
        require_numerical_runtime_verification(path, parsed.commands)
        require_exact_jj_export_profile(path, parsed.commands)
        require_no_unattested_age_cut_workflow(path, parsed.commands)
        observed_actions.update(validate_action_uses(path, parsed.actions))
        action_count += len(parsed.actions)
        for command in parsed.commands:
            shell_count += 1
            if command.scalar_style == "inline":
                inline_count += 1
            else:
                block_count += 1
            install_count += audit_shell_command(path, command)

    if observed_actions != set(PINNED_ACTIONS):
        fail(
            "GitHub Action pin set changed: "
            f"observed={sorted(observed_actions)}, expected={sorted(PINNED_ACTIONS)}"
        )

    metallicity_path = WORKFLOWS / "jj-tams-metallicity-differential.yml"
    metallicity = parsed_by_path.get(metallicity_path)
    if metallicity is None:
        fail(f"required metallicity workflow is missing: {metallicity_path.name}")
    require_metallicity_negative_artifact_gate(
        metallicity_path, metallicity.commands
    )

    production_names = (
        "bryson-v4-corrected-production.yml",
        "bryson-v4-corrected-zero-extended.yml",
    )
    for name in production_names:
        path = WORKFLOWS / name
        parsed = parsed_by_path.get(path)
        if parsed is None:
            fail(f"required production workflow is missing: {name}")
        require_artifact_provenance(
            path,
            parsed.data,
            parsed.commands,
            input_stem="host",
            env_stem="HOST",
            expected_workflow_env="EXPECTED_HOST_WORKFLOW",
            expected_workflow_path=".github/workflows/jj-g-host-export.yml",
        )
        require_host_artifact_contract_guard(path, parsed.commands)
        require_production_candidate_status(path, parsed.commands)
        require_production_aggregate_profile(path, parsed.commands)
        require_private_raw_chain_flow(path, parsed.data, parsed.commands)
        require_catalog_replay_input_artifact(path, parsed.data)
        require_numerical_environment_capture(path, parsed.commands)

    production_path = WORKFLOWS / "bryson-v4-corrected-production.yml"
    zero_path = WORKFLOWS / "bryson-v4-corrected-zero-extended.yml"
    require_accepted_aggregate_guard(
        production_path, parsed_by_path[production_path].commands, "$BRANCH"
    )
    require_accepted_aggregate_guard(
        zero_path, parsed_by_path[zero_path].commands, "zero"
    )

    propagation_path = WORKFLOWS / "bryson-v4-propagate-constant.yml"
    propagation = parsed_by_path.get(propagation_path)
    if propagation is None:
        fail(f"required standalone workflow is missing: {propagation_path.name}")
    require_artifact_provenance(
        propagation_path,
        propagation.data,
        propagation.commands,
        input_stem="production",
        env_stem="PRODUCTION",
        expected_workflow_env="EXPECTED_PRODUCTION_WORKFLOW",
        expected_workflow_path=(
            ".github/workflows/bryson-v4-corrected-production.yml"
        ),
    )
    require_artifact_provenance(
        propagation_path,
        propagation.data,
        propagation.commands,
        input_stem="host",
        env_stem="HOST",
        expected_workflow_env="EXPECTED_HOST_WORKFLOW",
        expected_workflow_path=".github/workflows/jj-g-host-export.yml",
    )
    require_posterior_manifest_guard(
        propagation_path, propagation.data, propagation.commands
    )
    require_host_artifact_contract_guard(
        propagation_path, propagation.commands
    )
    require_accepted_aggregate_guard(
        propagation_path, propagation.commands, "constant"
    )

    host_download = (
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
    production_download = (
        "gh",
        "run",
        "download",
        "$PRODUCTION_RUN_ID",
        "--repo",
        "$GH_REPOSITORY",
        "--name",
        "bryson-v4-corrected-posterior-constant",
        "--dir",
        "/tmp/bryson-v4-posterior",
    )
    production_inputs_download = (
        "gh",
        "run",
        "download",
        "$PRODUCTION_RUN_ID",
        "--repo",
        "$GH_REPOSITORY",
        "--name",
        "bryson-v4-corrected-production-inputs-constant",
        "--dir",
        "/tmp/DR25-occurrence-public",
    )
    expected_downloads = {
        "bryson-v4-corrected-production.yml": (host_download,),
        "bryson-v4-corrected-zero-extended.yml": (host_download,),
        "bryson-v4-propagate-constant.yml": (
            production_download,
            production_inputs_download,
            host_download,
        ),
    }
    for path, parsed in parsed_by_path.items():
        require_exact_external_downloads(
            path,
            parsed.commands,
            expected_downloads.get(path.name, ()),
        )

    print(
        f"PASS workflow security ({len(paths)} workflows; "
        f"{shell_count} shell commands: {block_count} block, "
        f"{inline_count} inline; {install_count} locked installs; "
        f"{action_count} SHA-pinned action uses)"
    )


if __name__ == "__main__":
    main()
