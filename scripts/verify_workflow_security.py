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
        "research/bryson-joint-posterior/aggregate_hab2_joint_posterior.py",
        "research/bryson-joint-posterior/propagate_hab2_joint_posterior.py",
        "research/bryson-joint-posterior/run_hab2_joint_posterior.py",
    }
)
APPROVED_EXPLICIT_SHELLS = frozenset(
    {"bash --noprofile --norc -e -o pipefail {0}"}
)
FORBIDDEN_SHELL_ENV_KEYS = frozenset({"BASH_ENV", "ENV", "SHELLOPTS"})

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
    allowed_invocations = {
        script_path,
        f"$GITHUB_WORKSPACE/{script_path}",
    }
    if invoked_path not in allowed_invocations:
        protected_name = script_path.rsplit("/", 1)[-1]
        if invoked_path.endswith(protected_name):
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
            "--expected-bryson-source-sha256": BRYSON_SOURCE_SHA256,
        },
    )
    if not valid:
        fail(f"{path.name}:{line.line_number} has an invalid aggregate guard: {reason}")


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
        require_production_candidate_status(path, parsed.commands)
        require_production_aggregate_profile(path, parsed.commands)
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
    expected_downloads = {
        "bryson-v4-corrected-production.yml": (host_download,),
        "bryson-v4-corrected-zero-extended.yml": (host_download,),
        "bryson-v4-propagate-constant.yml": (
            production_download,
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
