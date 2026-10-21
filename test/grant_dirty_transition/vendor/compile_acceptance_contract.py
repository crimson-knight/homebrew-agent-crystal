#!/usr/bin/env python3
"""Strict identities and rosters for complete Grant compile acceptance."""
import hashlib
import itertools
import json
import pathlib
import posixpath
import re
from dataclasses import dataclass


class AcceptanceError(ValueError):
    """An acceptance input lacks required evidence or exceeds its policy."""


FIELD_NAMES = (
    "id", "first_name", "email", "age", "is_active", "score", "country_code", "notes",
    "rating", "balance", "group_number", "settings_text", "created_at", "updated_at",
    "parent_id", "sequence_number",
)


def parse_json_text(text):
    def unique_object(pairs):
        values = {}
        for key, value in pairs:
            if key in values:
                raise AcceptanceError("Duplicate JSON key: " + key)
            values[key] = value
        return values

    def reject_constant(value):
        raise AcceptanceError("Nonfinite JSON value: " + value)

    try:
        return json.loads(text, object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except json.JSONDecodeError as error:
        raise AcceptanceError("Cannot parse JSON: " + str(error)) from error


def parse_json(path):
    try:
        return parse_json_text(pathlib.Path(path).read_text())
    except OSError as error:
        raise AcceptanceError("Cannot read JSON: " + str(error)) from error


def require_integer(value, label, minimum=1):
    if type(value) is not int or value < minimum:
        raise AcceptanceError(label + " requires an integer >= " + str(minimum))
    return value


def require_identity(value, label, length=64):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{%d}" % length, value) is None:
        raise AcceptanceError(label + " requires a lowercase hexadecimal identity")
    return value


def require_roster(actual, expected, label):
    if not isinstance(actual, list) or not actual:
        raise AcceptanceError(label + " requires a nonempty list")
    if any(not isinstance(value, str) or not value.strip() for value in actual):
        raise AcceptanceError(label + " requires nonblank string identities")
    if len(actual) != len(set(actual)) or sorted(actual) != sorted(expected):
        raise AcceptanceError(label + " differs from the required unique roster")


@dataclass(frozen=True)
class CompileCell:
    platform: str
    adapter: str
    model_count: int
    workload: str
    build_mode: str
    repetition: int

    @property
    def identity(self):
        return "%s/%s/%d/%s/%s/%d" % (
            self.platform, self.adapter, self.model_count, self.workload,
            self.build_mode, self.repetition,
        )


@dataclass(frozen=True)
class CompileAcceptanceContract:
    maximum_exclusive_bytes: int = 2000000000
    compiler_workers: int = 1
    feature_profile: str = "documented_default_grant"

    @classmethod
    def from_dict(cls, value):
        required = {
            "schema_version": 1,
            "mission": "memory-budget-experiment",
            "maximum_exclusive_bytes": 2000000000,
            "common_checker_fixed_limit_bytes": 1999999999,
            "list_of_model_counts": [300, 500],
            "list_of_workloads": ["all_model_queries", "all_model_queries_and_associations"],
            "list_of_build_modes": ["debug", "release"],
            "list_of_required_platforms": ["darwin-arm64", "linux-amd64"],
            "list_of_required_adapters": ["sqlite", "pg", "mysql"],
            "cold_repetitions": 3,
            "compiler_workers": 1,
            "primary_feature_profile": "documented_default_grant",
            "list_of_required_memory_metrics": ["compiler_peak_rss_bytes", "audited_whole_build_memory_bytes"],
            "required_matrix_size": 144,
            "required_core_matrix_size_per_adapter": 48,
        }
        if type(value) is not dict or set(value) != set(required):
            raise AcceptanceError("Contract field roster differs")
        for key, expected in required.items():
            if type(value[key]) is not type(expected) or value[key] != expected:
                raise AcceptanceError("Contract requires canonical " + key)
        return cls()

    def cells(self):
        return tuple(CompileCell(*parts) for parts in itertools.product(
            ("darwin-arm64", "linux-amd64"), ("sqlite", "pg", "mysql"),
            (300, 500), ("all_model_queries", "all_model_queries_and_associations"),
            ("debug", "release"), (1, 2, 3),
        ))


def model_roster(model_count):
    require_integer(model_count, "model_count", 2)
    return ["AcceptancePerson%04d" % index for index in range(model_count)]


def operation_roster(model_count):
    return [model + "/" + operation for model in model_roster(model_count)
            for operation in ("create", "hydrate", "scope")]


def field_roster(model_count):
    return [model + "/" + field for model in model_roster(model_count) for field in FIELD_NAMES]


def association_roster(model_count, workload):
    if workload == "all_model_queries":
        return []
    if workload != "all_model_queries_and_associations":
        raise AcceptanceError("Unsupported workload")
    models = model_roster(model_count)
    return [models[index] + "/" + edge + "/" + models[target]
            for index in range(model_count)
            for edge, target in (("parent", (index + 1) % model_count),
                                 ("children", (index - 1) % model_count),
                                 ("eager_parent", (index + 1) % model_count))]


def require_exact_sequence(actual, expected, label):
    if expected:
        require_roster(actual, expected, label)
    elif actual != []:
        raise AcceptanceError(label + " requires the empty query-only edge roster")


def verify_behavior(behavior, model_count, workload):
    required = {"schema_version", "model_count", "workload", "list_of_models",
                "list_of_operations", "list_of_field_checks", "list_of_association_edges", "assertion_failures"}
    if type(behavior) is not dict or set(behavior) != required:
        raise AcceptanceError("Behavior field roster differs")
    if type(behavior["schema_version"]) is not int or behavior["schema_version"] != 1:
        raise AcceptanceError("Behavior schema differs")
    if type(behavior["model_count"]) is not int or behavior["model_count"] != model_count:
        raise AcceptanceError("Behavior model count differs")
    if behavior["workload"] != workload or behavior["assertion_failures"] != []:
        raise AcceptanceError("Behavior workload or assertions failed")
    require_roster(behavior["list_of_models"], model_roster(model_count), "Observed models")
    require_roster(behavior["list_of_operations"], operation_roster(model_count), "Observed operations")
    require_roster(behavior["list_of_field_checks"], field_roster(model_count), "Observed typed field checks")
    require_exact_sequence(behavior["list_of_association_edges"], association_roster(model_count, workload), "Observed edges")


def compile_command(compiler_prefix, source_path, binary_path, build_mode):
    if not isinstance(compiler_prefix, list) or not compiler_prefix or any(
            not isinstance(value, str) or not value.strip() for value in compiler_prefix):
        raise AcceptanceError("An explicit compiler command prefix is required")
    if build_mode not in ("debug", "release"):
        raise AcceptanceError("Complete compile mode must be debug or release")
    command = compiler_prefix + ["build", "--no-color", "-Dwithout_mt", "--threads", "1", str(source_path), "-o", str(binary_path)]
    if build_mode == "release":
        command.append("--release")
    return command


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def portable_relative_path(value, label, allow_root=False):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise AcceptanceError(label + " requires a canonical relative POSIX path")
    path = pathlib.PurePosixPath(value)
    if (path.is_absolute() or ".." in path.parts or path.as_posix() != value
            or (path == pathlib.PurePosixPath(".") and not allow_root)):
        raise AcceptanceError(label + " requires a canonical relative POSIX path")
    return path


def verify_command_artifacts(build, observation):
    """Resolve recorded argv in the archive's portable logical workspace."""
    cwd = portable_relative_path(build.get("compiler_working_directory"), "Compiler working directory", True)
    for argument, artifact in (("source_argument", "fixture_source"), ("binary_argument", "binary")):
        relative = portable_relative_path(build.get(argument), "Compiler " + argument)
        if build[argument].startswith("-") or (cwd / relative).as_posix() != observation[artifact]["path"]:
            raise AcceptanceError("Compiler " + argument + " does not resolve to its hashed " + artifact + " artifact")
    if build.get("binary_command") != ["./" + build["binary_argument"]]:
        raise AcceptanceError("Executed binary command does not resolve to its hashed binary artifact")


def verify_artifact(root, reference):
    if type(reference) is not dict or set(reference) != {"path", "sha256"}:
        raise AcceptanceError("Artifact reference requires path and sha256")
    relative = portable_relative_path(reference["path"], "Artifact path")
    root = pathlib.Path(root).resolve()
    if any(root.joinpath(*relative.parts[:length]).is_symlink() for length in range(1, len(relative.parts) + 1)):
        raise AcceptanceError("Artifact paths require ordinary archived files")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AcceptanceError("Artifact symlink escaped the evidence directory") from error
    require_identity(reference["sha256"], "Artifact SHA-256")
    if not path.is_file() or sha256(path) != reference["sha256"]:
        raise AcceptanceError("Artifact content differs: " + str(relative))
    return path


def verify_observation(observation, cell, contract, artifact_root, admitted_profiles, source_root=None):
    required = {"cell_id", "platform", "adapter", "model_count", "workload", "build_mode", "repetition",
                "compiler_workers", "feature_profile", "cache_state", "compiler_peak_rss_bytes",
                "audited_whole_build_memory_bytes", "profile_id", "source_tree_sha256_before",
                "source_tree_sha256_after", "fixture_source", "fixture_manifest", "behavior",
                "binary", "binary_stdout", "compiler_stdout", "compiler_stderr", "build_receipt", "process_receipt"}
    if type(observation) is not dict or set(observation) != required:
        raise AcceptanceError("Observation field roster differs")
    if observation["cell_id"] != cell.identity:
        raise AcceptanceError("Observation cell identity differs")
    for field in ("platform", "adapter", "model_count", "workload", "build_mode", "repetition"):
        expected = getattr(cell, field)
        if type(observation[field]) is not type(expected) or observation[field] != expected:
            raise AcceptanceError("Observation dimension differs: " + field)
    if type(observation["compiler_workers"]) is not int or observation["compiler_workers"] != contract.compiler_workers:
        raise AcceptanceError("Compiler worker condition differs")
    if observation["feature_profile"] != contract.feature_profile or observation["cache_state"] != "cold_private":
        raise AcceptanceError("Feature or cold-cache condition differs")
    before = require_identity(observation["source_tree_sha256_before"], "Source tree before")
    if require_identity(observation["source_tree_sha256_after"], "Source tree after") != before:
        raise AcceptanceError("Source/dependency inputs changed during build")
    for metric in ("compiler_peak_rss_bytes", "audited_whole_build_memory_bytes"):
        measured = require_integer(observation[metric], metric)
        if measured >= contract.maximum_exclusive_bytes:
            raise AcceptanceError(metric + " exceeded the strict exclusive limit")
    profile_id = observation["profile_id"]
    if not isinstance(profile_id, str) or not profile_id.strip() or profile_id not in admitted_profiles:
        raise AcceptanceError("Toolchain/provider profile is unadmitted")
    profile = admitted_profiles[profile_id]
    if profile.get("platform") != cell.platform or profile.get("adapter") != cell.adapter:
        raise AcceptanceError("Admitted profile dimensions differ")
    if profile.get("whole_build_provider_qualified") is not True:
        raise AcceptanceError("Whole-build provider qualification is pending")
    artifacts = {field: verify_artifact(artifact_root, observation[field]) for field in (
        "fixture_source", "fixture_manifest", "behavior", "binary", "binary_stdout", "compiler_stdout", "compiler_stderr",
        "build_receipt", "process_receipt",
    )}
    fixture = parse_json(artifacts["fixture_manifest"])
    required_fixture = {"schema_version", "adapter", "model_count", "workload", "column_count_per_model",
                        "list_of_field_names", "time_conversion_boundary", "nullable_cases", "source_sha256",
                        "expected_behavior", "grant_require", "adapter_require", "association_identity_boundary"}
    if type(fixture) is not dict or set(fixture) != required_fixture:
        raise AcceptanceError("Generated fixture manifest field roster differs")
    for field in ("adapter", "model_count", "workload"):
        expected = getattr(cell, field)
        if type(fixture[field]) is not type(expected) or fixture[field] != expected:
            raise AcceptanceError("Generated fixture dimensions differ: " + field)
    if type(fixture["schema_version"]) is not int or fixture["schema_version"] != 1:
        raise AcceptanceError("Generated fixture schema differs")
    if type(fixture["column_count_per_model"]) is not int or fixture["column_count_per_model"] != 16:
        raise AcceptanceError("Generated fixture requires all 16 typed columns")
    if fixture["list_of_field_names"] != list(FIELD_NAMES):
        raise AcceptanceError("Generated fixture column roster differs")
    for field in ("grant_require", "adapter_require"):
        if not isinstance(fixture[field], str) or not fixture[field].strip() or pathlib.Path(fixture[field]).is_absolute():
            raise AcceptanceError("Generated fixture import requires a relative source path")
    for field, expected_path in (("grant_require", "src/grant.cr"),
                                 ("adapter_require", "src/adapter/" + cell.adapter + ".cr")):
        # Archive extraction paths can change; source imports retain the recorded
        # workspace layout and bind to the independently accepted checkout.
        candidate = posixpath.normpath(posixpath.join(posixpath.dirname(observation["fixture_source"]["path"]), fixture[field]))
        if not candidate.endswith(".cr"):
            candidate += ".cr"
        if candidate != expected_path:
            raise AcceptanceError("Generated fixture imported another source checkout")
        if source_root is not None and not (pathlib.Path(source_root) / expected_path).is_file():
            raise AcceptanceError("Accepted source checkout is missing the fixture import")
    # The manifest is a claim about generated executable code, so recreate that code.
    from generate_compile_acceptance import generate_fixture
    expected_fixture_source, expected_manifest = generate_fixture(
        cell.adapter, cell.model_count, cell.workload, fixture["grant_require"], fixture["adapter_require"]
    )
    if artifacts["fixture_source"].read_text() != expected_fixture_source or fixture != expected_manifest:
        raise AcceptanceError("Fixture source/manifest differs from the pinned deterministic generator")
    if fixture.get("source_sha256") != sha256(artifacts["fixture_source"]):
        raise AcceptanceError("Generated source differs from fixture manifest")
    observed_behavior = parse_json(artifacts["behavior"])
    verify_behavior(observed_behavior, cell.model_count, cell.workload)
    markers = [line.split("GRANT_COMPILE_ACCEPTANCE_BEHAVIOR=", 1)[1]
               for line in artifacts["binary_stdout"].read_text().splitlines()
               if line.startswith("GRANT_COMPILE_ACCEPTANCE_BEHAVIOR=")]
    if len(markers) != 1 or parse_json_text(markers[0]) != observed_behavior:
        raise AcceptanceError("Executed binary output differs from observed behavior")
    verify_behavior(fixture.get("expected_behavior"), cell.model_count, cell.workload)
    build = parse_json(artifacts["build_receipt"])
    if build.get("cell_id") != cell.identity:
        raise AcceptanceError("Build execution identity differs from cell/repetition")
    if build.get("fixture_source_sha256") != observation["fixture_source"]["sha256"]:
        raise AcceptanceError("Compiled fixture identity differs")
    if build.get("compiler_backend_sha256") != profile.get("compiler_backend_sha256"):
        raise AcceptanceError("Executed compiler backend identity differs")
    require_identity(build.get("compiler_backend_sha256"), "Compiler backend")
    if build.get("exit_status") != 0 or type(build.get("exit_status")) is not int:
        raise AcceptanceError("Complete compiler execution failed")
    if build.get("binary_exit_status") != 0 or type(build.get("binary_exit_status")) is not int:
        raise AcceptanceError("Resulting binary behavior failed")
    if build.get("timed_out") is not False or build.get("cache_started_empty") is not True:
        raise AcceptanceError("Build timeout or cold-cache evidence differs")
    if type(build.get("environment")) is not dict or build["environment"].get("CRYSTAL_WORKERS") != "1":
        raise AcceptanceError("Executed compiler environment lacks the one-worker condition")
    if build.get("binary_sha256") != observation["binary"]["sha256"]:
        raise AcceptanceError("Executed binary identity differs")
    if build.get("source_tree_sha256_before") != before or build.get("source_tree_sha256_after") != before:
        raise AcceptanceError("Build receipt input identities differ")
    verify_command_artifacts(build, observation)
    expected_command = compile_command(profile.get("compiler_prefix"), build.get("source_argument"),
                                       build.get("binary_argument"), cell.build_mode)
    if build.get("command") != expected_command:
        raise AcceptanceError("Complete compile command differs")
    output = artifacts["compiler_stdout"].read_text() + artifacts["compiler_stderr"].read_text()
    if re.search(r"\bwarning\b", output, re.IGNORECASE):
        raise AcceptanceError("Compiler output is YELLOW")
    process = parse_json(artifacts["process_receipt"])
    if process.get("cell_id") != cell.identity:
        raise AcceptanceError("Process execution identity differs from cell/repetition")
    for field in ("complete_process_tree", "short_lived_children_covered", "all_owned_processes_terminal"):
        if process.get(field) is not True:
            raise AcceptanceError("Process provider lost coverage: " + field)
    if process.get("provider_sha256") != profile.get("provider_sha256"):
        raise AcceptanceError("Process provider identity differs")
    require_identity(process.get("provider_sha256"), "Process provider")
    for metric in ("compiler_peak_rss_bytes", "audited_whole_build_memory_bytes"):
        if type(process.get(metric)) is not int or process[metric] != observation[metric]:
            raise AcceptanceError("Raw process metric differs from observation")
    return {"cell_id": cell.identity, "passed": True}


def evaluate_evidence(evidence, contract, artifact_root, admitted_profiles, expected_source, source_root=None):
    if set(expected_source) != {"contract_sha256", "source_commit", "source_tree_sha256", "generator_sha256"}:
        raise AcceptanceError("All independent source identity expectations are required")
    required = {"schema_version", "contract_sha256", "source_commit", "source_tree_sha256",
                "generator_sha256", "list_of_observations"}
    if (type(evidence) is not dict or set(evidence) != required or
            type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1):
        raise AcceptanceError("Evidence envelope field/schema roster differs")
    for field, expected in expected_source.items():
        if evidence.get(field) != expected:
            raise AcceptanceError("Evidence source identity differs: " + field)
    require_identity(evidence["source_commit"], "Source commit", 40)
    for field in ("contract_sha256", "source_tree_sha256", "generator_sha256"):
        require_identity(evidence[field], field)
    observations = evidence["list_of_observations"]
    if not isinstance(observations, list) or not observations:
        raise AcceptanceError("Complete evidence requires the nonempty 144-cell roster")
    cells = {cell.identity: cell for cell in contract.cells()}
    identifiers = [observation.get("cell_id") if isinstance(observation, dict) else None for observation in observations]
    require_roster(identifiers, list(cells), "Compile cells/repetitions")
    verdicts = []
    for observation in observations:
        if observation["source_tree_sha256_before"] != evidence["source_tree_sha256"]:
            raise AcceptanceError("Observation source differs from envelope")
        verdicts.append(verify_observation(observation, cells[observation["cell_id"]], contract,
                                           artifact_root, admitted_profiles, source_root))
    return {"passed": True, "target_state": "accepted", "required_cells": len(cells),
            "accepted_cells": len(verdicts), "list_of_verdicts": verdicts}
