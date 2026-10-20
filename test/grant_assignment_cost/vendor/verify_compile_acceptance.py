#!/usr/bin/env python3
"""Verify the complete source-bound Grant matrix; incomplete qualification exits 2."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

from compile_acceptance_contract import (
    AcceptanceError, CompileAcceptanceContract, evaluate_evidence, parse_json,
    require_identity, sha256,
)


def source_input_inventory(source_root):
    """Include hidden dependency metadata and resolved symlink content."""
    source_root = pathlib.Path(source_root).resolve()
    inventory = []
    visited_directories = {}
    visited_files = {}

    def visit(path, logical):
        if path.is_symlink():
            inventory.append({"path": logical, "kind": "symlink", "target": str(path.readlink())})
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, RuntimeError) as error:
            raise AcceptanceError("Compiler input symlink target is missing or unsupported: " + logical) from error
        if resolved.is_dir():
            if resolved in visited_directories:
                inventory.append({"path": logical, "kind": "directory_reference",
                                  "canonical_path": visited_directories[resolved]})
                return
            visited_directories[resolved] = logical
            for child in sorted(path.iterdir()):
                relative = logical + "/" + child.name
                if child.name in (".git", "__pycache__") or relative == "performance/results":
                    continue
                visit(child, relative)
        elif resolved.is_file():
            if resolved in visited_files:
                inventory.append({"path": logical, "kind": "file_reference", "canonical_path": visited_files[resolved]})
                return
            visited_files[resolved] = logical
            inventory.append({"path": logical, "kind": "file", "sha256": sha256(resolved)})
        else:
            raise AcceptanceError("Compiler input is missing or unsupported: " + logical)

    for relative in ("src", "spec", "scripts", "performance", "examples", "bench", "config", "lib",
                     "shard.yml", "shard.lock", ".crystal-flags", ".amber.yml"):
        path = source_root / relative
        if path.exists() or path.is_symlink():
            visit(path, relative)
    if not any(item["path"].startswith("lib/") and item["kind"] == "file" for item in inventory):
        raise AcceptanceError("Frozen dependency source inventory is empty")
    payload = json.dumps(inventory, sort_keys=True, separators=(",", ":"))
    return inventory, hashlib.sha256(payload.encode()).hexdigest()


def load_admitted_profiles(path):
    registry = parse_json(path)
    if type(registry) is not dict or set(registry) != {"schema_version", "list_of_profiles"} or registry["schema_version"] != 1:
        raise AcceptanceError("Admitted-profile registry schema differs")
    entries = registry["list_of_profiles"]
    if not isinstance(entries, list) or not entries:
        raise AcceptanceError("Compiler/whole-build profiles await qualification and admission")
    profiles = {}
    required = {"profile_id", "platform", "adapter", "whole_build_provider_qualified", "compiler_prefix",
                "compiler_backend_sha256", "provider_sha256", "qualification_receipt_sha256"}
    for profile in entries:
        if type(profile) is not dict or set(profile) != required:
            raise AcceptanceError("Admitted-profile field roster differs")
        identity = profile["profile_id"]
        if not isinstance(identity, str) or not identity.strip() or identity in profiles:
            raise AcceptanceError("Admitted-profile identities must be nonblank and unique")
        for field in ("compiler_backend_sha256", "provider_sha256", "qualification_receipt_sha256"):
            require_identity(profile[field], field)
        if profile["whole_build_provider_qualified"] is not True:
            raise AcceptanceError("Admitted profile lacks whole-build qualification")
        profiles[identity] = profile
    return profiles


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=pathlib.Path)
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--source-root", type=pathlib.Path, required=True)
    parser.add_argument("--admitted-profiles", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    report = {"passed": False, "target_state": "unmet", "list_of_errors": []}
    try:
        contract = CompileAcceptanceContract.from_dict(parse_json(args.contract))
        source_root = args.source_root.resolve()
        source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
        status = subprocess.check_output(["git", "status", "--porcelain"], cwd=source_root, text=True)
        if status:
            raise AcceptanceError("Final acceptance requires a clean source commit")
        _inventory, source_tree = source_input_inventory(source_root)
        generator = source_root / "scripts/generate_compile_acceptance.py"
        if not generator.is_file():
            raise AcceptanceError("The deterministic fixture generator is missing")
        expected = {"source_commit": source_commit, "source_tree_sha256": source_tree,
                    "contract_sha256": sha256(args.contract), "generator_sha256": sha256(generator)}
        profiles = load_admitted_profiles(args.admitted_profiles)
        profile_sha256 = sha256(args.admitted_profiles)
        report.update(evaluate_evidence(parse_json(args.evidence), contract, args.evidence.resolve().parent,
                                       profiles, expected, source_root))
        if source_input_inventory(source_root)[1] != source_tree:
            raise AcceptanceError("Source/dependency inputs changed during verification")
        if sha256(args.admitted_profiles) != profile_sha256:
            raise AcceptanceError("Admitted profiles changed during verification")
        report["source_identity"] = expected
        report["admitted_profiles_sha256"] = profile_sha256
    except (AcceptanceError, OSError, subprocess.CalledProcessError) as error:
        report["passed"] = False
        report["target_state"] = "unmet"
        report["list_of_errors"].append(str(error))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
