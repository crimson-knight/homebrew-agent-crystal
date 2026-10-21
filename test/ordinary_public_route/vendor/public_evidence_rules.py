"""Select contained public source evidence as regular files for hosted upload."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys
import tarfile

OUTER_SHA = "39ae53df3f72668f63101e0f65606cc41b2787c71292bff0f163031bb4bb309e"
ANCESTOR_SHA = "aebd690e5978aa6373e2177aa7ee2d5bcb8b7e064cc50aee18ae9c4d53fc5601"
INNER_SHA = "d2c90cc3110109337c92f567fdf533dadf475b3f468602b8fcb5e2ed21426ff5"
CONTENTS_SHA = "6ed26546943e29553c6cdf062652ecd30529924da402b53b5b39d3f7f6456080"
PINS_SHA = "b4510c07cfc5078e12ed24a0f1aaa50a80b861b420c9716d94dfae2beeb71164"
MAX_FILE = 20 * 2**20
MAX_TOTAL = 64 * 2**20
LABELS = ("v100-ordinary", "v100-optimized", "v102-ordinary", "v102-optimized", "v101-successor-ordinary", "v101-successor-optimized")
PATTERNS = (
    re.compile(rb"authorization\s*:\s*(?:basic|bearer)\s+[A-Za-z0-9_+/=-]{16,}", re.I),
    re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(rb"https?://[^\s/:@]+:[^\s/@]+@", re.I),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
)


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def public_path(name):
    path = PurePosixPath(name)
    need(bool(name) and str(path) == name and not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts), "Canonical contained evidence path required")
    forbidden = {".git", ".gitconfig", ".git-credentials", ".netrc", ".ssh", ".aws", ".npmrc", ".pypirc", ".env"}
    need(not any(part.casefold() in forbidden for part in path.parts), "Public evidence excludes checkout and credential metadata")
    need(not any(path.parts[i:i+2] == ("linux_whole_build_ci_v100", "checkout") for i in range(len(path.parts)-1)), "Provider checkout stays outside public evidence")
    return path


def read_regular(root, name):
    relative = public_path(name)
    need(root.resolve(strict=True) == root and stat.S_ISDIR(root.lstat().st_mode), "Exact physical evidence root required")
    path = root
    for component in relative.parts[:-1]:
        path /= component
        need(stat.S_ISDIR(path.lstat().st_mode), "Physical contained evidence parent required")
    path /= relative.name
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE, "Bounded single-link regular evidence file required")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino, opened.st_size) == (before.st_dev, before.st_ino, before.st_size), "Stable regular evidence identity required")
        raw = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns), "Stable complete bounded evidence bytes required")
    need(path.resolve(strict=True) == path and path.is_relative_to(root), "Contained physical evidence readback required")
    return raw


def inspect_public_bytes(name, raw, archive_sha=None):
    public_path(name)
    if archive_sha is not None:
        need(digest(raw) == archive_sha, "Exact public archive identity required")
        expanded = 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for index, member in enumerate(archive):
                need(index < 4096, "Bounded public archive member count required")
                public_path(member.name)
                need(member.isfile() or member.isdir() or member.issym(), "Reviewed public archive member kind required")
                expanded += member.size
                need(member.size <= MAX_FILE and expanded <= MAX_TOTAL, "Bounded public archive metadata required")
                if member.isfile() and not member.name.endswith(".tar.gz"):
                    data = archive.extractfile(member).read(MAX_FILE + 1)
                    need(not any(pattern.search(data) for pattern in PATTERNS), "Public archive credential-shaped content refused")
        return
    need(not any(pattern.search(raw) for pattern in PATTERNS), "Public evidence credential-shaped content refused")


def stage_evidence(sdk, output, stage):
    sdk = Path(sdk)
    output = Path(output)
    stage = Path(stage)
    need(stage.parent.resolve(strict=True) == stage.parent and not stage.exists() and not stage.is_symlink(), "Fresh physical public evidence stage required")
    public = sdk / "tools/grant_compile_acceptance"
    pin_raw = read_regular(public, "PUBLICATION_PINS.v101.json")
    need(digest(pin_raw) == PINS_SHA, "Exact public publication manifest required")
    pins = json.loads(pin_raw)
    python = Path(sys.executable).resolve(strict=True)
    python_sha = digest(python.read_bytes())
    need(any(row["version"] == platform.python_version() and row["sha256"] == python_sha for row in pins["source_python_profiles"][sys.platform]), "Exact observed source Python profile required for staging")
    plan = [(public, "PUBLICATION_PINS.v101.json", "public/PUBLICATION_PINS.v101.json", PINS_SHA, None)]
    for row in pins["files"]:
        archive_sha = row["sha256"] if row["path"].endswith(".tar.gz") else None
        plan.append((public, row["path"], "public/" + row["path"], row["sha256"], archive_sha))
    for name in ("CI_SOURCE_EXECUTION.json", "VERIFICATION_RECEIPT.json", "cohorts.stdout.txt", "cohorts.stderr.txt"):
        plan.append((output, name, "execution/" + name, None, None))
    cohort_root = "source cohorts with spaces/"
    plan.append((output, cohort_root + "SOURCE_TEST_RECEIPT.json", "execution/SOURCE_TEST_RECEIPT.json", None, None))
    for label in LABELS:
        for stream in ("stdout", "stderr"):
            name = label + "." + stream + ".txt"
            plan.append((output, cohort_root + name, "cohorts/" + name, None, None))
    verified_root = "verified package with spaces/"
    for name, expected in (("outer-reproduced.tar.gz", OUTER_SHA), ("inner-reproduced.tar.gz", INNER_SHA)):
        plan.append((output, verified_root + name, "reproduced/" + name, expected, expected))
    payload = verified_root + "grant-first-build-publication-v101/"
    contents = None
    try:
        contents_raw = read_regular(output, payload + "PACKAGE_CONTENTS.json")
    except FileNotFoundError:
        pass
    else:
        need(digest(contents_raw) == CONTENTS_SHA, "Exact reproduced member manifest required")
        contents = json.loads(contents_raw)
        members = {row["path"]: row["sha256"] for row in contents["files"]}
        plan.append((output, payload + "PACKAGE_CONTENTS.json", "manifests/PACKAGE_CONTENTS.json", CONTENTS_SHA, None))
        for name in ("PORTABLE_HELPER_COMPATIBILITY.v101.json", "origin/INNER_TAR_MEMBER_LEDGER.json", "origin/ARCHIVE_MEMBER_ORIGINS_COMPLETE.json", "successor_source/TOOL_SOURCE_PINS.json", "workspace/grant_linux_first_build_v102/SOURCE_PINS.json", "workspace/grant_linux_first_build_v102/ANCESTOR_SOURCE_ROSTER.json"):
            plan.append((output, payload + name, "manifests/" + name, members[name], None))
    selected, missing = [], []
    total = 0
    for root, source_name, destination, expected, archive_sha in plan:
        public_path(destination)
        try:
            raw = read_regular(root, source_name)
        except FileNotFoundError:
            need(root == output, "Every exact public source input required")
            missing.append(destination)
            continue
        need(expected is None or digest(raw) == expected, "Exact selected evidence digest required")
        inspect_public_bytes(destination, raw, archive_sha)
        total += len(raw)
        need(total <= MAX_TOTAL, "Bounded complete public evidence required")
        selected.append((destination, raw))
    # Successful source execution requires the complete twelve-stream evidence set.
    selected_map = dict(selected)
    if "execution/CI_SOURCE_EXECUTION.json" in selected_map:
        ci = json.loads(selected_map["execution/CI_SOURCE_EXECUTION.json"])
        if ci.get("source_controls_passed") is True:
            need(not missing and contents is not None, "Complete passing source evidence required")
            tests = json.loads(selected_map["execution/SOURCE_TEST_RECEIPT.json"])
            rows = tests["cohorts"] + tests["successor_regressions"]
            need(len(rows) == 6 and {row["label"] for row in rows} == set(LABELS), "All six original/regression cohorts required")
            for row in rows:
                for stream in ("stdout", "stderr"):
                    meta = row[stream]
                    need(meta["path"] == row["label"] + "." + stream + ".txt", "Exact raw cohort path required")
                    raw = selected_map["cohorts/" + meta["path"]]
                    need(len(raw) == meta["bytes"] and digest(raw) == meta["sha256"], "Exact raw cohort stream required")
    stage.mkdir(mode=0o700)
    rows = []
    for name, raw in selected:
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(raw)
        destination.chmod(0o644)
        need(read_regular(stage, name) == raw, "Exact staged evidence readback required")
        rows.append({"path": name, "bytes": len(raw), "sha256": digest(raw), "kind": "regular file"})
    receipt = {"mission": "memory-budget-experiment", "public_evidence_stage_passed": True,
        "selection": "Exact named public archives, reproduced archives/manifests, receipts, and twelve raw cohort streams",
        "workspace_and_provider_selection": "outside the staged evidence tree", "required_hidden_Grant_inputs": "retained in exact hash-pinned public source archives",
        "credential_metadata_refusal_passed": True, "files": rows, "missing_failure_evidence": missing,
        "source_python": {"version": platform.python_version(), "sha256": python_sha, "path": str(python)},
        "actual_compiler_container_native_ssh_jobs": 0, "accepted_target_cells": 0, "required_target_cells": 144}
    receipt_raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    inspect_public_bytes("PUBLIC_EVIDENCE_STAGE.json", receipt_raw)
    with (stage / "PUBLIC_EVIDENCE_STAGE.json").open("xb") as stream:
        stream.write(receipt_raw)
    expected_names = {row["path"] for row in rows} | {"PUBLIC_EVIDENCE_STAGE.json"}
    observed = set()
    for path in stage.rglob("*"):
        relative = path.relative_to(stage).as_posix()
        public_path(relative)
        need(not path.is_symlink(), "Physical staged evidence members required")
        if path.is_file():
            staged_raw = read_regular(stage, relative)
            need(staged_raw == (receipt_raw if relative == "PUBLIC_EVIDENCE_STAGE.json" else selected_map[relative]), "Final staged evidence retains exact selected bytes")
            observed.add(relative)
        else:
            need(stat.S_ISDIR(path.lstat().st_mode), "Physical staged evidence directories required")
    need(observed == expected_names, "Complete exact staged evidence membership required")
    return receipt


if __name__ == "__main__":
    receipt = stage_evidence(Path.cwd().resolve(), Path(os.environ["RUNNER_TEMP"]).resolve() / "grant-source-package-controls",
        Path(os.environ["RUNNER_TEMP"]).resolve() / "grant-source-package-public-evidence")
    print(json.dumps({"public_evidence_stage_passed": True, "regular_files": len(receipt["files"]), "missing_failure_evidence": receipt["missing_failure_evidence"]}))
