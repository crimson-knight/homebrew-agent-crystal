"""Record a read-only runner candidate and admit only a reviewed exact profile."""

import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import sys


def require(value, message):
    if not value:
        raise RuntimeError(message)


def file_identity(path):
    path = Path(path).resolve(strict=True)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 256 * 2**20,
            "A bounded physical executable file is required: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    after = path.stat()
    fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)
    require(fields(before) == fields(after), "Executable identity changed while reading")
    return {"path": str(path), "bytes": before.st_size, "sha256": digest.hexdigest()}


def docker_api(path):
    endpoint = Path("/var/run/docker.sock").resolve(strict=True)
    before = endpoint.stat()
    require(stat.S_ISSOCK(before.st_mode), "A local Docker API socket is required")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(endpoint))
        connection.sendall(("GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        require(response.status == 200, "Read-only Docker metadata request failed")
        raw = response.read(2**20 + 1)
        require(0 < len(raw) <= 2**20, "Bounded Docker metadata is required")
    after = endpoint.stat()
    require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
            "The local Docker API socket must retain its identity")
    value = json.loads(raw)
    require(isinstance(value, dict), "Docker metadata needs one object")
    return value


def process_start_time(pid):
    raw = Path("/proc/" + str(pid) + "/stat").read_text()
    require(len(raw) <= 16384, "Bounded process identity is required")
    return raw.rsplit(")", 1)[1].split()[19]


def package_versions():
    raw = Path("/var/lib/dpkg/status").read_text()
    require(len(raw.encode()) <= 16 * 2**20, "Bounded package metadata is required")
    selected = {"bash", "sudo", "coreutils", "python3.12-minimal", "docker-ce-cli",
                "docker-ce", "moby-cli", "moby-engine", "containerd.io"}
    result = {}
    for paragraph in raw.split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines()
                      if line and not line[0].isspace() and ": " in line)
        if fields.get("Package") in selected and fields.get("Status") == "install ok installed":
            result[fields["Package"]] = fields["Version"]
    require({"bash", "sudo", "coreutils", "python3.12-minimal"} <= set(result),
            "The directly used bootstrap package versions are required")
    return result


def candidate():
    require(sys.platform == "linux" and os.geteuid() == 0,
            "Read-only Linux metadata collection needs access to the daemon executable")
    docker = shutil.which("docker")
    require(docker is not None, "The installed Docker client is required")
    pid_text = Path("/run/docker.pid").read_text().strip()
    require(re.fullmatch("[1-9][0-9]{0,8}", pid_text) is not None,
            "The running Docker daemon PID is required")
    pid = int(pid_text)
    started = process_start_time(pid)
    daemon = file_identity("/proc/" + str(pid) + "/exe")
    require(Path(daemon["path"]).name == "dockerd", "The recorded process must be dockerd")
    version = docker_api("/version")
    info = docker_api("/info")
    tools = {key: file_identity(path) for key, path in {
        "docker_cli": docker, "sha256sum": "/usr/bin/sha256sum", "timeout": "/usr/bin/timeout",
        "bash": "/usr/bin/bash", "sudo": "/usr/bin/sudo", "python": sys.executable,
    }.items()}
    tools["docker_daemon"] = daemon
    require(process_start_time(pid) == started, "The running daemon identity must remain stable")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?", version["Version"]) is not None,
            "A complete Docker server version is required")
    profile = {key + "_sha256": value["sha256"] for key, value in tools.items()}
    profile.update({
        "docker_server_version": version["Version"], "docker_server_git_commit": version["GitCommit"],
        "docker_api_version": version["ApiVersion"], "kernel_release": os.uname().release,
        "machine": os.uname().machine, "runner_image_os": os.environ.get("ImageOS", ""),
        "runner_image_version": os.environ.get("ImageVersion", ""),
        "cgroup_version": str(info["CgroupVersion"]), "cgroup_driver": info["CgroupDriver"],
        "memory_limit_supported": info["MemoryLimit"], "swap_limit_supported": info["SwapLimit"],
        "package_versions": package_versions(),
    })
    require(all(value != "" for value in profile.values()), "Complete observed runner metadata is required")
    require(profile["machine"] == "x86_64" and profile["cgroup_version"] == "2"
            and profile["memory_limit_supported"] is True and profile["swap_limit_supported"] is True,
            "The proposed runner needs x86_64 cgroup-v2 memory and swap enforcement")
    return {"profile": profile, "tools": tools, "daemon_pid": pid,
            "daemon_start_time_ticks": started, "python_version": sys.version}


def reviewed_profile(expected, observed):
    require(expected.get("format") == "atlas-linux-runner-profile-set-v1",
            "The reviewed profile-set format is required")
    entries = expected.get("profiles")
    require(isinstance(entries, list) and 1 <= len(entries) <= 4,
            "A nonempty finite reviewed profile roster is required")
    encoded = []
    for entry in entries:
        require(isinstance(entry, dict) and entry.get("format") == "atlas-linux-runner-profile-v1"
                and isinstance(entry.get("profile"), dict), "Every reviewed profile needs its exact format")
        encoded.append(json.dumps(entry["profile"], sort_keys=True, separators=(",", ":")))
    require(len(set(encoded)) == len(encoded), "Unique reviewed profiles are required")
    actual = json.dumps(observed, sort_keys=True, separators=(",", ":"))
    matches = [entry for entry, identity in zip(entries, encoded) if identity == actual]
    require(len(matches) == 1, "Observed runner must match one complete reviewed profile")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-profile", required=True)
    parser.add_argument("--github-output", required=True)
    parser.add_argument("--github-env", required=True)
    args = parser.parse_args()
    result = {"format": "atlas-linux-runner-candidate-v1", "admitted": False,
              "actual_container_workloads": 0, "actual_Grant_cells": 0,
              "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "collector": file_identity(__file__)}
    try:
        result.update(candidate())
        expected_path = Path(args.expected_profile)
        if expected_path.is_file():
            expected = reviewed_profile(json.loads(expected_path.read_text()), result["profile"])
            result.update(admitted=True, state="reviewed-profile-matched")
            exports = {
                "ATLAS_DOCKER_CLI_SHA256": expected["profile"]["docker_cli_sha256"],
                "ATLAS_DOCKER_SERVER_VERSION": expected["profile"]["docker_server_version"],
                "ATLAS_SHA256SUM_SHA256": expected["profile"]["sha256sum_sha256"],
                "ATLAS_TIMEOUT_SHA256": expected["profile"]["timeout_sha256"],
            }
            require(all(isinstance(value, str) and "\n" not in value and "\r" not in value
                        for value in exports.values()), "Single-line reviewed profile values are required")
            with Path(args.github_env).open("a") as stream:
                for key, value in exports.items():
                    stream.write(key + "=" + value + "\n")
        else:
            result["state"] = "candidate-recorded; reviewed-profile-and-actual-controls-pending"
    except Exception as error:
        result.update(state="refused-before-container-workloads", error=str(error))
        raise
    finally:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        with Path(args.github_output).open("a") as stream:
            stream.write("admitted=" + str(result["admitted"]).lower() + "\n")
        print(json.dumps(result, indent=2))
    return 0 if result["admitted"] else 2


if __name__ == "__main__":
    sys.exit(main())
