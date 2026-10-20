"""Source-only physical bundle controls with an independently locked manifest."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("sdk_install_qualification.py")
SPEC = importlib.util.spec_from_file_location("bundle_boundary_driver", SOURCE)
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class BundleBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="source bundle with spaces ")
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name)
        names = ["scripts/toolchain_profile.rb", "docs/0.1.1/native-toolchain.md",
                 "skills/crystal-memory-budgets/references/installation-validation.md"]
        names += ["fixture/payload-%02d.txt" % number for number in range(65)]
        self.manifest = {"schema_version": 1, "package_name": "memory_budget",
                         "package_version": "0.1.1", "files": []}
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = ("synthetic bundle payload " + name + "\n").encode()
            path.write_bytes(raw)
            self.manifest["files"].append({"file": name, "sha256": hashlib.sha256(raw).hexdigest()})
        self.original_manifest_sha256 = self.write_manifest()

    def write_manifest(self):
        path = self.root / "PACKAGE_PINS.json"
        path.write_text(json.dumps(self.manifest, indent=2) + "\n")
        return SDK.sha256(path)

    def test_exact_68_payloads_and_69_physical_files_are_accepted(self):
        observed = SDK.verify_bundle(self.root, self.original_manifest_sha256)
        self.assertEqual(len(observed["files"]), 69)
        self.assertEqual(observed["directory_aliases"], {})
        self.assertEqual(observed["files"]["PACKAGE_PINS.json"], self.original_manifest_sha256)

    def test_missing_payload_refuses(self):
        (self.root / self.manifest["files"][0]["file"]).unlink()
        with self.assertRaisesRegex(SDK.QualificationError, "bundle identity differs"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_unexpected_payload_refuses(self):
        (self.root / "unexpected.txt").write_text("unexpected fixture\n")
        with self.assertRaisesRegex(SDK.QualificationError, "bundle identity differs"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_changed_payload_refuses(self):
        (self.root / self.manifest["files"][0]["file"]).write_text("changed fixture\n")
        with self.assertRaisesRegex(SDK.QualificationError, "bundle identity differs"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_contained_alias_still_refuses_the_regular_file_roster(self):
        path = self.root / self.manifest["files"][0]["file"]
        path.unlink()
        path.symlink_to(self.root / self.manifest["files"][1]["file"])
        with self.assertRaisesRegex(SDK.QualificationError, "bundle identity differs"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_changed_and_resealed_manifest_refuses_the_source_lock(self):
        path = self.root / self.manifest["files"][0]["file"]
        path.write_text("changed and resealed fixture\n")
        self.manifest["files"][0]["sha256"] = SDK.sha256(path)
        self.assertNotEqual(self.write_manifest(), self.original_manifest_sha256)
        with self.assertRaisesRegex(SDK.QualificationError, "pinned public source"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_same_count_path_replacement_refuses_the_source_lock(self):
        previous = self.root / self.manifest["files"][0]["file"]
        replacement = self.root / "replacement.txt"
        previous.rename(replacement)
        self.manifest["files"][0]["file"] = "replacement.txt"
        self.write_manifest()
        with self.assertRaisesRegex(SDK.QualificationError, "pinned public source"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_duplicate_payload_path_refuses_even_a_new_expected_manifest(self):
        self.manifest["files"][1] = dict(self.manifest["files"][0])
        with self.assertRaisesRegex(SDK.QualificationError, "exact 68-member"):
            SDK.verify_bundle(self.root, self.write_manifest())

    def test_predecessor_67_payload_shape_refuses(self):
        self.manifest["files"].pop()
        with self.assertRaisesRegex(SDK.QualificationError, "exact 68-member"):
            SDK.verify_bundle(self.root, self.write_manifest())

    def test_manifest_self_listing_refuses(self):
        self.manifest["files"][0] = {"file": "PACKAGE_PINS.json", "sha256": "0" * 64}
        with self.assertRaisesRegex(SDK.QualificationError, "exact 68-member"):
            SDK.verify_bundle(self.root, self.write_manifest())

    def test_changed_package_identity_refuses(self):
        self.manifest["package_version"] = "9.9.9"
        with self.assertRaisesRegex(SDK.QualificationError, "reviewed package identity"):
            SDK.verify_bundle(self.root, self.write_manifest())

    def test_missing_or_invalid_independent_manifest_pin_refuses(self):
        for value in (None, False, 123, "", "unreviewed", "A" * 64):
            with self.subTest(value=value), self.assertRaisesRegex(SDK.QualificationError, "source-locked manifest"):
                SDK.verify_bundle(self.root, value)

    def test_post_execution_payload_and_manifest_revalidation_refuses_damage(self):
        before = SDK.verify_bundle(self.root, self.original_manifest_sha256)
        self.assertEqual(SDK.verify_bundle(self.root, self.original_manifest_sha256), before)
        (self.root / self.manifest["files"][2]["file"]).write_text("post-execution changed fixture\n")
        with self.assertRaises(SDK.QualificationError):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_manifest_changed_after_admitted_read_refuses_the_physical_roster(self):
        original_read = Path.read_bytes
        manifest_path = self.root / "PACKAGE_PINS.json"

        def changed_after_read(path):
            raw = original_read(path)
            if path == manifest_path:
                path.write_bytes(raw + b"\n")
            return raw

        with mock.patch.object(Path, "read_bytes", changed_after_read):
            with self.assertRaisesRegex(SDK.QualificationError, "bundle identity differs"):
                SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_extra_unwritten_fifo_refuses_before_any_payload_hashing(self):
        os.mkfifo(self.root / "unwritten-fifo")
        with mock.patch.object(SDK, "sha256", side_effect=AssertionError("hashing followed special node")):
            with self.assertRaisesRegex(SDK.QualificationError, "ordinary regular files"):
                SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_manifest_fifo_refuses_before_opening_it(self):
        manifest_path = self.root / "PACKAGE_PINS.json"
        manifest_path.unlink()
        os.mkfifo(manifest_path)
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("read followed FIFO manifest")):
            with self.assertRaisesRegex(SDK.QualificationError, "ordinary regular files"):
                SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_contained_directory_alias_refuses(self):
        (self.root / "directory-alias").symlink_to(self.root / "fixture", target_is_directory=True)
        with self.assertRaisesRegex(SDK.QualificationError, "ordinary directories"):
            SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_bundle_root_alias_refuses(self):
        alias = self.root / "root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(SDK.QualificationError, "ordinary root directory"):
            SDK.verify_bundle(alias, self.original_manifest_sha256)

    def test_socket_and_device_kind_metadata_refuses_before_hashing(self):
        target = self.root / self.manifest["files"][0]["file"]
        ordinary_file = Path.is_file
        for kind in ("socket", "character-device", "block-device"):
            with self.subTest(kind=kind), mock.patch.object(Path, "is_file", lambda path: False if path == target else ordinary_file(path)):
                with mock.patch.object(SDK, "sha256", side_effect=AssertionError("hashing followed special kind")):
                    with self.assertRaisesRegex(SDK.QualificationError, "ordinary regular files"):
                        SDK.verify_bundle(self.root, self.original_manifest_sha256)

    def test_unreadable_directory_refuses_the_roster(self):
        def denied_walk(*arguments, **options):
            options["onerror"](PermissionError("synthetic unreadable bundle directory"))
        with mock.patch.object(SDK.os, "walk", side_effect=denied_walk):
            with self.assertRaisesRegex(SDK.QualificationError, "unreadable directory"):
                SDK.verify_bundle(self.root, self.original_manifest_sha256)


if __name__ == "__main__":
    unittest.main()
