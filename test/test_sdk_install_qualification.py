import hashlib
import copy
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
import shlex


MODULE_PATH = pathlib.Path(__file__).with_name("sdk_install_qualification.py")
SPEC = importlib.util.spec_from_file_location("sdk_install_qualification", MODULE_PATH)
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


class SpecResultTest(unittest.TestCase):
    def test_accepts_actual_passing_and_regression_shapes(self):
        SDK.verify_spec_result("39 examples, 0 failures, 0 errors, 0 pending\n", "", 39)
        SDK.verify_spec_result("construct_record: crystal_allocation_calls crystal_requested_bytes\n1 example, 1 failure, 0 errors, 0 pending\n", "", 1, 1)

    def test_rejects_wrong_counts_pending_errors_warnings_and_conflicting_summaries(self):
        observations = [
            ("38 examples, 0 failures, 0 errors\n", ""),
            ("39 examples, 0 failures, 0 errors, 1 pending\n", ""),
            ("39 examples, 0 failures, 1 error\n", ""),
            ("39 examples, 0 failures, 0 errors\nWarning: unsupported counter\n", ""),
            ("39 examples, 0 failures, 0 errors\n", "loader problem"),
            ("39 examples, 0 failures, 0 errors\n1 example, 1 failure, 0 errors\n", ""),
        ]
        for output, errors in observations:
            with self.subTest(output=output, errors=errors), self.assertRaises(SDK.QualificationError):
                SDK.verify_spec_result(output, errors, 39)

    def test_regression_requires_allocation_failure(self):
        with self.assertRaises(SDK.QualificationError):
            SDK.verify_spec_result("1 example, 1 failure, 0 errors\n", "", 1, 1)


class SourceArchiveTest(unittest.TestCase):
    def make_archive(self, root, names=("src/example.cr",), contents=b"source\n"):
        archive_path = root / "source.tar.gz"
        rows = []
        with tarfile.open(archive_path, "w:gz") as archive:
            for relative in names:
                member = tarfile.TarInfo("memory_budget-" + "a" * 40 + "/" + relative)
                member.size = len(contents)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(contents))
                rows.append({"file": relative, "bytes": len(contents), "mode": "100644",
                             "sha256": hashlib.sha256(contents).hexdigest(),
                             "git_blob": hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()})
        return archive_path, {"commit": "a" * 40, "archive_sha256": SDK.sha256(archive_path),
                              "archive_bytes": archive_path.stat().st_size, "files": rows}

    def test_extracts_exact_source_and_detects_later_source_damage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive, lock = self.make_archive(root)
            SDK.extract_sdk(archive, root / "output", lock)
            SDK.verify_source(root / "output", lock["files"])
            (root / "output/src/example.cr").write_text("changed\n")
            with self.assertRaises(SDK.QualificationError):
                SDK.verify_source(root / "output", lock["files"])

    def test_rejects_escape_duplicate_hash_and_mode_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for names in (("../escape",), ("src/example.cr", "src/example.cr")):
                archive, lock = self.make_archive(root, names)
                with self.subTest(names=names), self.assertRaises(SDK.QualificationError):
                    SDK.extract_sdk(archive, root / "output", lock)
            for key, changed in (("sha256", "0" * 64), ("git_blob", "0" * 40), ("mode", "100755")):
                archive, lock = self.make_archive(root)
                lock["files"][0][key] = changed
                with self.subTest(key=key), self.assertRaises(SDK.QualificationError):
                    SDK.extract_sdk(archive, root / "output", lock)
            self.assertFalse((root.parent / "escape").exists())


class StandardLibraryTest(unittest.TestCase):
    def test_internal_alias_damage_is_detected_separately_from_file_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "linux").mkdir()
            (root / "darwin").mkdir()
            (root / "linux/file.cr").write_text("linux\n")
            (root / "darwin/file.cr").write_text("darwin\n")
            (root / "selected").symlink_to("linux", target_is_directory=True)
            original = SDK.tree_identity(root)
            expected = {"stdlib_sha256": original["sha256"], "stdlib_file_count": len(original["files"]),
                        "stdlib_directory_aliases": original["directory_aliases"]}
            SDK.verify_stdlib(original, expected)
            (root / "selected").unlink()
            (root / "selected").symlink_to("darwin", target_is_directory=True)
            damaged = SDK.tree_identity(root)
            self.assertEqual(original["sha256"], damaged["sha256"])
            with self.assertRaises(SDK.QualificationError):
                SDK.verify_stdlib(damaged, expected)

    def test_external_alias_requires_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "stdlib"
            root.mkdir()
            (root / "external").symlink_to(root.parent, target_is_directory=True)
            with self.assertRaises(SDK.QualificationError):
                SDK.tree_identity(root)


class FormulaReceiptTest(unittest.TestCase):
    def test_requires_exact_source_and_one_actual_source_build(self):
        expected = {"version": "1.21.0-incremental-1", "source_archive_sha256": "a" * 64}
        receipt = [{"versions": {"stable": expected["version"]},
                    "urls": {"stable": {"checksum": expected["source_archive_sha256"]}},
                    "installed": [{"version": expected["version"], "poured_from_bottle": False}]}]
        SDK.verify_formula_receipt(receipt, expected)
        mutations = []
        changed = copy.deepcopy(receipt)
        changed[0]["versions"]["stable"] = "1.22.0"
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed[0]["urls"]["stable"]["checksum"] = "b" * 64
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed[0]["installed"][0]["poured_from_bottle"] = True
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed[0]["installed"] = []
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed[0]["installed"] *= 2
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(SDK.QualificationError):
                SDK.verify_formula_receipt(changed, expected)


class CompilerWrapperTest(unittest.TestCase):
    def test_accepts_actual_homebrew_environment_assignments_before_exec(self):
        prefix = pathlib.Path("/home/linuxbrew/.linuxbrew")
        install = prefix / "Cellar/agent-crystal/1.21.0-incremental-1"
        compiler = install / "libexec/agent-crystal-bin"
        stdlib = install / "share/agent-crystal/src"
        wrapper = '#!/bin/bash\nCRYSTAL_PATH="lib:' + str(stdlib) + '" LD_RUN_PATH="${LD_RUN_PATH:+${LD_RUN_PATH}:}' + str(prefix / "lib") + '" exec "' + str(compiler) + '"  "$@"\n'
        SDK.verify_wrapper(wrapper, compiler, stdlib, prefix, "Linux")
        for changed in (wrapper.replace(str(compiler), "/other/compiler"),
                        wrapper.replace("CRYSTAL_PATH=", "OTHER_PATH="),
                        wrapper.replace("LD_RUN_PATH=", "OTHER_LOADER="),
                        wrapper + "printf unexpected\\n\n"):
            with self.subTest(changed=changed), self.assertRaises(SDK.QualificationError):
                SDK.verify_wrapper(changed, compiler, stdlib, prefix, "Linux")

    def test_accepts_static_darwin_wrapper_with_spaces(self):
        prefix = pathlib.Path("/ordinary prefix with spaces")
        compiler = prefix / "Cellar/agent-crystal/1.21.0-incremental-1/libexec/agent-crystal-bin"
        stdlib = compiler.parent.parent / "share/agent-crystal/src"
        wrapper = "#!/bin/bash\n" + shlex.quote("CRYSTAL_PATH=lib:" + str(stdlib)) + " exec " + shlex.quote(str(compiler)) + ' "$@"\n'
        SDK.verify_wrapper(wrapper, compiler, stdlib, prefix, "Darwin")


if __name__ == "__main__":
    unittest.main()
