"""Physical metadata and mocked-flow controls for bounded diagnostic discovery."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cpu = load("bounded_cpu_under_test", ROOT / "sdk_cpu_diagnostic.py")
native = load("bounded_native_under_test", ROOT / "linux_native_projection.py")
reader = load("bounded_stable_reader", ROOT / "linux_projection_identity.py")


def elf_bytes(kind=2, entry=None):
    base = 0x400000 if kind == 2 else 0
    data = bytearray(b"\x90" * 2048)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, kind, 62, 1,
                     base + 0x100 if entry is None else entry, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, base, base, len(data), len(data), 4096)
    data[0x120:0x130] = bytes(range(16))
    return bytes(data)


class BoundedDiagnosticControls(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory(prefix="bounded diagnostic physical metadata ")
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name).resolve()
        self.binary = self.root / "retained arithmetic ELF"
        self.binary.write_bytes(elf_bytes())

    def roster(self):
        return native.Roster(reader.file_identity, time.monotonic() + 15)

    def debugger(self, pc=0x400120, entry=0x400100):
        return f"Program received signal SIGILL, Illegal instruction.\nrip 0x{pc:x} 0x{pc:x}\nEntry point: 0x{entry:x}\n"

    def test_entry_address_window_is_at_most_256_bytes(self):
        selection = cpu.disassembly_selection(self.binary)
        self.assertTrue(selection["selection_qualified"])
        self.assertEqual(selection["basis"], "ELF entry point")
        self.assertEqual(selection["stop_address"] - selection["start_address"], 256)
        args = cpu.disassembly_arguments("objdump", self.binary, selection)
        self.assertEqual(args, ["objdump", "-d", "--start-address=0x400100", "--stop-address=0x400200", self.binary])

    def test_entry_window_clips_to_file_backed_segment(self):
        self.binary.write_bytes(elf_bytes(entry=0x4007f0))
        selection = cpu.disassembly_selection(self.binary)
        self.assertTrue(selection["selection_qualified"])
        self.assertEqual(selection["stop_address"] - selection["start_address"], 16)

    def test_fixed_address_fault_maps_to_exact_retained_bytes(self):
        selection = cpu.disassembly_selection(self.binary, self.debugger())
        self.assertTrue(selection["selection_qualified"])
        self.assertEqual(selection["center_address"], 0x400120)
        self.assertEqual(selection["fault_file_offset"], 0x120)
        self.assertEqual(selection["fault_file_bytes_hex"], bytes(range(16)).hex())
        self.assertLessEqual(selection["stop_address"] - selection["start_address"], 256)

    def test_PIE_fault_maps_using_actual_runtime_entry_point(self):
        self.binary.write_bytes(elf_bytes(kind=3))
        slide = 0x555550000000
        selection = cpu.disassembly_selection(self.binary, self.debugger(slide + 0x120, slide + 0x100))
        self.assertTrue(selection["selection_qualified"])
        self.assertEqual(selection["center_address"], 0x120)
        self.assertEqual(selection["runtime_rip"], slide + 0x120)
        self.assertEqual(selection["fault_file_bytes_hex"], bytes(range(16)).hex())

    def test_fault_in_external_provider_keeps_unqualified_entry_symbol(self):
        selection = cpu.disassembly_selection(self.binary, self.debugger(pc=0x7fffffff0000))
        self.assertFalse(selection["selection_qualified"])
        self.assertIn("executable segment", selection["selection_error"])
        self.assertEqual(cpu.disassembly_arguments("objdump", self.binary, selection),
                         ["objdump", "-d", "--disassemble=_start", self.binary])

    def test_missing_actual_signal_keeps_fault_unqualified(self):
        selection = cpu.disassembly_selection(self.binary, self.debugger().replace("SIGILL", "SIGSEGV"))
        self.assertFalse(selection["selection_qualified"])
        self.assertIn("SIGILL required", selection["selection_error"])

    def test_duplicate_runtime_RIP_keeps_fault_unqualified(self):
        selection = cpu.disassembly_selection(self.binary, self.debugger() + "rip 0x400130 duplicate\n")
        self.assertFalse(selection["selection_qualified"])

    def test_changed_fixed_executable_runtime_entry_refuses_mapping(self):
        selection = cpu.disassembly_selection(self.binary, self.debugger(entry=0x401100))
        self.assertFalse(selection["selection_qualified"])
        self.assertIn("relocation", selection["selection_error"])

    def test_non_page_aligned_PIE_runtime_entry_refuses_mapping(self):
        self.binary.write_bytes(elf_bytes(kind=3))
        selection = cpu.disassembly_selection(self.binary, self.debugger(pc=0x555550000121, entry=0x555550000101))
        self.assertFalse(selection["selection_qualified"])

    def test_malformed_ELF_preserves_qualified_fault_boundary(self):
        self.binary.write_bytes(b"MODELED malformed ELF metadata")
        selection = cpu.disassembly_selection(self.binary)
        self.assertFalse(selection["selection_qualified"])
        self.assertEqual(selection["symbol"], "_start")

    def test_changed_program_header_bounds_refuse_address_selection(self):
        raw = bytearray(elf_bytes())
        struct.pack_into("<Q", raw, 32, len(raw) + 64)
        self.binary.write_bytes(raw)
        selection = cpu.disassembly_selection(self.binary)
        self.assertFalse(selection["selection_qualified"])

    def test_oversized_address_window_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "finite disassembly"):
            cpu.disassembly_arguments("objdump", self.binary,
                {"kind": "address-window", "start_address": 1, "stop_address": 258})

    def test_changed_symbol_fallback_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "entry-symbol"):
            cpu.disassembly_arguments("objdump", self.binary, {"kind": "selected-symbol", "symbol": "changed"})

    def test_complete_mocked_flow_preserves_both_targets_and_selected_fault(self):
        original = load("bounded_original_behavior_fixture", ROOT / "test_sdk_cpu_diagnostic.py")
        case = original.DiagnosticTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.tearDown)
        prior = original.FakeRunner.run
        def run(runner, label, arguments, **options):
            value = prior(runner, label, arguments, **options)
            if label.endswith("-build"):
                Path(arguments[-1]).write_bytes(elf_bytes())
            if label.endswith("-fault-location"):
                (runner.output / (label + ".stdout.txt")).write_text(self.debugger())
            return value
        with mock.patch.object(original.FakeRunner, "run", run):
            code, result = case.full_case()
        self.assertEqual(code, 0)
        self.assertEqual(set(result["contrasts"]), {"default", "generic"})
        default, generic = result["contrasts"]["default"], result["contrasts"]["generic"]
        self.assertTrue(default["fault_address_qualified"])
        self.assertFalse(generic["fault_address_qualified"])
        self.assertEqual(default["phase"], "generated_program_sigill")
        self.assertEqual(generic["phase"], "arithmetic_build_and_runtime_passed")
        for row in (default, generic):
            self.assertTrue(row["disassembly_selection"]["selection_qualified"])
            self.assertTrue(any(arg.startswith("--start-address=") for arg in row["disassembly"]["arguments"]))
        self.assertIn("info files", default["debugger"]["arguments"])
        self.assertIn("x/16xb $pc", default["debugger"]["arguments"])
        self.assertFalse(result["ordinary_smoke_accepted"])
        self.assertFalse(result["sdk_accepted"])
        self.assertTrue(result["terminal_clock_verified"])

    def test_synthetic_ELF_keeps_exact_binary_hash_and_original_caps(self):
        # The synthetic ELF is parsed as bytes; process creation remains guarded.
        selection = cpu.disassembly_selection(self.binary)
        self.assertEqual(selection["binary_sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(cpu.MAXIMUM_SECONDS, 240)
        self.assertEqual(cpu.MAXIMUM_RAW_BYTES, 32 * 2**20)

    def test_original_output_refusal_retains_completed_default_build_and_runtime(self):
        original = load("bounded_partial_behavior_fixture", ROOT / "test_sdk_cpu_diagnostic.py")
        case = original.DiagnosticTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.tearDown)
        prior = original.FakeRunner.run
        def run(runner, label, arguments, **options):
            if label == "default-disassembly":
                runner.refusal = "Command exceeded its raw-output budget"
            return prior(runner, label, arguments, **options)
        with mock.patch.object(original.FakeRunner, "run", run):
            code, result = case.full_case()
        self.assertEqual(code, 1)
        self.assertIn("raw-output budget", result["error"])
        self.assertEqual(result["contrasts"]["default"]["build"]["exit_code"], 0)
        self.assertEqual(result["contrasts"]["default"]["runtime"]["exit_code"], -4)
        self.assertNotIn("generic", result["contrasts"])

    def test_directory_reproduces_original_open_error_and_is_retained(self):
        directory = self.root / "lib"
        directory.mkdir()
        with self.assertRaises(IsADirectoryError):
            directory.open("rb")
        roster, result, seen = self.roster(), {}, set()
        physical = native.classify_elf_candidates(roster, [str(directory)], seen, result)
        self.assertEqual(physical, [])
        self.assertEqual(roster.entries[str(directory)]["kind"], "directory")
        self.assertEqual(result["non_ELF_candidates"][0]["classification"], "directory-provenance")
        self.assertEqual(result["non_ELF_candidate_count"], 1)
        self.assertIn(str(directory), seen)

    def test_directory_alias_retains_lexical_and_physical_provenance(self):
        directory = self.root / "real lib"
        directory.mkdir()
        alias = self.root / "lib alias"
        alias.symlink_to(directory.name)
        roster, result = self.roster(), {}
        native.classify_elf_candidates(roster, [str(alias)], set(), result)
        self.assertEqual(roster.entries[str(alias)]["target"], directory.name)
        self.assertEqual(result["non_ELF_candidates"][0]["requested_path"], str(alias))
        self.assertEqual(result["non_ELF_candidates"][0]["resolved_path"], str(directory))

    def test_regular_non_ELF_input_has_explicit_hash_accounting(self):
        text = self.root / "linker script"
        text.write_bytes(b"MODELED linker script input")
        result = {}
        self.assertEqual(native.classify_elf_candidates(self.roster(), [str(text)], set(), result), [])
        row = result["non_ELF_candidates"][0]
        self.assertEqual(row["classification"], "regular-non-ELF")
        self.assertEqual(row["sha256"], hashlib.sha256(text.read_bytes()).hexdigest())

    def test_mixed_candidates_forward_only_unique_ELF_files(self):
        directory = self.root / "directory"; directory.mkdir()
        text = self.root / "text"; text.write_bytes(b"text")
        alias = self.root / "ELF alias"; alias.symlink_to(self.binary.name)
        roster, result = self.roster(), {}
        physical = native.classify_elf_candidates(roster, [str(directory), str(text), str(alias), str(self.binary)], set(), result)
        self.assertEqual(physical, [str(self.binary)])
        self.assertEqual(result["non_ELF_candidate_count"], 2)
        self.assertEqual(len(result["ELF_candidate_classifications"]), 4)

    def test_changed_file_kind_refuses_instead_of_becoming_directory_provenance(self):
        roster = self.roster()
        roster.add(self.binary, required=True)
        self.binary.unlink(); self.binary.mkdir()
        with self.assertRaisesRegex(RuntimeError, "regular-file kind"):
            native.classify_elf_candidates(roster, [str(self.binary)], set(), {})

    def test_changed_directory_mode_refuses(self):
        directory = self.root / "directory"; directory.mkdir(mode=0o755)
        roster = self.roster(); roster.add(directory, required=True)
        directory.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError, "directory changed"):
            native.classify_elf_candidates(roster, [str(directory)], set(), {})

    def test_static_ELF_wave_capacity_remains_96(self):
        paths = []
        for index in range(97):
            path = self.root / ("ELF-" + str(index)); path.write_bytes(b"\x7fELF fixture")
            paths.append(str(path))
        result = {}
        with self.assertRaisesRegex(RuntimeError, "input budget"):
            native.classify_elf_candidates(self.roster(), paths, set(), result)
        self.assertEqual(len(result["ELF_candidate_classifications"]), 97)

    def test_missing_required_candidate_preserves_prior_classifications(self):
        directory = self.root / "a directory"; directory.mkdir()
        result = {}
        with self.assertRaisesRegex(RuntimeError, "Required native path is absent"):
            native.classify_elf_candidates(self.roster(), [str(directory), str(self.root / "z missing")], set(), result)
        self.assertEqual(result["non_ELF_candidates"][0]["classification"], "directory-provenance")


if __name__ == "__main__":
    unittest.main()
