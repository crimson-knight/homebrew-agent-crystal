"""Derive the manual tool-observation/resume workflow from the frozen dirtyv102 workflow."""
from pathlib import Path
import re
import shlex

ROOT = Path(__file__).resolve().parent
raw = (ROOT / 'grant-dirty-transition-mac.proposed.yml').read_text()
raw = raw.replace('permissions: {}', 'permissions:\n  actions: read')
raw = raw.replace('  ATLAS_GRANT_PACKET_SHA256:', '  ATLAS_GRANT_TRANSFER_SHA256: TRANSFER_MANIFEST_LITERAL\n  ATLAS_GRANT_PACKET_SHA256:')
begin = raw.index('      - name: Admit exact hosted API and lint providers')
end = raw.index('      - name: Install the ordinary formula', begin)
raw = raw[:begin] + '''      - name: Retain real pending-provider negative control
        timeout-minutes: 1
        run: |
          python3 - <<'PYTHON'
          import hashlib, json, os, pathlib, runpy, sys
          root = pathlib.Path("test/grant_dirty_transition").resolve()
          for filename, variable in (("SOURCE_PINS.json", "ATLAS_GRANT_PACKET_SHA256"), ("TRANSFER_SOURCE_PINS.json", "ATLAS_GRANT_TRANSFER_SHA256")):
              pins = root / filename
              if hashlib.sha256(pins.read_bytes()).hexdigest() != os.environ[variable]:
                  raise SystemExit("Exact externally reviewed manifest differs")
              for row in json.loads(pins.read_bytes())["files"]:
                  path = root / row["path"]
                  if path.is_symlink() or len(path.read_bytes()) != row["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
                      raise SystemExit("Exact execution source differs: " + row["path"])
          source = root / "preflight_transferred_tools.py"
          sys.argv = [str(source), "--proof-tools", str(root / "PROOF_TOOLS_PENDING.json"), "--proof-tools-sha256", "7dc906cffee33465969acc8c00b6c65d5339cebe0506be5311831624a89e5893"]
          try:
              runpy.run_path(str(source), run_name="__main__")
          except SystemExit as error:
              if type(error.code) is not int or error.code != 2:
                  raise
          else:
              raise SystemExit("Pending proof registry unexpectedly admitted")
          PYTHON

      - name: Allocate fresh private finite tool transfer
        id: transfer_start
        timeout-minutes: 1
        run: |
          python3 -I -S -B test/grant_dirty_transition/proof_tool_transfer.py initialize --root "$RUNNER_TEMP" --transfer-sha256 "$ATLAS_GRANT_TRANSFER_SHA256"

      - name: Transfer the exact independently reviewed preparation artifact
        id: tool_download
        timeout-minutes: 2
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          artifact-ids: '12310618101'
          repository: crimson-knight/homebrew-agent-crystal
          run-id: '39518892906'
          github-token: ${{ github.token }}
          merge-multiple: true
          path: ${{ steps.transfer_start.outputs.workspace }}/download

      - name: Verify all37 artifact members and canonical tool source identities
        id: tool_transfer
        timeout-minutes: 1
        env:
          TRANSFER_WORKSPACE: ${{ steps.transfer_start.outputs.workspace }}
          TRANSFER_CLOCK_SHA256: ${{ steps.transfer_start.outputs.clock_sha256 }}
        run: |
          python3 -I -S -B test/grant_dirty_transition/proof_tool_transfer.py transfer --root "$TRANSFER_WORKSPACE" --clock-sha256 "$TRANSFER_CLOCK_SHA256" --transfer-sha256 "$ATLAS_GRANT_TRANSFER_SHA256"

      - name: Exercise guarded transferred-source sensitivity controls
        timeout-minutes: 2
        env:
          TRANSFER_WORKSPACE: ${{ steps.transfer_start.outputs.workspace }}
        run: |
          python3 -I -S -B test/grant_dirty_transition/test_tool_transfer.py --artifact-directory "$TRANSFER_WORKSPACE/download"
          python3 -O -I -S -B test/grant_dirty_transition/test_tool_transfer.py --artifact-directory "$TRANSFER_WORKSPACE/download"

''' + raw[end:]
position = raw.index('      - name: Prove APIs and run original')
raw = raw[:position] + '''      - name: Observe exact same-job native inputs before analysis-tool execution
        id: tool_admission
        timeout-minutes: 3
        env:
          TRANSFER_WORKSPACE: ${{ steps.transfer_start.outputs.workspace }}
        run: |
          python3 -I -S -B test/grant_dirty_transition/proof_tool_transfer.py observe --root "$TRANSFER_WORKSPACE" --sdk-evidence "$RUNNER_TEMP/grant-sdk-readiness" --transfer-sha256 "$ATLAS_GRANT_TRANSFER_SHA256"

''' + raw[position:]
raw = raw.replace('        id: grant\n', "        id: grant\n        if: ${{ steps.tool_admission.outputs.execution_admitted == 'true' }}\n        env:\n          TRANSFER_WORKSPACE: ${{ steps.transfer_start.outputs.workspace }}\n")
raw = raw.replace('source = root / "run_dirty_experiment.py"', 'source = root / "run_admitted_dirty.py"')
raw = raw.replace('          source = root / "run_admitted_dirty.py"', '          # The guard preserves run_dirty_experiment.py through its separately pinned deadline successor.\n          source = root / "run_admitted_dirty.py"')
old = '"--proof-tools", str(root / "PROOF_TOOLS_PENDING.json"), "--proof-tools-sha256", "7dc906cffee33465969acc8c00b6c65d5339cebe0506be5311831624a89e5893",'
new = '"--proof-tools", str(pathlib.Path(os.environ["TRANSFER_WORKSPACE"]) / "PROOF_TOOLS.json"), "--proof-tools-sha256", hashlib.sha256((pathlib.Path(os.environ["TRANSFER_WORKSPACE"]) / "PROOF_TOOLS.json").read_bytes()).hexdigest(),\n              "--tool-workspace", os.environ["TRANSFER_WORKSPACE"], "--transfer-packet-sha256", os.environ["ATLAS_GRANT_TRANSFER_SHA256"],'
if raw.count(old) != 1:
    raise RuntimeError('One exact positive experiment registry argument block required')
raw = raw.replace(old, new)
position = raw.index('      - name: Preserve original SDK and same-job readiness evidence')
raw = raw[:position] + '''      - name: Retire verified private tool payload after complete return
        if: ${{ always() && steps.transfer_start.outcome == 'success' }}
        timeout-minutes: 1
        env:
          TRANSFER_WORKSPACE: ${{ steps.transfer_start.outputs.workspace }}
        run: |
          python3 -I -S -B test/grant_dirty_transition/proof_tool_transfer.py cleanup --root "$TRANSFER_WORKSPACE" --transfer-sha256 "$ATLAS_GRANT_TRANSFER_SHA256"

      - name: Stage exact tool admission and return metadata
        id: tool_stage
        if: ${{ always() && steps.transfer_start.outcome == 'success' }}
        timeout-minutes: 1
        env:
          TRANSFER_WORKSPACE: ${{ steps.transfer_start.outputs.workspace }}
        run: |
          python3 -I -S -B test/grant_dirty_transition/stage_tool_admission.py --source "$TRANSFER_WORKSPACE" --output "$RUNNER_TEMP/grant-tool-admission-artifact" --transfer-sha256 "$ATLAS_GRANT_TRANSFER_SHA256"

      - name: Preserve positive analysis-tool admission metadata
        if: ${{ always() && steps.tool_stage.outcome == 'success' }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v4.6.2
        with:
          name: grant-proof-tool-runtime-admission
          path: ${{ runner.temp }}/grant-tool-admission-artifact
          if-no-files-found: error
          retention-days: 30
          include-hidden-files: false

''' + raw[position:]


def pinned_cli(match):
    script, arguments = match.group('script'), shlex.split(match.group('arguments'))
    # Exact inline verification precedes importing the first local source file.
    # The token remains confined to the supported download action interface.
    lines = ["python3 " + (match.group('optimization') or '') + "- <<'PYTHON'", 'import hashlib, json, os, pathlib, runpy, stat, sys',
             'root = pathlib.Path("test/grant_dirty_transition").resolve()',
             'for filename, variable in (("SOURCE_PINS.json", "ATLAS_GRANT_PACKET_SHA256"), ("TRANSFER_SOURCE_PINS.json", "ATLAS_GRANT_TRANSFER_SHA256")):',
             '    raw = (root / filename).read_bytes()',
             '    if hashlib.sha256(raw).hexdigest() != os.environ[variable]:',
             '        raise SystemExit("Exact execution manifest differs")',
             '    for row in json.loads(raw)["files"]:',
             '        path = root / row["path"]',
             '        if not stat.S_ISREG(path.lstat().st_mode):',
             '            raise SystemExit("Physical execution source required")',
             '        value = path.read_bytes()',
             '        if len(value) != row["bytes"] or hashlib.sha256(value).hexdigest() != row["sha256"]:',
             '            raise SystemExit("Exact execution source differs")',
             'source = root / ' + repr(script),
             'sys.argv = [str(source), *[os.path.expandvars(value) for value in ' + repr(arguments) + ']]',
             'runpy.run_path(str(source), run_name="__main__")', 'PYTHON']
    return '\n'.join('          ' + line for line in lines)


raw = re.sub(r'^          python3 (?P<optimization>-O )?-I -S -B test/grant_dirty_transition/(?P<script>proof_tool_transfer\.py|stage_tool_admission\.py|test_tool_transfer\.py) (?P<arguments>.*)$',
             pinned_cli, raw, flags=re.M)
# The existing core verifies its own source packet. The additive guard source is
# independently admitted before the first local import in that same inline call.
raw = raw.replace('          source = root / "run_admitted_dirty.py"',
    '          transfer_raw = (root / "TRANSFER_SOURCE_PINS.json").read_bytes()\n'
    '          if hashlib.sha256(transfer_raw).hexdigest() != os.environ["ATLAS_GRANT_TRANSFER_SHA256"]:\n'
    '              raise SystemExit("Exact transfer manifest differs")\n'
    '          for row in json.loads(transfer_raw)["files"]:\n'
    '              path = root / row["path"]\n'
    '              if path.is_symlink() or len(path.read_bytes()) != row["bytes"] or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:\n'
    '                  raise SystemExit("Exact transfer source differs")\n'
    '          source = root / "run_admitted_dirty.py"')
(ROOT / 'grant-dirty-tools-transfer-mac.proposed.yml').write_text(raw)
