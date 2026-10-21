"""Prepare a rich2 four-arm source plan rooted at the unchanged edeb inventory."""
import json
from pathlib import Path

from propose_dirty_transition import ROOT, PATHS, derive, need, sha
from prepare_comparison import fingerprint

ARMS = ('original', 'comparison', 'transition', 'restored')
TOTAL_SECONDS = 15000
SETUP_SECONDS = 600
PROOF_SECONDS = 6600
MEASUREMENT_SECONDS = 7200
CONTROLLER_RETURN_SECONDS = 600
ARM_SECONDS = 1500
MEASUREMENT_RETURN_SECONDS = 600


def source_rows(arm):
    original = json.loads((ROOT / 'inputs/SOURCE_INPUTS.json').read_bytes())['inputs']
    values = derive(arm)
    rows = []
    for row in original:
        if row['path'] == 'src/grant/dirty.cr':
            for relative in PATHS[2:]:
                if values[relative] is not None:
                    rows.append(dict(path=relative,kind='file',sha256=sha(values[relative])))
        copied = dict(row)
        if row['path'] in PATHS and row['kind'] == 'file':
            copied['sha256'] = sha(values[row['path']])
        rows.append(copied)
    return rows


def prepare(output, grant, compiler):
    need(output.is_absolute() and not output.exists() and not output.is_symlink() and grant.is_absolute() and compiler.is_absolute(),
         'Fresh absolute source-plan paths required')
    output.mkdir(parents=True)
    baseline = json.loads((ROOT / 'inputs/SOURCE_INPUTS.json').read_bytes())
    need(fingerprint(source_rows('original')) == baseline['source_tree_sha256'], 'Exact unchanged1554 original source required')
    for suffix in ('cr.txt','json'):
        (output / ('FIXTURE_2.' + suffix)).write_bytes((ROOT / ('inputs/FIXTURE_2.' + suffix)).read_bytes())
    fixture = json.loads((output / 'FIXTURE_2.json').read_bytes())
    need(fixture['model_count'] == 2 and fixture['source_sha256'] == sha((output / 'FIXTURE_2.cr.txt').read_bytes()), 'Unchanged full rich2 fixture required')
    runs = []
    for arm in ARMS:
        requested = derive(arm)
        for relative,raw in requested.items():
            if raw is not None:
                target = output / 'overlays' / arm / (relative + '.txt')
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(raw)
        directory = grant / 'performance/results/compile-acceptance' / ('dirty-transition-' + arm + '-2-r1')
        runs.append(dict(arm=arm,models=2,repetition=1,working_directory=str(grant),output_directory=str(directory),
            source_rows=len(source_rows(arm)),expected_source_tree_sha256=fingerprint(source_rows(arm)),
            source_overlay={name:sha(raw) if raw is not None else None for name,raw in requested.items()},
            unchanged_fixture_source_sha256=fixture['source_sha256'],
            compile_argv=[str(compiler),'build','--no-color','--error-on-warnings','-Dwithout_mt','--threads','1',str(directory/'fixture.cr'),'-o',str(directory/'fixture')],
            runtime_argv=[str(directory/'fixture')],
            same_binary_controls=[dict(label='normal',field_canary='0',association_canary='0',expected_exit=0),
                dict(label='field-canary',field_canary='1',association_canary='0',expected_exit=1,required_assertion='AcceptancePerson0000 field first_name'),
                dict(label='association-canary',field_canary='0',association_canary='1',expected_exit=1,required_assertion='AcceptancePerson0000 parent model identity')]))
    value = dict(format='atlas-grant-fixed-carrier-dirty-four-arm-source-plan-v1',mission='memory-budget-experiment',
        ordered_arms=list(ARMS),runs=runs,models=2,repetition=1,adapter='sqlite',mode='debug',
        workload=dict(fields=32,operations=6,association_edges=6,all_original_default_features_preserved=True),
        source_fingerprints={arm:fingerprint(source_rows(arm)) for arm in ARMS},overlay_paths=list(PATHS),
        limits=dict(total=TOTAL_SECONDS,setup=SETUP_SECONDS,proof=PROOF_SECONDS,measurement=MEASUREMENT_SECONDS,
            controller_return=CONTROLLER_RETURN_SECONDS,arm=ARM_SECONDS,measurement_return=MEASUREMENT_RETURN_SECONDS,build=900,runtime=120),
        variant='fixed-carrier-full-dirty-transition',execution_admitted=False,actual_target_cells_accepted=0,required_target_cells=144,required_target_matrix_size=144,
        original_comparison_transition_restored=True,memory_savings_accepted=False,shipping_compatibility_accepted=False,
        explicit_design_refinement='Both candidates share separate fixed-carrier != and == helpers, preserving literal original operators, operand direction and evaluation counts')
    (output/'DIRTY_PLAN.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    return value
