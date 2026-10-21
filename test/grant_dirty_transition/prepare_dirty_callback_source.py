"""Project immutable Grant bytes for a separately admitted real callback on the hosted job."""
import argparse
from pathlib import Path
from propose_dirty_transition import ROOT, need
from stage_grant_sources import stage
from vendor.verify_compile_acceptance import source_input_inventory
from hook_callback import ORIGINAL_SOURCE_SHA256, PROBE_RELATIVE


def prepare(output):
    need(output.is_absolute() and not output.exists(), 'Fresh absolute callback source projection required')
    receipt = stage(ROOT / 'inputs/grant-source-and-frozen-dependencies.tar.gz', output)
    grant = output / 'grant'
    need(source_input_inventory(grant)[1] == ORIGINAL_SOURCE_SHA256, 'Exact original Grant callback project required')
    probe = grant / PROBE_RELATIVE
    probe.parent.mkdir(parents=True)
    probe.write_bytes((ROOT / 'source/hook_callback_probe.cr.txt').read_bytes())
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    prepare(parser.parse_args().output)
