"""Separate exact hosted fixture automation from local Codex application-edit admission."""
import os
from pathlib import Path
import re
from same_job_policy import identity, DRIVER_SHA256, LOCK_SHA256
from propose_dirty_transition import ROOT, need
from run_hosted_contrast import digest
from vendor.verify_compile_acceptance import source_input_inventory
import hook_callback


def hosted_value(grant, admission):
    job = admission['job_identity']
    runner = admission['runner']
    need(runner['run_id'] == job['GITHUB_RUN_ID'] and runner['run_attempt'] == job['GITHUB_RUN_ATTEMPT'] and
         runner['source_commit'] == job['GITHUB_SHA'] and runner['system'] == 'Darwin' and runner['machine'] == 'arm64' and
         runner['qualification_script_sha256'] == DRIVER_SHA256 and runner['source_lock_sha256'] == LOCK_SHA256,
         'Exact retained successful same-job SDK run/source/provider authority required for hosted automation')
    for name in ('observed_profile_sha256','observed_provider_sha256'):
        need(re.fullmatch('[0-9a-f]{64}',admission[name]) is not None,'Exact SDK profile/provider evidence identity required')
    return dict(format='atlas-grant-dirty-execution-context-v101',kind='hosted-ci-fixture-automation',
        project=str(grant),source_tree_sha256=hook_callback.ORIGINAL_SOURCE_SHA256,
        job_identity=job,sdk_driver_sha256=DRIVER_SHA256,sdk_source_lock_sha256=LOCK_SHA256,
        sdk_profile_sha256=admission['observed_profile_sha256'],sdk_provider_sha256=admission['observed_provider_sha256'],
        actual_callback_verified=False,local_application_source_edits_admitted=False,
        scope='Private fixture materialization through reviewed hosted automation; actual API/format/lint/spec/owner/runtime gates required')


def admit(grant, admission, tools, callback_path=None, callback_sha256=None, environment=None):
    environment = os.environ if environment is None else environment
    need(grant.is_absolute() and grant.resolve(strict=True) == grant and
         source_input_inventory(grant)[1] == hook_callback.ORIGINAL_SOURCE_SHA256,
         'Exact unchanged actual Grant project before context admission required')
    if environment.get('GITHUB_ACTIONS') == 'true':
        need(identity(environment) == admission['job_identity'] and
             isinstance(environment.get('ATLAS_GRANT_JOB_NONCE'),str) and
             re.fullmatch('[0-9a-f]{64}',environment['ATLAS_GRANT_JOB_NONCE']) is not None,
             'Current GitHub run/attempt/source/job/runner and sealed SDK nonce required')
        return dict(value=hosted_value(grant,admission),protected={})
    callback = hook_callback.admit(callback_path,callback_sha256,grant,admission,tools,environment)
    return dict(value=dict(format='atlas-grant-dirty-execution-context-v101',kind='local-codex-application-edit',
        project=str(grant),source_tree_sha256=hook_callback.ORIGINAL_SOURCE_SHA256,
        actual_callback_verified=True,local_application_source_edits_admitted=True,callback_receipt_sha256=callback_sha256),
        callback=callback['receipt'],protected=callback['protected'])


def complete(value, grant, admission):
    if value['kind'] == 'hosted-ci-fixture-automation':
        need(value == hosted_value(grant,admission),'Exact derived hosted execution context required at return')
    else:
        need(value['format'] == 'atlas-grant-dirty-execution-context-v101' and value['kind'] == 'local-codex-application-edit' and
             value['project'] == str(grant) and value['source_tree_sha256'] == hook_callback.ORIGINAL_SOURCE_SHA256 and
             value['actual_callback_verified'] is True and value['local_application_source_edits_admitted'] is True and
             re.fullmatch('[0-9a-f]{64}',value['callback_receipt_sha256']) is not None,
             'Local application edits require exact real callback evidence')
