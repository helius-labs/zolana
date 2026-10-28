#!/usr/bin/env python3
"""Validate generated policy PRs before running CI on their exact commits."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('release-client-policy.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
REPO = policy.REPO
CONTEXTS = ('async prover / transfer queue', 'Client policy checks')


def api(path, payload=None):
    args = ['gh', 'api', path]
    if payload is None:
        return json.loads(subprocess.check_output(args, text=True))
    return json.loads(subprocess.check_output(args + ['--method', 'POST', '--input', '-'], input=json.dumps(payload), text=True))


def identity(number, head):
    policy.require(str(number).isdigit() and re.fullmatch(r'[0-9a-f]{40}', head), 'Invalid client policy PR identity')
    pr = api(f'repos/{REPO}/pulls/{number}')
    policy.require(pr['state'] == 'open' and pr['head']['sha'] == head and pr['head']['ref'] == policy.BRANCH and
                   pr['head']['repo']['full_name'] == REPO and pr['base']['ref'] == 'main', 'Client policy PR was superseded or is not the generated branch')
    policy.require(pr.get('mergeable') is True and re.fullmatch(r'[0-9a-f]{40}', pr.get('merge_commit_sha') or ''), 'Client policy merge commit is not ready; polling will retry')
    return {'head': head, 'base': pr['base']['sha'], 'merge': pr['merge_commit_sha']}


def validate(shas, request_id):
    command = policy.command
    command('git', 'fetch', 'origin', shas['base'], shas['head'])
    changed = set(command('git', 'diff', '--name-only', shas['base'], shas['head']).splitlines())
    policy.require(changed <= {policy.POLICY, policy.DEFAULT, 'sdk-libs/ts/CHANGELOG.md'} and changed,
                   'Native policy CI accepts only generated policy files and release notes')
    original = json.loads(command('git', 'show', shas['base'] + ':' + policy.POLICY))
    expected = {**original, 'deployment': policy.overlap(original['deployment'], policy.qualified(request_id))}
    actual = json.loads(command('git', 'show', shas['head'] + ':' + policy.POLICY))
    policy.require(actual == expected, 'Policy PR differs from the qualified rotation or removes existing trust')
    with tempfile.TemporaryDirectory() as directory:
        default = Path(directory) / 'default.ts'
        default.write_text('/** Mirrors `sdk-libs/prover-tee/src/policy.json`, kept equal by a test. */\nexport const DEFAULT_TEE_POLICY_FILE: Readonly<{ deployment: unknown }> = Object.freeze(' + json.dumps(expected, indent=2) + ');\n')
        subprocess.run(['npx', '--yes', 'oxfmt@0.67.0', '--write', str(default)], check=True)
        policy.require(command('git', 'show', shas['head'] + ':' + policy.DEFAULT) == default.read_text().strip(), 'Generated TypeScript policy contains unrelated code')


def report(shas, state, description):
    url = f"https://github.com/{REPO}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    for sha in (shas['head'], shas['merge']):
        for context in CONTEXTS:
            api(f'repos/{REPO}/statuses/{sha}', {'context': context, 'state': state, 'description': description, 'target_url': url})


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['start', 'report'])
    p.add_argument('--pr', required=True)
    p.add_argument('--head', required=True)
    p.add_argument('--base')
    p.add_argument('--merge')
    p.add_argument('--request')
    p.add_argument('--result')
    a = p.parse_args()
    shas = identity(a.pr, a.head)
    if a.action == 'start':
        policy.require(shas['base'] == os.environ['GITHUB_SHA'], 'Main advanced before policy validation; polling will retry against the current base')
        validate(shas, a.request)
        report(shas, 'pending', 'Running transfer queue and client policy validation')
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(f"head={shas['head']}\nbase={shas['base']}\nmerge={shas['merge']}\n")
    else:
        policy.require(shas['base'] == a.base and shas['merge'] == a.merge, 'PR base changed; validate the current merge again')
        report(shas, 'success' if a.result == 'success' else 'failure',
               'Transfer queue and client policy validation passed' if a.result == 'success' else 'Client policy validation failed; inspect this run')
