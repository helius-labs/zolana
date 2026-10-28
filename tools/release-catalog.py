#!/usr/bin/env python3
"""Build one immutable release only after every artifact and source quality check is ready."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import re

from release_evidence import download, load_signed, publish_signed, put

BUCKET = 'zolana-nitro-eif-558215002830'
SERVICES = {'photon': 'photon', 'forester': 'forester', 'prover': 'forester_prover'}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def release_context():
    identifier = os.environ.get('RELEASE_CONTEXT_ID')
    if not identifier:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'current.json'
            download('release-context/current.json', path)
            identifier = json.loads(path.read_text())['context_id']
    if not re.fullmatch(r'[0-9a-f]{64}', identifier):
        raise ValueError('Invalid release context ID')
    context = load_signed(f'release-context/{identifier}.json', 'helius-labs/zolana-infra',
                          'helius-labs/zolana-infra/.github/workflows/release.yml')
    if context.get('version') != 1 or digest(context) != identifier:
        raise ValueError('Release context contents changed')
    os.environ['RELEASE_CONTEXT_ID'] = identifier
    return context


def infra_file(path):
    context = release_context()
    files = {'infra/releases/devnet-d.json': context['desired'],
             'infra/releases/v0.5.0-alpha.json': context['configuration'],
             'infra/releases/catalog/' + context['release']['id'] + '.json': context['release']}
    if path not in files:
        raise ValueError('Release context does not contain the requested base release')
    return files[path]


def output(**values):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        for key, value in values.items():
            stream.write(f'{key}={json.dumps(value,separators=(",",":")) if not isinstance(value,str) else value}\n')


def nitro_profile(configuration, base, head):
    # A client-policy merge must not create another enclave identity.
    source = command('git','log','--first-parent','-1','--format=%H',head,'--','prover/server/',
                     ':(exclude)**/*.md',':(exclude)**/*_test.go',':(exclude)**/testdata/**',':(exclude)**/scripts/**')
    tools = command('git','log','--first-parent','-1','--format=%H',head,'--',
                    'prover/server/Dockerfile.nitro','prover/server/nitro/',
                    'prover/server/build-release.sh','prover/server/build-aeglos.sh',
                    'tools/images.json','tools/release-image.sh','.github/workflows/publish-nitro.yml')
    # Protocol checks must still observe the deployed on-chain program version.
    protocol_source = configuration['source_commit']
    if subprocess.run(['git','merge-base','--is-ancestor',source,protocol_source]).returncode == 0:
        source = protocol_source
    return {'source_commit':source,'build_tools_commit':tools,
            'backend':configuration['client_prover']['backend'],
            'concurrency':configuration['client_prover']['concurrency'],
            'indexer_url':base['nitro']['measurements']['indexer_url']}


def verify_protocol(configuration, head):
    deployed = configuration['source_commit']
    approved = [deployed] + [entry['source_commit'] for entry in configuration.get('compatible_protocol_builds', []) if entry.get('protocol_source') == deployed]
    if not any(not command('git', 'diff', '--name-only', revision, head, '--', 'programs', 'program-libs') for revision in approved):
        raise ValueError('Source protocol differs from the deployed programs or libraries. Approve and deploy the protocol migration before publishing this environment; compatibility cannot be inferred from a successful build.')


def plan():
    desired = infra_file('infra/releases/devnet-d.json')
    base = infra_file('infra/releases/catalog/' + desired['release'] + '.json')
    configuration = infra_file('infra/releases/v0.5.0-alpha.json')
    verify_protocol(configuration, os.environ['GITHUB_SHA'])
    Path(os.environ['RUNNER_TEMP'], 'base-release.json').write_text(json.dumps(base))
    spec = importlib.util.spec_from_file_location('changes', 'tools/release-changes.py')
    changes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(changes)
    subprocess.run(['git', 'merge-base', '--is-ancestor', base['source_commit'], os.environ['GITHUB_SHA']], check=True)
    paths = command('git', 'diff', '--name-only', base['source_commit'], os.environ['GITHUB_SHA']).splitlines()
    selected = changes.changed_services(paths)
    requested = os.environ.get('SERVICE', 'changed')
    if requested != 'changed':
        selected['services'] = sorted(set(selected['services']) | {requested})
        selected['nitro'] = selected['nitro'] or requested == 'prover'
    profile = nitro_profile(configuration, base, os.environ['GITHUB_SHA'])
    candidate = digest(profile)
    verification_changed=any(p.startswith('tools/release-probe/') for p in paths)
    output(release_context=os.environ['RELEASE_CONTEXT_ID'], services=selected['services'], nitro=selected['nitro'], any=bool(selected['services'] or selected['nitro'] or verification_changed),
           short_sha=os.environ['GITHUB_SHA'][:12], base_release=base['id'], profile=json.dumps(profile,separators=(',',':')), measured_source=profile['source_commit'], build_tools=profile['build_tools_commit'], candidate=candidate, generation='tee-' + candidate[:20])


def component(service, image, path):
    record = {'kind': 'component', 'name': SERVICES[service], 'image': image, 'source_commit': os.environ['GITHUB_SHA']}
    if service == 'photon':
        root = Path('services/photon/src/migration')
        record['schema_digest'] = digest({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*.rs'))})
        declared = Path('services/photon/rollback-compatibility.json')
        record['rollback_compatible_schemas'] = sorted(set(json.loads(declared.read_text()).get('rollback_compatible_schemas', []))) if declared.exists() else []
        record['compatible_schemas'] = sorted(set([record['schema_digest']] + (json.loads(declared.read_text()).get('compatible_schemas', []) if declared.exists() else [])))
    Path(path).write_text(json.dumps(record, sort_keys=True) + '\n')


def quality(path):
    deadline = time.monotonic() + 5400
    excluded = {'publish-image.yml','publish-nitro.yml','publish-service-image.yml','publish-gpu.yml','deploy-tee.yml'}
    while time.monotonic() < deadline:
        all_runs = json.loads(command('gh', 'api', '--paginate', '--slurp', f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs?head_sha={os.environ['GITHUB_SHA']}&event=push&per_page=100"))
        runs = [r for page in all_runs for r in page['workflow_runs'] if r['path'].rsplit('/',1)[-1] not in excluded]
        latest = {}
        for run in runs:
            previous = latest.get(run['workflow_id'])
            if previous is None or (run['run_number'],run['run_attempt']) > (previous['run_number'],previous['run_attempt']):
                latest[run['workflow_id']] = run
        # This workflow always runs on main; do not race delayed workflow creation.
        if any(r['path'].endswith('/typescript.yml') for r in latest.values()) and all(r['status'] == 'completed' for r in latest.values()):
            failed = [r['name'] for r in latest.values() if r['conclusion'] not in ('success','skipped','neutral')]
            if failed:
                raise ValueError('Release blocked by source CI: ' + ', '.join(failed))
            passed = [r for r in latest.values() if r['conclusion'] == 'success']
            if not passed:
                raise ValueError('Release requires successful source CI')
            Path(path).write_text(json.dumps({'passed':True,'runs':[{'id':r['id'],'attempt':r['run_attempt'],'path':r['path']} for r in sorted(passed,key=lambda r:r['id'])]}))
            return
        time.sleep(15)
    raise ValueError('Source quality checks have not completed; no deployable release was published')


def put_immutable(key, path):
    result = subprocess.run(['aws','s3api','put-object','--bucket',BUCKET,'--key',key,'--body',str(path),'--content-type','application/json','--if-none-match','*'], capture_output=True,text=True)
    if result.returncode:
        if 'PreconditionFailed' not in result.stderr:
            raise ValueError('Cannot publish immutable release object: ' + result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            old = Path(directory)/'old.json'
            command('aws','s3api','get-object','--bucket',BUCKET,'--key',key,str(old))
            if json.loads(old.read_text()) != json.loads(Path(path).read_text()):
                raise ValueError('Immutable publication already exists with different contents')


def assemble(parts, base_id, quality_path, destination):
    base = infra_file('infra/releases/catalog/' + base_id + '.json')
    record = {k:v for k,v in base.items() if k not in ('id','bootstrap','quality','legacy_client_policy')}
    record['source_commit'] = os.environ['GITHUB_SHA']
    found = set()
    for path in Path(parts).rglob('*.json'):
        part = json.loads(path.read_text())
        if part['kind'] == 'component':
            name = part.pop('name'); part.pop('kind')
            if name in found:raise ValueError('Duplicate release component: '+name)
            record['components'][name] = part
            found.add(name)
        elif part['kind'] == 'nitro':
            if 'nitro' in found:raise ValueError('Duplicate Nitro artifact')
            record['nitro'] = {k:v for k,v in part.items() if k != 'kind'}
            found.add('nitro')
        elif part['kind'] == 'probe':
            if 'probe' in found:raise ValueError('Duplicate probe artifact')
            record['probe'] = {k:v for k,v in part.items() if k != 'kind'}
            found.add('probe')
        else:raise ValueError('Unknown release artifact part')
    expected = {SERVICES[s] for s in json.loads(os.environ['EXPECTED_SERVICES'])} | {'probe'}
    if os.environ.get('EXPECTED_NITRO') == 'true':
        expected.add('nitro')
    if found != expected:
        raise ValueError(f'Incomplete release: expected {sorted(expected)}, received {sorted(found)}')
    record['quality'] = json.loads(Path(quality_path).read_text())
    if record['quality'].get('passed') is not True:
        raise ValueError('Source CI has not passed')
    record['id'] = digest(record)
    Path(destination).write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    output(release_id=record['id'])


def publish(path):
    record = json.loads(Path(path).read_text())
    if record['id'] != digest({k:v for k,v in record.items() if k != 'id'}):
        raise ValueError('Release ID mismatch')
    publish_signed(path, f"releases/{record['id']}/release.json", os.environ['ATTESTATION_BUNDLE'])
    # Ready is the final commit marker. Events only wake reconciliation.
    index = Path(os.environ['RUNNER_TEMP'])/'release-ready.json'
    index.write_text(json.dumps({'release_id':record['id'],'source_commit':record['source_commit']}))
    for item in list(record['components'].values()) + [record['probe'],record['nitro']['measurements']]:
        image = item['image']; repo = image.split('/',1)[1].split('@',1)[0]; image_digest=image.split('@',1)[1]
        manifest=command('aws','ecr','batch-get-image','--repository-name',repo,'--image-ids',f'imageDigest={image_digest}','--query','images[0].imageManifest','--output','text')
        tag='retain-'+record['id'][:20]
        result=subprocess.run(['aws','ecr','put-image','--repository-name',repo,'--image-tag',tag,'--image-manifest',manifest],capture_output=True,text=True)
        if result.returncode:
            existing=command('aws','ecr','describe-images','--repository-name',repo,'--image-ids',f'imageTag={tag}','--query','imageDetails[0].imageDigest','--output','text')
            if existing != image_digest:
                raise ValueError('Retained release tag points to another artifact')
    put_immutable(f"releases/ready/{record['source_commit']}/{record['id']}.json", index)
    print('Published complete immutable release '+record['id'])


def prepare_request(profile_text, candidate, destination):
    profile = json.loads(profile_text)
    if digest(profile) != candidate:
        raise ValueError('Candidate profile identity mismatch')
    request = {'version': 1, 'profile': profile, 'candidate_id': candidate,
               'publisher_commit': os.environ['GITHUB_SHA'], 'run_id': os.environ['GITHUB_RUN_ID']}
    Path(destination).write_bytes(canonical(request) + b'\n')


def prepare(profile_text, candidate):
    profile = json.loads(profile_text)
    if digest(profile) != candidate:
        raise ValueError('Candidate profile identity mismatch')
    path = Path(os.environ['RUNNER_TEMP']) / 'prepare-request.json'
    request = json.loads(path.read_text())
    identifier = digest(request)
    publish_signed(path, f'prepare-requests/{identifier}.json', os.environ['ATTESTATION_BUNDLE'])
    index = path.with_name('prepare-ready.json')
    index.write_text(json.dumps({'request_id': identifier, 'candidate_id': candidate}) + '\n')
    put(f'prepare-requests/ready/{identifier}.json', index)
    deadline = time.monotonic() + 2100
    while time.monotonic() < deadline:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'candidate.json'
            result = subprocess.run(['aws', 's3api', 'head-object', '--bucket', BUCKET, '--key', f'candidates/{candidate}/key.json.sigstore.json'], capture_output=True, text=True)
            if result.returncode == 0:
                result = subprocess.run(['aws', 's3api', 'get-object', '--bucket', BUCKET, '--key', f'candidates/{candidate}/key.json', str(path)], capture_output=True, text=True)
            if result.returncode == 0:
                from release_evidence import verify_file
                verify_file(path, f'candidates/{candidate}/key.json', 'helius-labs/zolana-infra',
                            'helius-labs/zolana-infra/.github/workflows/prepare-nitro-release.yml')
                key = json.loads(path.read_text())
                if key.get('candidate_id') != candidate or key.get('profile') != profile:
                    raise ValueError('Candidate key belongs to another build profile')
                output(kms_key=key['kms_key'], seed_context=key['seed_context'], generation=key['generation'], candidate=candidate,
                       backend=profile['backend'], concurrency=str(profile['concurrency']), indexer_url=profile['indexer_url'])
                return
            if 'NoSuchKey' not in result.stderr and '404' not in result.stderr:
                raise ValueError('Cannot read candidate allocation result')
        time.sleep(15)
    raise ValueError('Nitro preparation is pending; retry reuses the same identity and durable request')


def qualification_request(parts, quality_path, destination):
    parts=Path(parts)
    nitro=json.loads((parts/'nitro.json').read_text())
    probe=json.loads((parts/'probe.json').read_text());probe.pop('kind')
    quality=json.loads(Path(quality_path).read_text())
    if quality.get('passed') is not True:
        raise ValueError('Source CI must pass before sealing a candidate')
    request={'version':1,'candidate_id':nitro['measurements']['candidate_id'],
             'profile':nitro['measurements']['profile'],'measurements':nitro['measurements'],
             'probe':probe,'quality':quality,'publisher_commit':os.environ['GITHUB_SHA']}
    Path(destination).write_bytes(canonical(request)+b'\n')
    output(request_id=digest(request),candidate=request['candidate_id'])


def qualify(request_path, part_path):
    request=json.loads(Path(request_path).read_text());identifier=digest(request);candidate=request['candidate_id']
    publish_signed(request_path, 'qualification-requests/'+identifier+'.json', os.environ['ATTESTATION_BUNDLE'])
    index = Path(request_path).with_name('qualification-ready.json')
    index.write_text(json.dumps({'request_id':identifier, 'candidate_id':candidate})+'\n')
    put(f'qualification-requests/ready/{identifier}.json', index)
    deadline=time.monotonic()+3300
    while time.monotonic()<deadline:
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'qualification.json'
            result=subprocess.run(['aws','s3api','head-object','--bucket',BUCKET,'--key',f'candidates/{candidate}/qualification.json.sigstore.json'],capture_output=True,text=True)
            if result.returncode==0:
                result=subprocess.run(['aws','s3api','get-object','--bucket',BUCKET,'--key',f'candidates/{candidate}/qualification.json',str(path)],capture_output=True,text=True)
            if result.returncode==0:
                from release_evidence import verify_file
                verify_file(path, f'candidates/{candidate}/qualification.json', 'helius-labs/zolana-infra',
                            'helius-labs/zolana-infra/.github/workflows/prepare-nitro-release.yml')
                receipt=json.loads(path.read_text())
                if (receipt.get('verified') is not True or receipt.get('candidate_id')!=candidate or
                    receipt.get('profile')!=request['profile'] or receipt.get('measurements_digest')!=digest(request['measurements'])):
                    raise ValueError('Qualification receipt belongs to another measured candidate')
                import re
                if not re.fullmatch(r'[0-9a-f]{64}',receipt.get('hpke_public_key','')):
                    raise ValueError('Candidate is missing its qualified public key')
                part=json.loads(Path(part_path).read_text());part['hpke_public_key']=receipt['hpke_public_key']
                part['qualification']={'receipt_id':digest(receipt),'candidate_id':candidate}
                Path(part_path).write_text(json.dumps(part,sort_keys=True)+'\n')
                return
            if 'NoSuchKey' not in result.stderr and '404' not in result.stderr:
                raise ValueError('Cannot read private qualification receipt')
        time.sleep(15)
    raise ValueError('Candidate qualification is still pending; retry retains the same sealed identity')


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('plan')
    c=sub.add_parser('component'); c.add_argument('service'); c.add_argument('image'); c.add_argument('path')
    q=sub.add_parser('quality'); q.add_argument('path')
    a=sub.add_parser('assemble'); a.add_argument('parts');a.add_argument('base_id');a.add_argument('quality');a.add_argument('destination')
    u=sub.add_parser('publish');u.add_argument('path')
    r=sub.add_parser('prepare-request');r.add_argument('profile');r.add_argument('candidate');r.add_argument('destination')
    r=sub.add_parser('prepare');r.add_argument('profile');r.add_argument('candidate')
    q=sub.add_parser('qualification-request');q.add_argument('parts');q.add_argument('quality');q.add_argument('destination')
    q=sub.add_parser('qualify');q.add_argument('request');q.add_argument('part')
    args=p.parse_args()
    if args.command=='plan':plan()
    elif args.command=='component':component(args.service,args.image,args.path)
    elif args.command=='quality':quality(args.path)
    elif args.command=='assemble':assemble(args.parts,args.base_id,args.quality,args.destination)
    elif args.command=='publish':publish(args.path)
    elif args.command=='qualification-request':qualification_request(args.parts,args.quality,args.destination)
    elif args.command=='qualify':qualify(args.request,args.part)
    elif args.command=='prepare-request':prepare_request(args.profile,args.candidate,args.destination)
    else:prepare(args.profile,args.candidate)


if __name__=='__main__':main()
