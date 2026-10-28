"""Propose overlapping SDK pins without claiming that source changes are delivered."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile

import re
import os
import time
from release_evidence import BUCKET, load_signed


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def validate_policy(policy):
    require(set(policy)<= {'platform','measurements','hpke_public_key','gpu','max_age_secs'},'Unknown client policy fields')
    require(policy.get('gpu')=='optional' and type(policy.get('max_age_secs')) is int and 0<policy['max_age_secs']<=2**53-1,'Invalid Nitro policy settings')
    require(policy.get('platform')=='aws-nitro' and policy.get('measurements'),'Missing Nitro client policy')
    for measurement in policy['measurements']:
        require(set(measurement)<= {'pcr0','pcr1','pcr2','hpke_public_key'},'Unknown measurement policy fields')
        for pcr in ('pcr0','pcr1','pcr2'):
            value=measurement.get(pcr,'')
            require(re.fullmatch(r'[0-9a-f]{96}',value) and value!='0'*96,'Invalid or debug client measurement')
        if measurement.get('hpke_public_key'):
            require(re.fullmatch(r'[0-9a-f]{64}',measurement['hpke_public_key']),'Invalid per-image HPKE key pin')
    if policy.get('hpke_public_key'):
        require(re.fullmatch(r'[0-9a-f]{64}',policy['hpke_public_key']),'Invalid client HPKE key pin')


REPO='helius-labs/zolana'
BRANCH='release/devnet-d-client-policy'
POLICY='sdk-libs/prover-tee/src/policy.json'
DEFAULT='sdk-libs/ts/src/client/prover/tee/default.ts'


def overlap(policy,record):
    validate_policy(policy)
    result=copy.deepcopy(policy)
    # Preserve every accepted image/key pair when replacing a global pin.
    global_key=result.pop('hpke_public_key',None)
    for pin in result['measurements']:
        if global_key:
            require(not pin.get('hpke_public_key') or pin['hpke_public_key']==global_key,'Conflicting existing client key pins')
            pin['hpke_public_key']=global_key
    measurement=record['nitro']['measurements']
    key=record['nitro'].get('hpke_public_key')
    require(key,'Qualify the candidate identity before proposing client pins')
    pin={p.lower():measurement[p] for p in ('PCR0','PCR1','PCR2')}
    pin['hpke_public_key']=key
    if pin not in result['measurements']:
        result['measurements'].append(pin)
    return result


def propose(record):
    main=json.loads(command('gh','api',f'repos/{REPO}/git/ref/heads/main'))['object']['sha']
    original=json.loads(command('gh','api',f'repos/{REPO}/contents/{POLICY}?ref={main}'))
    document=json.loads(base64.b64decode(original['content']))
    updated=overlap(document['deployment'],record)
    if updated==document['deployment']:
        return 'Source policy already accepts this candidate; waiting for actual client delivery.'
    document['deployment']=updated
    existing=json.loads(command('gh','pr','list','--repo',REPO,'--head',BRANCH,'--state','open','--json','number,url'))
    if existing:
        pending=json.loads(command('gh','api',f'repos/{REPO}/contents/{POLICY}?ref={BRANCH}'))
        comparison=json.loads(command('gh','api',f'repos/{REPO}/compare/{main}...{BRANCH}'))
        if json.loads(base64.b64decode(pending['content']))==document and comparison['status'] in ('ahead','identical'):
            return existing[0]['url']
    changelog='sdk-libs/ts/CHANGELOG.md'
    changelog_file=json.loads(command('gh','api',f'repos/{REPO}/contents/{changelog}?ref={main}'))
    notes=base64.b64decode(changelog_file['content']).decode()
    entry='- `defaultTeePolicy()` accepts the qualified devnet Nitro identity alongside the previous image and key during deployment rotation.\n'
    if entry not in notes:
        first=notes.find('\n## ',notes.find('\n## ')+1)
        split=len(notes) if first<0 else first
        current=notes[:split]
        if '\nChanged\n' in current:
            current=current.replace('\nChanged\n','\nChanged\n\n'+entry,1)
        elif '\nFixed\n' in current:
            current=current.replace('\nFixed\n','\nChanged\n\n'+entry+'\nFixed\n',1)
        else:
            current=current.rstrip()+'\n\nChanged\n\n'+entry+'\n'
        notes=current+notes[split:]
    with tempfile.TemporaryDirectory() as directory:
        default=Path(directory)/'default.ts'
        default.write_text('/** Mirrors `sdk-libs/prover-tee/src/policy.json`, kept equal by a test. */\nexport const DEFAULT_TEE_POLICY_FILE: Readonly<{ deployment: unknown }> = Object.freeze('+json.dumps(document,indent=2)+');\n')
        subprocess.run(['npx','--yes','oxfmt@0.67.0','--write',str(default)],check=True)
        changes=[{'path':POLICY,'contents':base64.b64encode((json.dumps(document,indent=2)+'\n').encode()).decode()},
                 {'path':DEFAULT,'contents':base64.b64encode(default.read_bytes()).decode()},
                 {'path':changelog,'contents':base64.b64encode(notes.encode()).decode()}]
    # Build a signed commit off main without temporarily resetting an open PR.
    import secrets
    staging=BRANCH+'-build-'+secrets.token_hex(8)
    ref=subprocess.run(['gh','api',f'repos/{REPO}/git/ref/heads/{BRANCH}'],capture_output=True,text=True)
    if ref.returncode:
        require('404' in ref.stderr,'Cannot inspect SDK policy branch')
    previous=json.loads(ref.stdout)['object']['sha'] if ref.returncode==0 else None
    command('gh','api',f'repos/{REPO}/git/refs','-f','ref=refs/heads/'+staging,'-f','sha='+main)
    try:
        mutation={'query':'mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}',
                  'variables':{'input':{'branch':{'repositoryNameWithOwner':REPO,'branchName':staging},'expectedHeadOid':main,
                  'message':{'headline':'Accept qualified devnet-d Nitro identity with rotation overlap'},'fileChanges':{'additions':changes}}}}
        result=subprocess.run(['gh','api','graphql','--input','-'],input=json.dumps(mutation),capture_output=True,text=True,check=True)
        committed=json.loads(result.stdout)
        require(not committed.get('errors'),'Cannot create signed client policy proposal')
        commit=committed['data']['createCommitOnBranch']['commit']['oid']
        if previous:
            actual=json.loads(command('gh','api',f'repos/{REPO}/git/ref/heads/{BRANCH}'))['object']['sha']
            require(actual==previous,'SDK policy branch changed during generation; retry safely')
            command('gh','api','--method','PATCH',f'repos/{REPO}/git/refs/heads/{BRANCH}','-f','sha='+commit,'-F','force=true')
        else:
            command('gh','api',f'repos/{REPO}/git/refs','-f','ref=refs/heads/'+BRANCH,'-f','sha='+commit)
    finally:
        command('gh','api','--method','DELETE',f'repos/{REPO}/git/refs/heads/{staging}')
    body='Accepts the qualified candidate alongside every currently supported Nitro image/key pair. Existing key pins remain enforced.\n\nMerge, then publish/deploy the consumer that uses this policy. Its successful deployment must publish a client-policy receipt; the infrastructure deployment stays draft until that delivery is verified. Merging this source PR alone does not trigger cutover.\n\nCandidate: `'+record['nitro']['generation']+'`.'
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'body.md';path.write_text(body)
        if existing:
            command('gh','pr','edit',str(existing[0]['number']),'--repo',REPO,'--body-file',str(path))
            return existing[0]['url']
        return command('gh','pr','create','--repo',REPO,'--base','main','--head',BRANCH,'--title','Accept qualified devnet-d Nitro identity','--body-file',str(path))


def qualified(request_id):
    require(re.fullmatch(r'[0-9a-f]{64}', request_id), 'Invalid qualification request ID')
    request = load_signed(f'qualification-requests/{request_id}.json', REPO,
                          REPO+'/.github/workflows/publish-image.yml')
    from release_evidence import load_signed as evidence
    import hashlib
    def digest(value): return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    require(digest(request) == request_id, 'Qualification request changed')
    candidate = request['candidate_id']
    require(candidate == digest(request['profile']), 'Candidate profile changed')
    receipt = evidence(f'candidates/{candidate}/qualification.json', 'helius-labs/zolana-infra',
                       'helius-labs/zolana-infra/.github/workflows/prepare-nitro-release.yml')
    require(receipt.get('verified') is True and receipt.get('candidate_id') == candidate and
            receipt.get('profile') == request['profile'] and receipt.get('measurements_digest') == digest(request['measurements']),
            'Qualification does not describe the measured candidate')
    key = receipt.get('hpke_public_key', '')
    require(re.fullmatch(r'[0-9a-f]{64}', key), 'Missing qualified HPKE key')
    return {'nitro': {'generation': 'tee-'+candidate[:20], 'measurements': request['measurements'], 'hpke_public_key': key}}


def discover():
    pages=json.loads(command('aws','s3api','list-objects-v2','--bucket',BUCKET,'--prefix','qualification-requests/ready/','--output','json'))
    for item in sorted(pages.get('Contents',[]),key=lambda value:value['LastModified'],reverse=True):
        request_id=item['Key'].rsplit('/',1)[1].removesuffix('.json')
        with tempfile.TemporaryDirectory() as directory:
            index=Path(directory)/'index.json'
            subprocess.run(['aws','s3','cp',f"s3://{BUCKET}/{item['Key']}",str(index)],check=True)
            candidate=json.loads(index.read_text())['candidate_id']
        require(re.fullmatch(r'[0-9a-f]{64}',candidate),'Invalid candidate')
        ready=subprocess.run(['aws','s3api','head-object','--bucket',BUCKET,'--key',f'candidates/{candidate}/qualification.json'],capture_output=True,text=True)
        if ready.returncode:
            require('404' in ready.stderr or 'Not Found' in ready.stderr,'Cannot inspect qualified candidate')
            continue
        return request_id,qualified(request_id)
    return None,None


def dispatch_validation(url, request_id):
    # No source policy change means actual delivery is still required, not another PR.
    if not url.startswith('https://github.com/'):
        print(url)
        return
    number=url.rstrip('/').rsplit('/',1)[1]
    pr=json.loads(command('gh','api',f'repos/{REPO}/pulls/{number}'))
    if not pr.get('merge_commit_sha'):
        return
    states=json.loads(command('gh','api',f"repos/{REPO}/commits/{pr['merge_commit_sha']}/status"))['statuses']
    latest=next((state for state in states if state['context']=='async prover / transfer queue'),None)
    if latest and latest['state']=='success':
        return
    if latest and latest['state']=='pending':
        from datetime import datetime,timezone
        if (datetime.now(timezone.utc)-datetime.fromisoformat(latest['updated_at'].replace('Z','+00:00'))).total_seconds()<3600:
            return
    subprocess.run(['gh','api','--method','POST',f'repos/{REPO}/dispatches','--input','-'],
                   input=json.dumps({'event_type':'validate-client-policy-pr','client_payload':{
                       'pr':number,'expected_head':pr['head']['sha'],'request_id':request_id}}),text=True,check=True)


if __name__ == '__main__':
    request_id,record=discover()
    if record:
        dispatch_validation(propose(record),request_id)
