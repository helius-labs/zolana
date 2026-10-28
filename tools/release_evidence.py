"""Exchange immutable artifacts and their Sigstore bundles through the existing bucket."""
import json
from pathlib import Path
import subprocess
import tempfile

BUCKET = 'zolana-nitro-eif-558215002830'
REPOSITORY_IDS = {'helius-labs/zolana': '1235775078', 'helius-labs/zolana-infra': '1329866583'}


def download(key, path):
    subprocess.run(['aws', 's3api', 'get-object', '--bucket', BUCKET, '--key', key, str(path)], check=True, stdout=subprocess.DEVNULL)


def put(key, path, immutable=True):
    args = ['aws', 's3api', 'put-object', '--bucket', BUCKET, '--key', key, '--body', str(path), '--content-type', 'application/json']
    if immutable:
        args += ['--if-none-match', '*']
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        if not immutable or 'PreconditionFailed' not in result.stderr:
            raise ValueError('Cannot publish release evidence: ' + result.stderr)
        # Different valid signatures of the same subject are expected on retries.
        if not key.endswith('.sigstore.json'):
            with tempfile.TemporaryDirectory() as directory:
                old = Path(directory) / 'existing.json'
                download(key, old)
                if old.read_bytes() != Path(path).read_bytes():
                    raise ValueError('Immutable release evidence already has different contents')


def publish_signed(path, key, bundle):
    put(key + '.sigstore.json', bundle)
    put(key, path)


def verify_file(path, key, repo, workflow, source_digest=None, source_ref='refs/heads/main', repository_id=None):
    with tempfile.TemporaryDirectory() as directory:
        bundle = Path(directory) / 'bundle.json'
        download(key + '.sigstore.json', bundle)
        args = ['gh', 'attestation', 'verify', str(path), '--bundle', str(bundle), '--repo', repo,
                '--signer-workflow', workflow, '--deny-self-hosted-runners', '--format', 'json']
        if source_digest:
            args += ['--source-digest', source_digest]
        if source_ref:
            args += ['--source-ref', source_ref]
        results = json.loads(subprocess.check_output(args, text=True))
        expected = str(repository_id or REPOSITORY_IDS.get(repo, ''))
        if not expected or not any(str(r['verificationResult']['signature']['certificate'].get('sourceRepositoryIdentifier')) == expected for r in results):
            raise ValueError('Signed evidence belongs to another repository ID')
        return results


def load_signed(key, repo, workflow, **kwargs):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'subject.json'
        download(key, path)
        verify_file(path, key, repo, workflow, **kwargs)
        return json.loads(path.read_text())
