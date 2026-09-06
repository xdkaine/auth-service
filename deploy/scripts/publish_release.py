"""Publish complete digest receipts; deployment is performed by the server's allowlist."""
import argparse
import base64
import json
import hashlib
import subprocess
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]*")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def validate_config(config):
    if not REPOSITORY.fullmatch(config.get('repository', '')):
        raise ValueError('Invalid repository.')
    images = config.get('images')
    if not isinstance(images, list) or not images:
        raise ValueError('A nonempty image matrix is required.')
    kinds = set()
    repos = set()
    for item in images:
        kind, repository = item.get('kind', ''), item.get('image', '')
        if not NAME.fullmatch(kind) or kind in kinds:
            raise ValueError('Invalid or duplicate image kind.')
        if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9/_.-]+', repository) or repository in repos:
            raise ValueError('Invalid or duplicate image repository.')
        if repository.split('/')[1] != config['repository'].split('/')[0].lower():
            raise ValueError('Images must belong to the configured repository owner.')
        kinds.add(kind)
        repos.add(repository)
    return {item['kind']: item['image'] for item in images}


def schema_hashes(config, root=Path('.')):
    """Hash tracked schema files: 8-byte path length, path, 8-byte content length, content."""
    result = {}
    for component, inputs in sorted(config.get('schemaInputs', {}).items()):
        if not NAME.fullmatch(component) or not isinstance(inputs, list) or not inputs:
            raise ValueError('Invalid schema input definition.')
        paths = set()
        for prefix in inputs:
            if not isinstance(prefix, str) or prefix.startswith(('/', '-')) or '..' in Path(prefix).parts:
                raise ValueError('Unsafe schema input path.')
            output = subprocess.check_output(['git', 'ls-files', '-z', '--', prefix], cwd=root)
            found = [item for item in output.split(b'\0') if item]
            if not found:
                raise ValueError('Schema input does not match tracked files.')
            paths.update(found)
        digest = hashlib.sha256()
        for path in sorted(paths):
            full = root / os.fsdecode(path)
            if full.is_symlink() or not full.is_file():
                raise ValueError('Schema inputs must be regular tracked files.')
            content = full.read_bytes()
            digest.update(len(path).to_bytes(8, 'big'))
            digest.update(path)
            digest.update(len(content).to_bytes(8, 'big'))
            digest.update(content)
        result[component] = 'sha256:' + digest.hexdigest()
    return result


def make_receipt(config, directory, branch, source, run_id):
    allowed = validate_config(config)
    if branch not in ('dev', 'main') or not SHA.fullmatch(source):
        raise ValueError('Expected main/dev and a full source SHA.')
    if not str(run_id).isdigit() or int(run_id) <= 0:
        raise ValueError('Invalid workflow run ID.')
    result = {}
    for path in sorted(Path(directory).glob('*.json')):
        item = json.loads(path.read_text())
        kind = item.get('kind')
        if kind not in allowed or kind in result:
            raise ValueError('Unknown or duplicate image kind.')
        if item.get('source') != source:
            raise ValueError('Mixed-source image receipt.')
        digest = item.get('digest', '')
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError('Expected an immutable SHA-256 digest.')
        result[kind] = allowed[kind] + '@' + digest
    if set(result) != set(allowed):
        raise ValueError('The complete configured image set is required.')
    return {'schema': 1, 'repository': config['repository'], 'branch': branch,
            'source': source, 'images': result, 'runId': str(run_id)}


class GitHub:
    def __init__(self, repository, token):
        self.repository, self.token = repository, token

    def __call__(self, path, data=None, method=None, missing_ok=False):
        req = urllib.request.Request('https://api.github.com/repos/' + self.repository + '/' + path,
            data=None if data is None else json.dumps(data).encode(), method=method,
            headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + self.token,
                     'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise RuntimeError(f'GitHub request failed with HTTP {error.code}.') from None


def publish(api, receipt):
    branch, source = receipt['branch'], receipt['source']
    source_ref = 'git/ref/heads/' + branch
    if api(source_ref)['object']['sha'] != source:
        return False
    release_ref = 'deploy/' + branch
    previous = api('git/ref/heads/' + release_ref, missing_ok=True)
    # Existing deployment history is append-only. Concurrent writers fail the non-force update.
    parent = previous['object']['sha'] if previous else source
    payload = json.dumps(receipt, indent=2, sort_keys=True) + '\n'
    blob = api('git/blobs', {'content': base64.b64encode(payload.encode()).decode(), 'encoding': 'base64'})
    tree = api('git/trees', {'tree': [{'path': 'release.json', 'mode': '100644', 'type': 'blob', 'sha': blob['sha']}]})
    commit = api('git/commits', {'message': f"deploy({branch}): release {source[:12]}",
                                'tree': tree['sha'], 'parents': [parent]})
    if api(source_ref)['object']['sha'] != source:
        return False
    if previous:
        api('git/refs/heads/' + release_ref, {'sha': commit['sha'], 'force': False}, method='PATCH')
    else:
        api('git/refs', {'ref': 'refs/heads/' + release_ref, 'sha': commit['sha']})
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='deploy/delivery.json')
    parser.add_argument('--digests', default='digests')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    ref = os.environ.get('GITHUB_REF', '')
    if ref not in ('refs/heads/dev', 'refs/heads/main') or os.environ.get('GITHUB_EVENT_NAME') == 'pull_request':
        raise ValueError('Publishing requires a main/dev branch workflow.')
    if os.environ.get('GITHUB_REPOSITORY') != config['repository']:
        raise ValueError('Unexpected source repository.')
    receipt = make_receipt(config, args.digests, ref.removeprefix('refs/heads/'),
                           os.environ['GITHUB_SHA'], os.environ['GITHUB_RUN_ID'])
    receipt['schemaHashes'] = schema_hashes(config)
    if publish(GitHub(config['repository'], os.environ['GH_TOKEN']), receipt):
        print('Published complete immutable deployment receipt.')
    else:
        print('A newer source commit exists; stale release skipped.')


if __name__ == '__main__':
    main()
