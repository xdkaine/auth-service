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
from functools import lru_cache

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


@lru_cache(maxsize=32)
def resolve_digest(image):
    output = subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', image,
                                     '--format', '{{.Manifest.Digest}}'], text=True,
                                     stderr=subprocess.DEVNULL, timeout=45).strip()
    if not DIGEST.fullmatch(output):
        raise ValueError('Registry did not return an immutable base digest.')
    return output


def external_docker_images(body):
    images, stages = set(), set()
    for image, stage in re.findall(r'^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?', body, re.M | re.I):
        if image.lower() not in stages and image.lower() != 'scratch':
            images.add(image)
        if stage:
            stages.add(stage.lower())
    syntax = re.search(r'^#\s*syntax\s*=\s*(\S+)', body, re.M)
    if syntax:
        images.add(syntax.group(1))
    return sorted(images)


def image_input_hashes(config, root=Path('.'), resolver=None):
    inputs = config.get('reusableImageInputs', {})
    if not isinstance(inputs, dict) or set(inputs) - {'auth-migrate'}:
        raise ValueError('Only the migration artifact may reuse a prior image.')
    allowed = validate_config(config)
    if set(inputs) - set(allowed):
        raise ValueError('Reusable image must be configured.')
    result = schema_hashes({'schemaInputs': inputs}, root)
    resolver = resolver or resolve_digest
    for kind, file_hash in result.items():
        image = next(item for item in config['images'] if item['kind'] == kind)
        dockerfile = image.get('dockerfile', 'Dockerfile')
        if not isinstance(dockerfile, str) or Path(dockerfile).is_absolute() or '..' in Path(dockerfile).parts:
            raise ValueError('Unsafe reusable Dockerfile path.')
        path = root / dockerfile
        if path.is_symlink() or not path.is_file():
            raise ValueError('Reusable Dockerfile must be a regular file.')
        bases = {}
        for reference in external_docker_images(path.read_text()):
            resolved = resolver(reference)
            if not isinstance(resolved, str) or not DIGEST.fullmatch(resolved):
                raise ValueError('Invalid resolved Docker input digest.')
            bases[reference] = resolved
        framed = json.dumps({'files': file_hash, 'image': image, 'bases': bases}, sort_keys=True, separators=(',', ':')).encode()
        result[kind] = 'sha256:' + hashlib.sha256(framed).hexdigest()
    return result


def reuse_evidence(config, baseline, kind, input_hash, branch):
    if kind != 'auth-migrate' or not isinstance(baseline, dict):
        return None
    if kind not in config.get('reusableImageInputs', {}) or not isinstance(input_hash, str) or not DIGEST.fullmatch(input_hash):
        return None
    if baseline.get('schema') != 1 or baseline.get('repository') != config['repository'] or baseline.get('branch') != branch:
        return None
    if not isinstance(baseline.get('source'), str) or not SHA.fullmatch(baseline['source']):
        return None
    if any(not isinstance(baseline.get(field), dict) for field in ('imageInputHashes', 'images', 'builtFrom')):
        return None
    if baseline.get('imageInputHashes', {}).get(kind) != input_hash:
        return None
    image = baseline.get('images', {}).get(kind, '')
    prefix = validate_config(config)[kind] + '@'
    built_from = baseline.get('builtFrom', {}).get(kind, '')
    if not isinstance(image, str) or not image.startswith(prefix) or not DIGEST.fullmatch(image[len(prefix):]):
        return None
    if not isinstance(built_from, str) or not SHA.fullmatch(built_from):
        return None
    return {'digest': image[len(prefix):], 'builtFrom': built_from}


def load_baseline(api, branch):
    from urllib.parse import quote
    result = api('contents/release.json?ref=' + quote('deploy/' + branch, safe=''), missing_ok=True)
    if not result:
        return None
    try:
        return json.loads(base64.b64decode(result['content'], validate=False))
    except (ValueError, KeyError, TypeError):
        return None


def make_receipt(config, directory, branch, source, run_id, *, baseline=None, root=Path('.'), resolver=None):
    allowed = validate_config(config)
    if branch not in ('dev', 'main') or not SHA.fullmatch(source):
        raise ValueError('Expected main/dev and a full source SHA.')
    if not str(run_id).isdigit() or int(run_id) <= 0:
        raise ValueError('Invalid workflow run ID.')
    result = {}
    inputs = image_input_hashes(config, root, resolver=resolver)
    provenance = {}
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
        built_from = item.get('builtFrom', source)
        if not isinstance(built_from, str) or not SHA.fullmatch(built_from):
            raise ValueError('Invalid original image build revision.')
        if kind in inputs and item.get('inputHash') != inputs[kind]:
            raise ValueError('Migration build inputs changed after planning.')
        if built_from != source:
            evidence = reuse_evidence(config, baseline, kind, inputs.get(kind), branch)
            if not evidence or evidence != {'digest': digest, 'builtFrom': built_from}:
                raise ValueError('Reused image lacks matching prior receipt provenance.')
        provenance[kind] = built_from
        result[kind] = allowed[kind] + '@' + digest
    if set(result) != set(allowed):
        raise ValueError('The complete configured image set is required.')
    return {'schema': 1, 'repository': config['repository'], 'branch': branch,
            'source': source, 'images': result, 'runId': str(run_id),
            'builtFrom': provenance, 'imageInputHashes': inputs}


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
    api = GitHub(config['repository'], os.environ['GH_TOKEN'])
    branch = ref.removeprefix('refs/heads/')
    receipt = make_receipt(config, args.digests, branch,
                           os.environ['GITHUB_SHA'], os.environ['GITHUB_RUN_ID'],
                           baseline=load_baseline(api, branch))
    receipt['schemaHashes'] = schema_hashes(config)
    if publish(api, receipt):
        print('Published complete immutable deployment receipt.')
    else:
        print('A newer source commit exists; stale release skipped.')


if __name__ == '__main__':
    main()
