"""Always rebuild runtime; reuse only an unchanged migration artifact with recorded provenance."""
import json
import os
import subprocess
from pathlib import Path
from publish_release import GitHub, image_input_hashes, load_baseline, reuse_evidence, validate_config


def registry_image_exists(image):
    try:
        result = subprocess.run(['docker', 'manifest', 'inspect', image], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=45, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def plan_images(config, branch, source, baseline=None, root=Path('.'), verify_image=registry_image_exists, resolver=None):
    validate_config(config)
    hashes = image_input_hashes(config, root, resolver=resolver)
    rows = []
    for image in config['images']:
        kind = image['kind']
        evidence = reuse_evidence(config, baseline, kind, hashes[kind], branch) if kind in hashes else None
        if evidence and not verify_image(image['image'] + '@' + evidence['digest']):
            evidence = None
        rows.append({**image, 'build': evidence is None, 'digest': evidence['digest'] if evidence else '',
                     'builtFrom': evidence['builtFrom'] if evidence else source,
                     'inputHash': hashes.get(kind, '')})
    return {'include': rows}


def main():
    config = json.loads(Path('deploy/delivery.json').read_text())
    if os.environ['GITHUB_REPOSITORY'] != config['repository']:
        raise ValueError('Unexpected repository.')
    branch = os.environ['GITHUB_REF'].removeprefix('refs/heads/')
    baseline = None
    if branch in ('dev', 'main') and os.environ.get('GITHUB_EVENT_NAME') != 'pull_request':
        baseline = load_baseline(GitHub(config['repository'], os.environ['GH_TOKEN']), branch)
    matrix = plan_images(config, branch, os.environ['GITHUB_SHA'], baseline)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('images=' + json.dumps(matrix, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
