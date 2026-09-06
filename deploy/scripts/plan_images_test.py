import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from plan_images import plan_images
from publish_release import image_input_hashes, make_receipt, resolve_digest

SOURCE = 'a' * 40
ORIGINAL = 'b' * 40
DIGEST = 'sha256:' + 'c' * 64


class Planning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / 'schema.prisma').write_text('model Example {}')
        (self.root / 'runtime.ts').write_text('runtime v1')
        (self.root / 'Dockerfile').write_text('# syntax=docker/dockerfile:1.6\nFROM node:22-alpine AS builder\nFROM builder AS migration-tool\n')
        self.resolver = lambda image: 'sha256:' + 'e' * 64
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        self.config = {'repository': 'owner/auth', 'images': [
            {'kind': 'auth', 'image': 'ghcr.io/owner/auth'},
            {'kind': 'auth-migrate', 'image': 'ghcr.io/owner/auth-migrate'}],
            'reusableImageInputs': {'auth-migrate': ['schema.prisma']}}
        self.baseline = {'schema': 1, 'repository': 'owner/auth', 'branch': 'dev', 'source': 'd' * 40,
                         'images': {'auth-migrate': 'ghcr.io/owner/auth-migrate@' + DIGEST},
                         'imageInputHashes': image_input_hashes(self.config, self.root, resolver=self.resolver),
                         'builtFrom': {'auth-migrate': ORIGINAL}}

    def plan(self, baseline=None):
        return plan_images(self.config, 'dev', SOURCE, baseline, self.root, verify_image=lambda image: True, resolver=self.resolver)['include']

    def test_deleted_or_unreadable_registry_image_rebuilds(self):
        checked = []
        def verify(image):
            checked.append(image)
            return False
        rows = plan_images(self.config, 'dev', SOURCE, self.baseline, self.root, verify_image=verify, resolver=self.resolver)['include']
        self.assertTrue(rows[1]['build'])
        self.assertEqual(checked, ['ghcr.io/owner/auth-migrate@' + DIGEST])

    def test_unchanged_migration_reuses_original_digest_runtime_always_builds(self):
        rows = self.plan(self.baseline)
        self.assertTrue(rows[0]['build'])
        self.assertEqual(rows[0]['builtFrom'], SOURCE)
        self.assertFalse(rows[1]['build'])
        self.assertEqual(rows[1]['digest'], DIGEST)
        self.assertEqual(rows[1]['builtFrom'], ORIGINAL)

    def test_runtime_only_change_does_not_rebuild_migration(self):
        (self.root / 'runtime.ts').write_text('runtime v2')
        rows = self.plan(self.baseline)
        self.assertTrue(rows[0]['build'])
        self.assertFalse(rows[1]['build'])

    def test_input_change_rebuilds_migration(self):
        (self.root / 'schema.prisma').write_text('model Changed {}')
        self.assertTrue(self.plan(self.baseline)[1]['build'])

    def test_mutable_node_base_or_docker_frontend_update_rebuilds(self):
        for changed in ['node:22-alpine', 'docker/dockerfile:1.6']:
            def resolver(image):
                self.assertNotEqual(image, 'builder')
                return 'sha256:' + ('f' if image == changed else 'e') * 64
            rows = plan_images(self.config, 'dev', SOURCE, self.baseline, self.root,
                               verify_image=lambda image: True, resolver=resolver)['include']
            self.assertTrue(rows[1]['build'])

    def test_build_arguments_or_target_change_rebuilds(self):
        for field, value in [('buildArgs', 'NEW_OPTION=true'), ('target', 'other-stage'), ('context', './subdirectory')]:
            with self.subTest(field=field):
                config = copy.deepcopy(self.config)
                config['images'][1][field] = value
                rows = plan_images(config, 'dev', SOURCE, self.baseline, self.root,
                                   verify_image=lambda image: True, resolver=self.resolver)['include']
                self.assertTrue(rows[1]['build'])

    def test_unresolved_base_fails_closed(self):
        with self.assertRaises(ValueError):
            plan_images(self.config, 'dev', SOURCE, self.baseline, self.root,
                        verify_image=lambda image: True, resolver=lambda image: 'latest')

    def test_registry_resolution_is_bounded_and_cached_per_process(self):
        resolve_digest.cache_clear()
        with patch('publish_release.subprocess.check_output', return_value=DIGEST + '\n') as command:
            self.assertEqual(resolve_digest('node:22-alpine'), DIGEST)
            self.assertEqual(resolve_digest('node:22-alpine'), DIGEST)
            command.assert_called_once()
            self.assertEqual(command.call_args.kwargs['timeout'], 45)
        resolve_digest.cache_clear()

    def test_missing_baseline_or_legacy_provenance_rebuilds(self):
        self.assertTrue(all(row['build'] for row in self.plan()))
        for field in ['imageInputHashes', 'builtFrom']:
            baseline = copy.deepcopy(self.baseline)
            del baseline[field]
            self.assertTrue(self.plan(baseline)[1]['build'])

    def test_wrong_identity_or_mutable_digest_rebuilds(self):
        for key, value in [('branch', 'main'), ('repository', 'attacker/auth'),
                           ('images', {'auth-migrate': 'ghcr.io/owner/auth-migrate:latest'})]:
            self.assertTrue(self.plan(self.baseline | {key: value})[1]['build'])

    def test_runtime_cannot_be_configured_for_reuse(self):
        self.config['reusableImageInputs']['auth'] = ['runtime.ts']
        with self.assertRaises(ValueError): self.plan(self.baseline)

    def artifacts(self):
        directory = self.root / 'digests'
        directory.mkdir()
        for row in self.plan(self.baseline):
            (directory / (row['kind'] + '.json')).write_text(json.dumps({
                'kind': row['kind'], 'source': SOURCE, 'digest': row['digest'] or DIGEST,
                'builtFrom': row['builtFrom'], 'inputHash': row['inputHash']}))
        return directory

    def test_receipt_keeps_complete_images_and_honest_original_build_source(self):
        receipt = make_receipt(self.config, self.artifacts(), 'dev', SOURCE, '1',
                               baseline=self.baseline, root=self.root, resolver=self.resolver)
        self.assertEqual(set(receipt['images']), {'auth', 'auth-migrate'})
        self.assertEqual(receipt['source'], SOURCE)
        self.assertEqual(receipt['builtFrom'], {'auth': SOURCE, 'auth-migrate': ORIGINAL})
        self.assertEqual(receipt['imageInputHashes'], self.baseline['imageInputHashes'])

    def test_publisher_rejects_reuse_without_baseline(self):
        with self.assertRaises(ValueError):
            make_receipt(self.config, self.artifacts(), 'dev', SOURCE, '1', root=self.root, resolver=self.resolver)

    def test_publisher_rechecks_hash_after_plan(self):
        artifacts = self.artifacts()
        (self.root / 'schema.prisma').write_text('changed after plan')
        with self.assertRaises(ValueError):
            make_receipt(self.config, artifacts, 'dev', SOURCE, '1', baseline=self.baseline, root=self.root, resolver=self.resolver)


if __name__ == '__main__':
    unittest.main()
