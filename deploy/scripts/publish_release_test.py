import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from publish_release import make_receipt, publish, schema_hashes

SOURCE = 'a' * 40
CONFIG = {'repository': 'owner/repo', 'images': [
    {'kind': 'api', 'image': 'ghcr.io/owner/api'}, {'kind': 'web', 'image': 'ghcr.io/owner/web'}]}


class Receipts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for kind in ('api', 'web'):
            self.write(kind)

    def write(self, kind, **overrides):
        item = dict(kind=kind, source=SOURCE, digest='sha256:' + 'b' * 64)
        item.update(overrides)
        (self.root / (kind + '.json')).write_text(json.dumps(item))

    def receipt(self):
        return make_receipt(CONFIG, self.root, 'dev', SOURCE, '123')

    def test_complete(self):
        self.assertEqual(self.receipt()['images']['web'], 'ghcr.io/owner/web@sha256:' + 'b' * 64)

    def test_unknown(self):
        self.write('unexpected')
        with self.assertRaises(ValueError): self.receipt()

    def test_missing(self):
        (self.root / 'web.json').unlink()
        with self.assertRaises(ValueError): self.receipt()

    def test_mixed_source(self):
        self.write('api', source='c' * 40)
        with self.assertRaises(ValueError): self.receipt()

    def test_mutable_digest(self):
        self.write('api', digest='latest')
        with self.assertRaises(ValueError): self.receipt()

    def test_duplicate(self):
        (self.root / 'duplicate.json').write_text((self.root / 'web.json').read_text())
        with self.assertRaises(ValueError): self.receipt()

    def test_schema_changes_detected(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        path = self.root / 'schema.sql'
        path.write_text('create table example (id int);')
        subprocess.run(['git', '-C', str(self.root), 'add', 'schema.sql'], check=True)
        config = {'schemaInputs': {'api': ['schema.sql']}}
        before = schema_hashes(config, self.root)
        self.assertEqual(before, schema_hashes(config, self.root))
        path.write_text('create table example (id int, value text);')
        self.assertNotEqual(before, schema_hashes(config, self.root))

    def test_schema_missing_fails_closed(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        with self.assertRaises(ValueError):
            schema_hashes({'schemaInputs': {'api': ['missing.sql']}}, self.root)

    def test_stale_before_write(self):
        calls = []
        def api(path, **kwargs):
            calls.append(path)
            return {'object': {'sha': 'c' * 40}}
        self.assertFalse(publish(api, self.receipt()))
        self.assertEqual(calls, ['git/ref/heads/dev'])

    def test_stale_before_ref_update(self):
        calls, reads = [], []
        def api(path, data=None, **kwargs):
            calls.append(path)
            if path == 'git/ref/heads/dev':
                reads.append(1)
                return {'object': {'sha': SOURCE if len(reads) == 1 else 'c' * 40}}
            if path == 'git/ref/heads/deploy/dev': return {'object': {'sha': 'd' * 40}}
            return {'sha': 'e' * 40}
        self.assertFalse(publish(api, self.receipt()))
        self.assertNotIn('git/refs/heads/deploy/dev', calls)


if __name__ == '__main__': unittest.main()
