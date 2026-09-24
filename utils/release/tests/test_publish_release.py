import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'publish-release.sh'


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '--bare', str(self.root / 'remote.git'))
        self.git('init')
        self.git('config', 'user.name', 'Release Test')
        self.git('config', 'user.email', 'release@example.invalid')
        (self.repo / 'Makefile').write_text('VERSION ?= 0.3.0\n')
        self.git('add', 'Makefile')
        self.git('commit', '--signoff', '-m', 'Release fixture')
        self.git('branch', '-M', 'release-0.3')
        self.git('remote', 'add', 'origin', str(self.root / 'remote.git'))
        self.git('push', 'origin', 'release-0.3')
        self.sha = self.git('rev-parse', 'HEAD')
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        gh = bin_dir / 'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FAKE_ROOT'])
args = sys.argv[1:]
with (root / 'calls').open('a') as f: f.write(json.dumps(args) + '\\n')
if args[0] == 'api':
    if os.environ.get('API_ERROR'): sys.exit(1)
    print(json.dumps([[{'tag_name': 'v0.3.0'}]] if os.environ.get('EXISTING_RELEASE') else [[]]))
elif args[:2] == ['release', 'create']:
    (root / 'published').write_text(json.dumps(args))
elif args[:2] != ['release', 'view']:
    sys.exit(2)
''')
        gh.chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}',
                    'FAKE_ROOT': str(self.root), 'GH_TOKEN': 'fake', 'GH_REPO': 'owner/repo',
                    'RELEASE_BRANCH': 'release-0.3', 'RELEASE_SHA': self.sha}

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, text=True, capture_output=True, check=True).stdout.strip()

    def run_script(self):
        return subprocess.run(['bash', str(SCRIPT)], cwd=self.repo, env=self.env, text=True, capture_output=True)

    def test_publishes_exact_tag(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git('rev-parse', 'v0.3.0^{commit}'), self.sha)
        self.assertIn('--verify-tag', json.loads((self.root / 'published').read_text()))
        self.assertEqual(self.git('ls-remote', '--heads', 'origin').split()[0], self.sha)

    def test_reuses_existing_correct_tag(self):
        self.git('tag', '-a', 'v0.3.0', '-m', 'Release')
        self.git('push', 'origin', 'refs/tags/v0.3.0')
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue((self.root / 'published').exists())

    def test_existing_release_is_not_republished(self):
        self.git('tag', 'v0.3.0')
        self.git('push', 'origin', 'refs/tags/v0.3.0')
        self.env['EXISTING_RELEASE'] = '1'
        self.assertEqual(self.run_script().returncode, 0)
        self.assertFalse((self.root / 'published').exists())

    def test_api_error_does_not_create_tag(self):
        self.env['API_ERROR'] = '1'
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.git('tag'), '')

    def test_moved_branch_is_rejected(self):
        self.git('commit', '--allow-empty', '--signoff', '-m', 'Later work')
        self.git('push', 'origin', 'release-0.3')
        self.git('checkout', '--detach', self.sha)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.git('tag'), '')

    def test_wrong_tag_is_preserved_and_rejected(self):
        self.git('commit', '--allow-empty', '--signoff', '-m', 'Other commit')
        self.git('tag', 'v0.3.0')
        wrong_sha = self.git('rev-parse', 'v0.3.0')
        self.git('checkout', '--detach', self.sha)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.git('rev-parse', 'v0.3.0'), wrong_sha)
        self.assertFalse((self.root / 'published').exists())

    def test_version_must_match_release_stream(self):
        (self.repo / 'Makefile').write_text('VERSION ?= 0.4.0\n')
        self.git('commit', '--all', '--signoff', '-m', 'Wrong stream')
        self.git('push', 'origin', 'release-0.3')
        self.env['RELEASE_SHA'] = self.git('rev-parse', 'HEAD')
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.git('tag'), '')
