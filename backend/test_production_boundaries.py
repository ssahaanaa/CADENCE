import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
import sys
sys.path[:0] = [str(ROOT), str(ROOT / 'backend'), str(ROOT / 'cadence_module1'), str(ROOT / 'cadence_module3')]

from fastapi.testclient import TestClient
from backend import db, config
from backend import main
from cadence_module1 import github_discovery as gh
from cadence_module1 import network_discovery as nd


class ExtendedProductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='cadence-ext-'))
        cls.old_db_dir, cls.old_db_path = db.DATA_DIR, db.DB_PATH
        db.DATA_DIR = cls.tmp / 'data'
        db.DB_PATH = db.DATA_DIR / 'cadence.db'
        cls.old_config_dir, cls.old_config_path = config.DATA_DIR, config.SCAN_CONFIG_PATH
        config.DATA_DIR = cls.tmp / 'config'
        config.SCAN_CONFIG_PATH = config.DATA_DIR / 'scan_config.json'
        cls.old_constraints = config.CONSTRAINTS_PATH
        config.CONSTRAINTS_PATH = cls.tmp / 'constraints.json'
        main.APP_PASSWORD = 'unit-test-secret'
        db.init_db()

    @classmethod
    def tearDownClass(cls):
        db.DATA_DIR, db.DB_PATH = cls.old_db_dir, cls.old_db_path
        config.DATA_DIR, config.SCAN_CONFIG_PATH = cls.old_config_dir, cls.old_config_path
        config.CONSTRAINTS_PATH = cls.old_constraints
        main.APP_PASSWORD = ''
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_auth_and_health(self):
        with TestClient(main.app) as client:
            self.assertEqual(client.get('/api/health').status_code, 200)
            self.assertEqual(client.get('/api/config').status_code, 401)
            response = client.get('/api/config', headers={'x-app-password': 'unit-test-secret'})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()['github_token'])

    def test_config_and_zip_upload_boundaries(self):
        with TestClient(main.app) as client:
            headers = {'x-app-password': 'unit-test-secret'}
            response = client.put('/api/config', headers=headers, json={'path': '', 'project_name': 'test'})
            self.assertEqual(response.status_code, 200)
            bad = client.post('/api/source-upload', headers=headers,
                              files={'file': ('source.txt', b'not zip', 'application/zip')})
            self.assertEqual(bad.status_code, 400)
            traversal = io.BytesIO()
            with zipfile.ZipFile(traversal, 'w') as zf:
                zf.writestr('../escape.py', 'print(1)')
            rejected = client.post('/api/source-upload', headers=headers,
                                   files={'file': ('source.zip', traversal.getvalue(), 'application/zip')})
            self.assertEqual(rejected.status_code, 400)
            valid = io.BytesIO()
            with zipfile.ZipFile(valid, 'w') as zf:
                zf.writestr('project/app.py', 'import hashlib\nhashlib.md5(b"x")\n')
            uploaded = client.post('/api/source-upload', headers=headers,
                                   files={'file': ('project.zip', valid.getvalue(), 'application/zip')})
            self.assertEqual(uploaded.status_code, 200, uploaded.text)
            selected = uploaded.json()['path']
            self.assertTrue(Path(selected, 'app.py').is_file())

    def test_database_persistence_and_run_isolation(self):
        db.create_run('persist-1')
        db.set_status('persist-1', 'success')
        db.set_outputs('persist-1', {'vulnerabilities.json': '[]', 'migration_ranking.json': '{}'})
        db.set_progress('persist-1', 'system-a', 'step-a', True)
        self.assertEqual(db.get_progress('persist-1'), {('system-a', 'step-a'): True})
        row = db.get_latest_success()
        self.assertEqual(row['id'], 'persist-1')
        # A fresh connection sees the same committed data.
        import sqlite3
        with sqlite3.connect(db.DB_PATH) as conn:
            self.assertEqual(conn.execute('select status from runs where id=?', ('persist-1',)).fetchone()[0], 'success')

    def test_github_token_headers_and_clone_failures_are_bounded(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return b'[]'
        captured = {}
        def fake_urlopen(request, timeout):
            captured['auth'] = request.get_header('Authorization')
            captured['timeout'] = timeout
            return Response()
        with patch.object(gh.urllib.request, 'urlopen', fake_urlopen):
            self.assertEqual(gh.list_org_repos('acme', token='secret-token'), [])
        self.assertEqual(captured['auth'], 'Bearer secret-token')
        self.assertEqual(captured['timeout'], gh.API_TIMEOUT_SECONDS)
        repo = {'name': 'private', 'clone_url': 'https://github.com/acme/private.git'}
        with patch.object(gh.subprocess, 'run', side_effect=gh.subprocess.CalledProcessError(128, 'git')) as run:
            name, findings, error = gh._clone_and_scan_repo('acme', repo, 'secret-token')
        self.assertEqual((name, findings, error), ('private', [], 'clone failed, skipped'))
        env = run.call_args.kwargs['env']
        self.assertNotIn('secret-token', run.call_args.args[0])
        self.assertIn('GIT_CONFIG_VALUE_0', env)
        self.assertNotIn('secret-token', str(run.call_args.args[0]))

    def test_domain_passive_scope_and_failed_probe_reporting(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return json.dumps([{'name_value': '*.example.com\napi.example.com\nother.evil.test'}]).encode()
        with patch.object(nd.urllib.request, 'urlopen', return_value=Response()):
            self.assertEqual(nd.discover_passive_subdomains('example.com'), ['api.example.com', 'example.com'])
        with patch.object(nd, 'is_live', return_value=False):
            self.assertEqual(nd.discover_live_hosts(['api.example.com'], ports=(443,)), [])

    def test_api_run_requires_target_and_rejects_invalid_limit(self):
        with TestClient(main.app) as client:
            headers = {'x-app-password': 'unit-test-secret'}
            self.assertEqual(client.get('/api/runs?limit=0', headers=headers).status_code, 400)
            # Empty config from this isolated test setup means no run can be queued.
            config.save({'path': '', 'github_org': '', 'domain': '', 'hosts': [], 'project_name': 'x', 'github_token': ''})
            self.assertEqual(client.post('/api/runs', headers=headers).status_code, 400)


if __name__ == '__main__':
    unittest.main(verbosity=2)
