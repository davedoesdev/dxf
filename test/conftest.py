import os
import subprocess
import time
import requests
import pytest
import dxf
import dxf.main

# From https://pytest.org/latest/example/simple.html#making-test-result-information-available-in-fixtures
# pylint: disable=no-member,unused-argument
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()
    if rep.failed:
        setattr(item.getparent(pytest.Module), 'rep_failed', True)

_here = os.path.join(os.path.dirname(__file__))
_fixture_dir = os.path.join(_here, 'fixtures')
_registry_dir = os.path.join(_here, 'registry')
_auth_dir = os.path.join(_here, 'auth')
_remove_container = os.path.join(_here, 'remove_container.sh')

DEVNULL = open(os.devnull, 'wb')

def pytest_namespace():
    return {
        'blob1_file': os.path.join(_fixture_dir, 'blob1'),
        'blob2_file': os.path.join(_fixture_dir, 'blob2'),
        'blob3_file': os.path.join(_fixture_dir, 'blob3'),
        'blob4_file': os.path.join(_fixture_dir, 'blob4'),

        'blob1_hash': os.environ['HASH1'],
        'blob2_hash': os.environ['HASH2'],
        'blob3_hash': os.environ['HASH3'],
        'blob4_hash': os.environ['HASH4'],

        'blob1_size': 1 * 1024 * 1024,
        'blob2_size': 2 * 1024 * 1024,
        'blob3_size': 2 * 1024 * 1024,
        'blob4_size': 2 * 1024 * 1024,

        'username': 'fred',
        'password': '!WordPass0$',

        'repo': 'foo/bar'
    }

# pylint: disable=redefined-outer-name
def _auth(dxf_obj, response):
    dxf_obj.authenticate(pytest.username, pytest.password, response=response)

def _setup_fixture(request):
    setattr(request.node, 'rep_failed', False)
    def cleanup():
        if getattr(request.node, 'rep_failed', False):
            subprocess.call(['docker', 'logs', 'dxf_registry'])
            subprocess.call(['docker', 'logs', 'dxf_auth'])
        subprocess.call([_remove_container, 'dxf_registry'])
        subprocess.call([_remove_container, 'dxf_auth'])
    request.addfinalizer(cleanup)
    cleanup()
    cmd = ['docker', 'run', '-d', '-p', '5000:5000', '--name', 'dxf_registry']
    regver, auth, do_token = request.param
    if auth:
        cmd += ['-v', _registry_dir + ':/registry',
                '-v', _auth_dir + ':/auth',
                '-e', 'REGISTRY_HTTP_TLS_CERTIFICATE=/registry/registry.pem',
                '-e', 'REGISTRY_HTTP_TLS_KEY=/registry/registry.key']
        if do_token:
            # Thanks to https://the.binbashtheory.com/creating-private-docker-registry-2-0-with-token-authentication-service/
            cmd += ['-e', 'REGISTRY_AUTH=token',
                    '-e', 'REGISTRY_AUTH_TOKEN_REALM=https://localhost:5001/auth',
                    '-e', 'REGISTRY_AUTH_TOKEN_SERVICE=Docker registry',
                    '-e', 'REGISTRY_AUTH_TOKEN_ISSUER=Auth Service',
                    '-e', 'REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/auth/auth.pem']
            cmd2 = ['docker', 'run', '-d', '-p', '5001:5001',
                    '--name', 'dxf_auth', '-v', _auth_dir + ':/auth',
                    'cesanta/docker_auth', '/auth/config.yml']
            subprocess.check_call(cmd2, stdout=DEVNULL)
        else:
            cmd += ['-e', 'REGISTRY_AUTH=htpasswd',
                    '-e', 'REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm',
                    '-e', 'REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd']
    cmd += ['registry:' + str(regver)]
    subprocess.check_call(cmd, stdout=DEVNULL)
    return auth, do_token

_fixture_params = []
for regver in [2, 2.2]:
    _fixture_params.extend([(regver, None, False),
                            (regver, _auth, False),
                            (regver, _auth, True)])

@pytest.fixture(scope='module', params=_fixture_params)
def dxf_obj(request):
    auth, do_token = _setup_fixture(request)
    r = dxf.DXF('localhost:5000', pytest.repo, auth, not auth)
    r.test_do_token = do_token
    for _ in range(5):
        try:
            assert r.list_repos() == []
            return r
        except requests.exceptions.ConnectionError as ex:
            time.sleep(1)
    raise ex

@pytest.fixture(scope='module', params=_fixture_params)
def dxf_main(request):
    auth, do_token = _setup_fixture(request)
    environ = {
        'DXF_HOST': 'localhost:5000',
        'DXF_INSECURE': '0' if auth else '1',
        'TEST_DO_TOKEN': do_token
    }
    if auth:
        environ['DXF_USERNAME'] = pytest.username
        environ['DXF_PASSWORD'] = pytest.password
    for _ in range(5):
        try:
            assert dxf.main.doit(['list-repos'], environ) == 0
            return environ
        except requests.exceptions.ConnectionError as ex:
            time.sleep(1)
    raise ex
