import os
import subprocess
import time
import hashlib
import requests
import pytest
import jws.exceptions
import dxf

_here = os.path.join(os.path.dirname(__file__))
_fixture_dir = os.path.join(_here, 'fixtures')
_registry_dir = os.path.join(_here, 'registry')
_auth_dir = os.path.join(_here, 'auth')
_remove_container = os.path.join(_here, 'remove_container.sh')

_blob1_file = os.path.join(_fixture_dir, 'blob1')
_blob2_file = os.path.join(_fixture_dir, 'blob2')

_blob1_hash = os.environ['HASH1']
_blob2_hash = os.environ['HASH2']

_username = 'fred'
_password = '!WordPass0$'

DEVNULL = open(os.devnull, 'wb')

# pylint: disable=redefined-outer-name
def _auth(dxf_obj, response):
    dxf_obj.auth_by_password(_username, _password, response=response)

@pytest.fixture(scope='module', params=[(None, False), (_auth, False), (_auth, True)])
def dxf_obj(request):
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
    auth, do_token = request.param
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
    cmd += ['registry:2']
    subprocess.check_call(cmd, stdout=DEVNULL)
    r = dxf.DXF('localhost:5000', 'foo/bar', auth, not auth)
    r.test_do_token = do_token
    for _ in range(5):
        try:
            assert r.list_repos() == []
            return r
        except requests.exceptions.ConnectionError as ex:
            time.sleep(1)
    raise ex

def test_push_blob(dxf_obj):
    assert dxf_obj.push_blob(_blob1_file) == _blob1_hash
    assert dxf_obj.push_blob(_blob2_file) == _blob2_hash
    assert dxf_obj.list_repos() == ['foo/bar']

def _pull_blob(dxf_obj, dgst):
    sha256 = hashlib.sha256()
    for chunk in dxf_obj.pull_blob(dgst):
        sha256.update(chunk)
    assert sha256.hexdigest() == dgst

def test_pull_blob(dxf_obj):
    _pull_blob(dxf_obj, _blob1_hash)
    _pull_blob(dxf_obj, _blob2_hash)
    with pytest.raises(dxf.exceptions.DXFDigestMismatchError) as ex:
        class DummySHA256(object):
            def update(self, chunk):
                pass

            def hexdigest(self):
                return orig_sha256().hexdigest()
        orig_sha256 = hashlib.sha256
        hashlib.sha256 = DummySHA256
        try:
            for chunk in dxf_obj.pull_blob(_blob1_hash):
                pass
        finally:
            hashlib.sha256 = orig_sha256
    assert ex.value.got == hashlib.sha256().hexdigest()
    assert ex.value.expected == _blob1_hash

def _del_blob(dxf_obj, dgst):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.del_blob(dgst)
    # pylint: disable=no-member
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_del_blob(dxf_obj):
    _del_blob(dxf_obj, _blob1_hash)
    _del_blob(dxf_obj, _blob2_hash)

def test_set_alias(dxf_obj):
    dxf_obj.set_alias('hello', _blob1_hash)
    dxf_obj.set_alias('there', _blob1_hash, _blob2_hash)
    dxf_obj.set_alias('world', _blob2_hash)

def test_get_alias(dxf_obj):
    assert dxf_obj.get_alias('hello') == [_blob1_hash]
    assert dxf_obj.get_alias('there') == [_blob1_hash, _blob2_hash]
    assert dxf_obj.get_alias('world') == [_blob2_hash]

def test_list_aliases(dxf_obj):
    assert sorted(dxf_obj.list_aliases()) == ['hello', 'there', 'world']

def _del_alias(dxf_obj, alias):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.del_alias(alias)
    # pylint: disable=no-member
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_del_alias(dxf_obj):
    _del_alias(dxf_obj, 'hello')
    _del_alias(dxf_obj, 'there')
    _del_alias(dxf_obj, 'world')

def test_manifest(dxf_obj):
    manifest = dxf_obj.set_alias('mani_test', _blob1_hash)
    assert manifest
    assert dxf_obj.get_alias(manifest=manifest) == [_blob1_hash]
    with pytest.raises(jws.exceptions.SignatureError):
        dxf_obj.get_alias(manifest=' '+manifest)

def test_unsigned_manifest(dxf_obj):
    manifest = dxf_obj.set_alias('mani_test2', _blob2_hash, return_unsigned_manifest=True)
    assert manifest
    with pytest.raises(KeyError):
        dxf_obj.get_alias(manifest=manifest)
    assert dxf_obj.get_alias(manifest=manifest, verify=False) == [_blob2_hash]
    assert dxf_obj.get_alias(manifest=manifest, verify=False, return_unsigned_manifest=True) == manifest

def test_auth(dxf_obj):
    # pylint: disable=protected-access
    if dxf_obj._insecure:
        with pytest.raises(dxf.exceptions.DXFAuthInsecureError):
            dxf_obj.auth_by_password(_username, _password)
    elif dxf_obj.test_do_token:
        assert dxf_obj.auth_by_password(_username, _password, '*') == dxf_obj.token
    else:
        assert dxf_obj.auth_by_password(_username, _password) is None
