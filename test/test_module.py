import os
import hashlib
import json
import requests
import pytest
from jwcrypto import jws
import dxf.exceptions

# pylint: disable=no-member

def _not_found(dxf_obj, dgst):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.blob_size(dgst)
    assert ex.value.response.status_code == requests.codes.not_found

def test_not_found(dxf_obj):
    _not_found(dxf_obj, pytest.blob1_hash)
    _not_found(dxf_obj, pytest.blob2_hash)

def test_push_blob(dxf_obj):
    assert dxf_obj.push_blob(pytest.blob1_file) == pytest.blob1_hash
    state = {
        'called': False,
        'total': 0
    }
    # pylint: disable=unused-argument
    def progress1(dgst, chunk, size):
        state['called'] = True
    assert dxf_obj.push_blob(pytest.blob1_file, progress=progress1) == pytest.blob1_hash
    assert not state['called']
    def progress2(dgst, chunk, size):
        assert size == pytest.blob2_size
        state['total'] += len(chunk)
    assert dxf_obj.push_blob(pytest.blob2_file, progress=progress2) == pytest.blob2_hash
    assert state['total'] == pytest.blob2_size
    assert dxf_obj.list_repos() == [pytest.repo]

def test_blob_size(dxf_obj):
    assert dxf_obj.blob_size(pytest.blob1_hash) == pytest.blob1_size
    assert dxf_obj.blob_size(pytest.blob2_hash) == pytest.blob2_size

def _pull_blob(dxf_obj, dgst, expected_size, chunk_size):
    if expected_size is None:
        it = dxf_obj.pull_blob(dgst, chunk_size=chunk_size)
    else:
        it, size = dxf_obj.pull_blob(dgst, size=True, chunk_size=chunk_size)
        assert size == expected_size
    sha256 = hashlib.sha256()
    for chunk in it:
        if chunk_size is None:
            assert len(chunk) == 8192
        else:
            assert len(chunk) == chunk_size
        sha256.update(chunk)
    assert 'sha256:' + sha256.hexdigest() == dgst

def test_pull_blob(dxf_obj):
    _pull_blob(dxf_obj, pytest.blob1_hash, None, None)
    _pull_blob(dxf_obj, pytest.blob2_hash, pytest.blob2_size, None)
    _pull_blob(dxf_obj, pytest.blob1_hash, None, 4096)
    with pytest.raises(dxf.exceptions.DXFDigestMismatchError) as ex:
        class DummySHA256(object):
            # pylint: disable=no-self-use
            def update(self, chunk):
                pass
            def hexdigest(self):
                return orig_sha256().hexdigest()
        orig_sha256 = hashlib.sha256
        hashlib.sha256 = DummySHA256
        try:
            for _ in dxf_obj.pull_blob(pytest.blob1_hash):
                pass
        finally:
            hashlib.sha256 = orig_sha256
    assert ex.value.got == 'sha256:' + hashlib.sha256().hexdigest()
    assert ex.value.expected == pytest.blob1_hash

def test_pull_and_push_blob(dxf_obj):
    it = dxf_obj.pull_blob(pytest.blob1_hash)
    state = {'total': 0}
    sha256 = hashlib.sha256()
    def progress(dgst, chunk):
        assert dgst == pytest.blob1_hash
        state['total'] += len(chunk)
        sha256.update(chunk)
    assert dxf_obj.push_blob(data=it,
                             digest=pytest.blob1_hash,
                             progress=progress,
                             check_exists=False) == \
           pytest.blob1_hash
    assert state['total'] == pytest.blob1_size
    assert 'sha256:' + sha256.hexdigest() == pytest.blob1_hash
    _pull_blob(dxf_obj, pytest.blob1_hash, pytest.blob1_size, None)

def test_set_alias(dxf_obj):
    dxf_obj.set_alias('hello', pytest.blob1_hash)
    if dxf_obj.regver != 2.2:
        assert dxf_obj.del_alias('hello') == [pytest.blob1_hash]
        assert dxf_obj.list_aliases() == []
        dxf_obj.set_alias('hello', pytest.blob1_hash)
    dxf_obj.set_alias('there', pytest.blob1_hash, pytest.blob2_hash)
    dxf_obj.set_alias('world', pytest.blob2_hash)

def test_get_alias(dxf_obj):
    assert dxf_obj.get_alias('hello') == [pytest.blob1_hash]
    assert dxf_obj.get_alias('there') == [pytest.blob1_hash, pytest.blob2_hash]
    assert dxf_obj.get_alias('world') == [pytest.blob2_hash]

def test_get_digest(dxf_obj):
    if dxf_obj.regver == 2.2:
        with pytest.raises(dxf.exceptions.DXFDigestNotAvailableForSchema1):
            dxf_obj.get_digest('hello')
        return
    assert dxf_obj.get_digest('hello') == pytest.blob1_hash
    assert dxf_obj.get_digest('there') == pytest.blob1_hash
    assert dxf_obj.get_digest('world') == pytest.blob2_hash
    pytest.copy_registry_image(dxf_obj.regver)
    # pylint: disable=protected-access
    dxf_obj2 = dxf.DXF('localhost:5000', 'test/registry', dxf_obj._auth, dxf_obj._insecure, None, dxf_obj._tlsverify)
    assert dxf_obj2.get_digest(str(dxf_obj.regver)) == dxf_obj.reg_digest

def test_list_aliases(dxf_obj):
    assert sorted(dxf_obj.list_aliases()) == ['hello', 'there', 'world']
    assert sorted(list(dxf_obj.list_aliases(batch_size=2, iterate=True))) == ['hello', 'there', 'world']

def test_context_manager(dxf_obj):
    with dxf_obj as odxf:
        test_list_aliases(odxf)

def test_manifest(dxf_obj):
    manifest = dxf_obj.set_alias('mani_test', pytest.blob1_hash)
    assert manifest
    if dxf_obj.regver != 2.2:
        assert dxf_obj.get_manifest('mani_test') == manifest
    #assert json.dumps(json.loads(dxf_obj.get_manifest('mani_test')),
    #                  sort_keys=True) == \
    #       json.dumps(json.loads(manifest), sort_keys=True)
    assert dxf_obj.get_alias(manifest=manifest) == [pytest.blob1_hash]
    if json.loads(manifest)['schemaVersion'] == 1:
        with pytest.raises(jws.InvalidJWSSignature):
            dxf_obj.get_alias(manifest=' '+manifest)
    if dxf_obj.regver != 2.2:
        dxf_obj.set_manifest('mani_test2', manifest)
        assert dxf_obj.get_alias('mani_test2') == [pytest.blob1_hash]

def test_unsigned_manifest_v1(dxf_obj):
    manifest = dxf_obj.make_unsigned_manifest('mani_test3', pytest.blob2_hash)
    assert manifest
    with pytest.raises(KeyError):
        dxf_obj.get_alias(manifest=manifest)
    assert dxf_obj.get_alias(manifest=manifest, verify=False) == [pytest.blob2_hash]

def test_unsigned_manifest_v2(dxf_obj):
    manifest = dxf_obj.make_manifest(pytest.blob2_hash)
    assert manifest
    assert dxf_obj.get_alias(manifest=manifest) == [pytest.blob2_hash]

#@pytest.mark.onlytest
def test_auth(dxf_obj):
    # pylint: disable=protected-access
    if not dxf_obj.test_do_auth:
        assert dxf_obj.authenticate() is None
    elif not dxf_obj.test_do_token:
        assert dxf_obj.authenticate(pytest.username, pytest.password) is None
    else:
        assert dxf_obj.authenticate(pytest.username, pytest.password, '*') == dxf_obj.token
        assert dxf_obj.token

def test_del_blob(dxf_obj):
    _pull_blob(dxf_obj, pytest.blob2_hash, None, None)
    dxf_obj.del_blob(pytest.blob2_hash)
    _not_found(dxf_obj, pytest.blob2_hash)
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.del_blob(pytest.blob2_hash)
    assert ex.value.response.status_code == requests.codes.not_found

def test_del_alias(dxf_obj):
    assert dxf_obj.get_alias('world') == [pytest.blob2_hash]
    if dxf_obj.regver == 2.2:
        with pytest.raises(requests.exceptions.HTTPError) as ex:
            dxf_obj.del_alias('world')
        assert ex.value.response.status_code == requests.codes.method_not_allowed
        assert dxf_obj.get_alias('world') == [pytest.blob2_hash]
    else:
        assert dxf_obj.del_alias('world') == [pytest.blob2_hash]
        # Note: test gc but it isn't needed to make a 404
        pytest.gc()
        with pytest.raises(requests.exceptions.HTTPError) as ex:
            dxf_obj.get_alias('world')
        assert ex.value.response.status_code == requests.codes.not_found
        with pytest.raises(requests.exceptions.HTTPError) as ex:
            dxf_obj.del_alias('world')
        assert ex.value.response.status_code == requests.codes.not_found

_abc_hash = 'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

def test_hash_bytes():
    assert dxf.hash_bytes(b'abc') == _abc_hash

def test_tlsverify(dxf_obj):
    # pylint: disable=protected-access
    if not dxf_obj._insecure:
        v = os.environ['REQUESTS_CA_BUNDLE']
        del os.environ['REQUESTS_CA_BUNDLE']
        try:
            if dxf_obj._tlsverify:
                with pytest.raises(requests.exceptions.SSLError):
                    dxf_obj.list_repos()
            else:
                expected = [pytest.repo]
                if dxf_obj.regver != 2.2:
                    expected += ['test/registry']
                assert sorted(dxf_obj.list_repos()) == sorted(expected)
        finally:
            os.environ['REQUESTS_CA_BUNDLE'] = v

def test_tlsverify_str(dxf_obj):
    # pylint: disable=protected-access
    if not dxf_obj._insecure:
        v = os.environ['REQUESTS_CA_BUNDLE']
        del os.environ['REQUESTS_CA_BUNDLE']
        tlsv = dxf_obj._tlsverify
        dxf_obj._tlsverify = v
        try:
            expected = [pytest.repo]
            if dxf_obj.regver != 2.2:
                expected += ['test/registry']
            assert sorted(dxf_obj.list_repos()) == sorted(expected)
        finally:
            os.environ['REQUESTS_CA_BUNDLE'] = v
            dxf_obj._tlsverify = tlsv

def test_pagination(dxf_obj):
    # pylint: disable=protected-access
    num = 11
    for i in range(num):
        name = 'test/{0}'.format(i)
        dxf_obj2 = dxf.DXF('localhost:5000', name, dxf_obj._auth, dxf_obj._insecure, None, dxf_obj._tlsverify)
        assert dxf_obj2.push_blob(data=b'abc', digest=_abc_hash) == _abc_hash
    expected = [pytest.repo] + ['test/{0}'.format(i) for i in range(num)]
    if dxf_obj.regver != 2.2:
        expected += ['test/registry']
    assert sorted(dxf_obj2.list_repos(batch_size=3)) == sorted(expected)
