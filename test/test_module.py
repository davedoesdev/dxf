import hashlib
import requests
import pytest
import dxf.exceptions

# pylint: disable=no-member

def _not_found(dxf_obj, dgst):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.blob_size(dgst)
    # pylint: disable=no-member
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
    assert sha256.hexdigest() == dgst

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
    assert ex.value.got == hashlib.sha256().hexdigest()
    assert ex.value.expected == pytest.blob1_hash

def test_set_alias(dxf_obj):
    dxf_obj.set_alias('hello', pytest.blob1_hash)
    dxf_obj.set_alias('there', pytest.blob1_hash, pytest.blob2_hash)
    dxf_obj.set_alias('world', pytest.blob2_hash)

def test_get_alias(dxf_obj):
    assert dxf_obj.get_alias('hello') == [pytest.blob1_hash]
    assert dxf_obj.get_alias('there') == [pytest.blob1_hash, pytest.blob2_hash]
    assert dxf_obj.get_alias('world') == [pytest.blob2_hash]

def test_list_aliases(dxf_obj):
    assert sorted(dxf_obj.list_aliases()) == ['hello', 'there', 'world']

def test_context_manager(dxf_obj):
    with dxf_obj as odxf:
        test_list_aliases(odxf)

def test_manifest(dxf_obj):
    manifest = dxf_obj.set_alias('mani_test', pytest.blob1_hash)
    assert manifest
    assert dxf_obj.get_alias(manifest=manifest) == [pytest.blob1_hash]

def test_unsigned_manifest(dxf_obj):
    manifest = dxf_obj.make_manifest(pytest.blob2_hash)
    assert manifest
    assert dxf_obj.get_alias(manifest=manifest) == [pytest.blob2_hash]

def test_auth(dxf_obj):
    # pylint: disable=protected-access
    if dxf_obj._insecure:
        with pytest.raises(dxf.exceptions.DXFAuthInsecureError):
            dxf_obj.authenticate(pytest.username, pytest.password)
    elif dxf_obj.test_do_token:
        assert dxf_obj.authenticate(pytest.username, pytest.password, '*') == dxf_obj.token
        assert dxf_obj.token
    else:
        assert dxf_obj.authenticate(pytest.username, pytest.password) is None

def _del_blob(dxf_obj, dgst):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.del_blob(dgst)
    # pylint: disable=no-member
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_del_blob(dxf_obj):
    _del_blob(dxf_obj, pytest.blob1_hash)
    _del_blob(dxf_obj, pytest.blob2_hash)

def _del_alias(dxf_obj, alias):
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf_obj.del_alias(alias)
    # pylint: disable=no-member
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_del_alias(dxf_obj):
    _del_alias(dxf_obj, 'hello')
    _del_alias(dxf_obj, 'there')
    _del_alias(dxf_obj, 'world')

def test_hash_bytes():
    assert dxf.hash_bytes(b'abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
