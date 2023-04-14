import os
import sys
import errno
import time
import hashlib
import requests.exceptions
import pytest
import tqdm
from conftest import record_or_replay
import dxf.main

# pylint: disable=no-member

def test_empty(dxf_main, capsys):
    assert dxf.main.doit(['list-repos'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""

def _not_found(dxf_main, name):
    assert dxf.main.doit(['blob-size', pytest.repo, name], dxf_main) == errno.ENOENT

def test_not_found(dxf_main):
    _not_found(dxf_main, pytest.blob1_hash)
    _not_found(dxf_main, pytest.blob2_hash)
    _not_found(dxf_main, '@fooey')

def test_push_blob(dxf_main, capsys):
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob2_file], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'fooey'], dxf_main) == errno.ENOENT
    out, err = capsys.readouterr()
    assert out == ""
    assert err.index('Not Found') >= 0
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file, '@fooey'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'fooey'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['list-repos'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.repo + os.linesep
    assert err == ""

def _pull_blob(dxf_main, name, dgst, capfdbinary, repo=None):
    assert dxf.main.doit(['pull-blob', pytest.repo if repo is None else repo, name], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert 'sha256:' + sha256.hexdigest() == dgst
    assert err == b""

def test_pull_blob(dxf_main, capfdbinary):
    environ = {'DXF_BLOB_INFO': '1'}
    environ.update(dxf_main)
    assert dxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash, pytest.blob2_hash], environ) == 0
    out, err = capfdbinary.readouterr()
    out_sha256 = hashlib.sha256()
    out_sha256.update(out)
    expected_sha256 = hashlib.sha256()
    expected_sha256.update(pytest.blob1_hash.encode('utf-8'))
    expected_sha256.update(b' ')
    expected_sha256.update(str(pytest.blob1_size).encode('utf-8'))
    expected_sha256.update(os.linesep.encode('utf-8'))
    with open(pytest.blob1_file, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            expected_sha256.update(chunk)
    expected_sha256.update(pytest.blob2_hash.encode('utf-8'))
    expected_sha256.update(b' ')
    expected_sha256.update(str(pytest.blob2_size).encode('utf-8'))
    expected_sha256.update(os.linesep.encode('utf-8'))
    with open(pytest.blob2_file, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            expected_sha256.update(chunk)
    assert out_sha256.digest() == expected_sha256.digest()
    assert err == b""
    _pull_blob(dxf_main, pytest.blob1_hash, pytest.blob1_hash, capfdbinary)
    _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfdbinary)
    _pull_blob(dxf_main, '@fooey', pytest.blob1_hash, capfdbinary)

def test_progress(dxf_main, capfd):
    environ = {'DXF_PROGRESS': '1'}
    environ.update(dxf_main)
    assert dxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash], environ) == 0
    _, err = capfd.readouterr()
    assert pytest.blob1_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    assert " " + str(pytest.blob1_size) + "/" + str(pytest.blob1_size) in err
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob3_file], environ) == 0
    _, err = capfd.readouterr()
    assert pytest.blob3_hash[0:8] in err
    assert " 0%" in err
    assert " 100%" in err
    assert " " + str(pytest.blob3_size) + "/" + str(pytest.blob3_size) in err

def test_see_progress(dxf_main, monkeypatch):
    environ = {'DXF_PROGRESS': '1'}
    environ.update(dxf_main)
    # pylint: disable=too-few-public-methods
    class FakeStdout(object):
        # pylint: disable=no-self-use
        def write(self, _):
            time.sleep(0.05)
        def flush(self):
            pass
    monkeypatch.setattr(sys, 'stdout', FakeStdout())
    assert dxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash], environ) == 0
    orig_tqdm = tqdm.tqdm
    def new_tqdm(*args, **kwargs):
        tqdm_obj = orig_tqdm(*args, **kwargs)
        class TQDM(object):
            # pylint: disable=no-self-use
            def update(self, n):
                tqdm_obj.update(n)
                time.sleep(0.025)
            def close(self):
                tqdm_obj.close()
            @property
            def n(self):
                return tqdm_obj.n
            @property
            def total(self):
                return tqdm_obj.total
        return TQDM()
    monkeypatch.setattr(tqdm, 'tqdm', new_tqdm)
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob4_file], environ) == 0

def test_set_alias(dxf_main, capsys):
    assert dxf.main.doit(['set-alias', pytest.repo, 'hello', pytest.blob1_hash], dxf_main) == 0
    _, err = capsys.readouterr()
    assert err == ""
    if dxf_main['REGVER'] != 2.2:
        assert dxf.main.doit(['del-alias', pytest.repo, 'hello'], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == pytest.blob1_hash + os.linesep
        assert err == ""
        # Deleting tag actually deletes by DCD:
        # https://github.com/docker/distribution/issues/1566
        # So fooey gets deleted too
        assert dxf.main.doit(['list-aliases', pytest.repo], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == ""
        assert err == ""
        assert dxf.main.doit(['set-alias', pytest.repo, 'hello', pytest.blob1_hash], dxf_main) == 0
        assert dxf.main.doit(['set-alias', pytest.repo, 'fooey', pytest.blob1_hash], dxf_main) == 0
        _, err = capsys.readouterr()
        assert err == ""
    assert dxf.main.doit(['set-alias', pytest.repo, 'there', pytest.blob1_hash, pytest.blob2_hash], dxf_main) == 0
    _, err = capsys.readouterr()
    assert err == ""
    assert dxf.main.doit(['set-alias', pytest.repo, 'world', pytest.blob2_file], dxf_main) == 0
    _, err = capsys.readouterr()
    assert err == ""

def test_get_alias(dxf_main, capsys):
    assert dxf.main.doit(['get-alias', pytest.repo, 'hello'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'there'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep + \
                  pytest.blob2_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""

def test_get_digest(dxf_main, capsys):
    if dxf_main['REGVER'] == 2.2:
        with pytest.raises(dxf.exceptions.DXFDigestNotAvailableForSchema1):
            dxf.main.doit(['get-digest', pytest.repo, 'hello'], dxf_main)
        return
    assert dxf.main.doit(['get-digest', pytest.repo, 'hello'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['get-digest', pytest.repo, 'there'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['get-digest', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    pytest.copy_registry_image(dxf_main['REGVER'])
    assert dxf.main.doit(['get-digest',
                          'test/registry',
                          str(dxf_main['REGVER'])],
                         dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == dxf_main['REG_DIGEST'] + os.linesep
    assert err == ""

def test_blob_size(dxf_main, capsys):
    assert dxf.main.doit(['blob-size', pytest.repo, pytest.blob1_hash, pytest.blob2_hash, '@hello', '@there', '@world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == str(pytest.blob1_size) + os.linesep + \
                  str(pytest.blob2_size) + os.linesep + \
                  str(pytest.blob1_size) + os.linesep + \
                  str(pytest.blob1_size + pytest.blob2_size) + os.linesep + \
                  str(pytest.blob2_size) + os.linesep
    assert err == ""

_def_hash = 'sha256:cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34'

def test_mount_blob(dxf_main, capfdbinary):
    if dxf_main['REGVER'] == 2.2:
        with pytest.raises(dxf.exceptions.DXFMountFailed):
            dxf.main.doit(['mount-blob', 'some/other', pytest.repo, pytest.blob1_hash], dxf_main)
    else:
        assert dxf.main.doit(['mount-blob', 'some/other', pytest.repo, pytest.blob1_hash], dxf_main) == 0
        out, err = capfdbinary.readouterr()
        assert out == pytest.blob1_hash.encode('utf-8') + os.linesep.encode('utf-8')
        assert err == b""
        _pull_blob(dxf_main, pytest.blob1_hash, pytest.blob1_hash, capfdbinary, 'some/other')
    with pytest.raises(dxf.exceptions.DXFMountFailed):
        dxf.main.doit(['mount-blob', 'some/other', pytest.repo, _def_hash], dxf_main)
    with pytest.raises(dxf.exceptions.DXFMountFailed):
        dxf.main.doit(['mount-blob', 'some/other', 'another/repo', pytest.blob1_hash], dxf_main)
    if dxf_main['REGVER'] == 2.2:
        with pytest.raises(dxf.exceptions.DXFMountFailed):
            dxf.main.doit(['mount-blob', 'some/other', pytest.repo, pytest.blob2_hash, '@blob2-mounted'], dxf_main)
    else:
        assert dxf.main.doit(['mount-blob', 'some/other', pytest.repo, pytest.blob2_hash, '@blob2-mounted'], dxf_main) == 0
        out, err = capfdbinary.readouterr()
        assert out == pytest.blob2_hash.encode('utf-8') + os.linesep.encode('utf-8')
        assert err == b""
        _pull_blob(dxf_main, '@blob2-mounted', pytest.blob2_hash, capfdbinary, 'some/other')

def test_list_aliases(dxf_main, capsys):
    assert dxf.main.doit(['list-aliases', pytest.repo], dxf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'fooey', 'hello', 'there', 'world']
    assert err == ""

def test_manifest(dxf_main, capfdbinary, monkeypatch):
    assert dxf.main.doit(['set-alias', pytest.repo, 'mani_test', pytest.blob1_hash], dxf_main) == 0
    manifest, err = capfdbinary.readouterr()
    assert manifest
    assert err == b""
    # pylint: disable=too-few-public-methods
    class FakeStdin(object):
        # pylint: disable=no-self-use
        def read(self):
            return manifest.decode()
    monkeypatch.setattr(sys, 'stdin', FakeStdin())
    assert dxf.main.doit(['get-alias', pytest.repo], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    assert out.decode() == pytest.blob1_hash + os.linesep
    assert err == b""
    assert dxf.main.doit(['blob-size', pytest.repo], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    assert out.decode() == str(pytest.blob1_size) + os.linesep
    assert err == b""
    assert dxf.main.doit(['pull-blob', pytest.repo], dxf_main) == 0
    out, err = capfdbinary.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert 'sha256:' + sha256.hexdigest() == pytest.blob1_hash
    assert err == b""
    assert dxf.main.doit(['del-blob', pytest.repo], dxf_main) == 0
    assert dxf.main.doit(['pull-blob', pytest.repo], dxf_main) == errno.ENOENT

#@pytest.mark.onlytest
def test_auth(dxf_main, capsys):
    if (not dxf_main['TEST_DO_AUTH']) or (not dxf_main['TEST_DO_TOKEN']):
        assert dxf.main.doit(['auth', pytest.repo], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == ""
        assert err == ""
    else:
        assert dxf.main.doit(['auth', pytest.repo, '*'], dxf_main) == 0
        token, err = capsys.readouterr()
        assert token
        assert err == ""
        environ = {}
        environ.update(dxf_main)
        environ.pop('DXF_USERNAME', None)
        environ.pop('DXF_PASSWORD', None)
        environ.pop('DXF_AUTHORIZATION', None)
        assert dxf.main.doit(['list-repos'], environ) == 0
        out, err = capsys.readouterr()
        expected = [pytest.repo]
        if dxf_main['REGVER'] != 2.2:
            expected += ['test/registry', 'some/other']
        assert sorted(out.rstrip().split(os.linesep)) == sorted(expected)
        assert err == ""
        assert dxf.main.doit(['list-aliases', pytest.repo], environ) == errno.EACCES
        out, err = capsys.readouterr()
        assert out == ""
        environ['DXF_TOKEN'] = token.strip()
        assert dxf.main.doit(['list-aliases', pytest.repo], environ) == 0
        out, err = capsys.readouterr()
        assert sorted(out.split(os.linesep)) == ['', 'fooey', 'hello', 'mani_test', 'there', 'world']
        assert err == ""

def test_del_blob(dxf_main, capfdbinary):
    _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfdbinary)
    assert dxf.main.doit(['del-blob', pytest.repo, pytest.blob2_hash], dxf_main) == 0
    _not_found(dxf_main, pytest.blob2_hash)
    assert dxf.main.doit(['del-blob', pytest.repo, pytest.blob2_hash], dxf_main) == errno.ENOENT

def test_del_alias(dxf_main, capsys):
    assert dxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    if dxf_main['REGVER'] != 2.2:
        # Note: test gc but it isn't needed to make a 404
        pytest.gc()
    assert dxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == errno.ENOENT
    assert dxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main) == errno.ENOENT

def _num_args(dxf_main, op, minimum, maximum, capsys):
    if minimum is not None:
        with pytest.raises(SystemExit):
            dxf.main.doit([op, pytest.repo] + ['a'] * (minimum - 1), dxf_main)
        out, err = capsys.readouterr()
        assert out == ""
        assert "too few arguments" in err
    if maximum is not None:
        with pytest.raises(SystemExit):
            dxf.main.doit([op, pytest.repo] + ['a'] * (maximum + 1), dxf_main)
        out, err = capsys.readouterr()
        assert out == ""
        assert "too many arguments" in err

def test_bad_args(dxf_main, capsys):
    _num_args(dxf_main, 'push-blob', 1, 2, capsys)
    _num_args(dxf_main, 'mount-blob', 2, 3, capsys)
    _num_args(dxf_main, 'set-alias', 2, None, capsys)
    _num_args(dxf_main, 'list-aliases', None, 0, capsys)
    with pytest.raises(SystemExit):
        dxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file, 'fooey'], dxf_main)
    out, err = capsys.readouterr()
    assert out == ""
    assert "invalid alias" in err
    with pytest.raises(SystemExit):
        dxf.main.doit(['mount-blob', 'some/other', pytest.repo, pytest.blob2_hash, 'blob2-mounted'], dxf_main)
    out, err = capsys.readouterr()
    assert out == ""
    assert "invalid alias" in err

def test_auth_host(dxf_main):
    if dxf_main['TEST_DO_TOKEN']:
        environ = {
            'DXF_AUTH_HOST': 'localhost:5002'
        }
        environ.update(dxf_main)
        with pytest.raises(requests.exceptions.ConnectionError):
            dxf.main.doit(['list-repos'], environ)

def test_tlsverify(dxf_main):
    if dxf_main['DXF_INSECURE'] == '0':
        v = os.environ['REQUESTS_CA_BUNDLE']
        del os.environ['REQUESTS_CA_BUNDLE']
        try:
            if dxf_main['DXF_SKIPTLSVERIFY'] == '0':
                with pytest.raises(requests.exceptions.SSLError):
                    dxf.main.doit(['list-repos'], dxf_main)
            else:
                assert dxf.main.doit(['list-repos'], dxf_main) == 0
        finally:
            os.environ['REQUESTS_CA_BUNDLE'] = v

def test_tlsverify_str(dxf_main):
    if dxf_main['DXF_INSECURE'] == '0':
        v = os.environ['REQUESTS_CA_BUNDLE']
        del os.environ['REQUESTS_CA_BUNDLE']
        skip = dxf_main['DXF_SKIPTLSVERIFY']
        dxf_main['DXF_SKIPTLSVERIFY'] = '0'
        dxf_main['DXF_TLSVERIFY'] = v
        try:
            assert dxf.main.doit(['list-repos'], dxf_main) == 0
        finally:
            os.environ['REQUESTS_CA_BUNDLE'] = v
            dxf_main['DXF_SKIPTLSVERIFY'] = skip
            del dxf_main['DXF_TLSVERIFY']

@record_or_replay
def test_docker_image_single_arch(dxf_regmain, capsys):
    assert dxf.main.doit(['get-alias', 'ubuntu', '12.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == "sha256:d8868e50ac4c7104d2200d42f432b661b2da8c1e417ccfae217e6a1e04bb9295\n\
sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed\n\
sha256:589bba2f1b36ae56f0152c246e2541c5aa604b058febfcf2be32e9a304fec610\n\
sha256:d62ecaceda3964b735cdd2af613d6bb136a52c1da0838b2ff4b4dab4212bcb1c\n\
sha256:6d93b41cfc6bf0d2522b7cf61588de4cd045065b36c52bd3aec2ba0622b2b22b\n"
    assert err == ""

    assert dxf.main.doit(['get-digest', 'ubuntu', '12.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == "sha256:5b117edd0b767986092e9f721ba2364951b0a271f53f1f41aff9dd1861c2d4fe\n"
    assert err == ""

    assert dxf.main.doit(['blob-size', 'ubuntu', '@12.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == "39156124\n"
    assert err == ""

@record_or_replay
def test_docker_image_multi_arch(dxf_regmain, capsys):
    assert dxf.main.doit(['get-alias', 'ubuntu', '22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == '{"linux/amd64": ["sha256:2ab09b027e7f3a0c2e8bb1944ac46de38cebab7145f0bd6effebfe5492c818b6"], "linux/arm/v7": ["sha256:aea1895b7fd03ef3bc263eef4b6f1dd219fc3286f3ff79495aadb81a88650723"], "linux/arm64/v8": ["sha256:cd741b12a7eaa64357041c2d3f4590c898313a7f8f65cd1577594e6ee03a8c38"], "linux/ppc64le": ["sha256:2561b3b559ec9b25bafa07804afa433803291265f7dd847de711224b0f238237"], "linux/s390x": ["sha256:15f635e04e894b7646b4ebca40424ddf244867fc663429ea8b877eca172a7cf1"]}\n'
    assert err == ""

    assert dxf.main.doit(['get-digest', 'ubuntu', '22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == '{"linux/amd64": "sha256:08d22c0ceb150ddeb2237c5fa3129c0183f3cc6f5eeb2e7aa4016da3ad02140a", "linux/arm/v7": "sha256:2bf0095935ffb29018664cf219d8c1b2c890e3e3c4af89113df23e7330397187", "linux/arm64/v8": "sha256:bab8ce5c00ca3ef91e0d3eb4c6e6d6ec7cffa9574c447fd8d54a8d96e7c1c80e", "linux/ppc64le": "sha256:4220c61b3ab7b82dd3ff3395f9efe2b63e730c3f24284d1519013cf3cda822f8", "linux/s390x": "sha256:63ad39053efde0c294433cd8f9709c6d69a36e1f0af4ffbf81c3d261caffb615"}\n'
    assert err == ""

    assert dxf.main.doit(['blob-size', 'ubuntu', '@22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == '{"linux/amd64": 29533950, "linux/arm/v7": 26140319, "linux/arm64/v8": 27347481, "linux/ppc64le": 34593661, "linux/s390x": 28015959}\n'
    assert err == ""

    assert dxf.main.doit(['pull-blob', 'ubuntu', '@22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == '{"linux/amd64": ["sha256:2ab09b027e7f3a0c2e8bb1944ac46de38cebab7145f0bd6effebfe5492c818b6"], "linux/arm/v7": ["sha256:aea1895b7fd03ef3bc263eef4b6f1dd219fc3286f3ff79495aadb81a88650723"], "linux/arm64/v8": ["sha256:cd741b12a7eaa64357041c2d3f4590c898313a7f8f65cd1577594e6ee03a8c38"], "linux/ppc64le": ["sha256:2561b3b559ec9b25bafa07804afa433803291265f7dd847de711224b0f238237"], "linux/s390x": ["sha256:15f635e04e894b7646b4ebca40424ddf244867fc663429ea8b877eca172a7cf1"]}\n'
    assert err == ""

@record_or_replay
def test_docker_image_multi_arch_del(dxf_regmain, capsys, monkeypatch):
    orig_DXF = dxf.DXF
    paths = []
    def DXF(*args, **kwargs):
        dxf.DXF = orig_DXF
        r = dxf.DXF(*args, **kwargs)
        orig_request = r._request # pylint: disable=protected-access
        def request(method, path, **kwargs):
            if method == 'delete':
                paths.append(path)
                return None
            return orig_request(method, path, **kwargs)
        monkeypatch.setattr(r, '_request', request)
        return r
    monkeypatch.setattr(dxf, 'DXF', DXF)
    assert dxf.main.doit(['del-alias', 'ubuntu', '22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == '{"linux/amd64": "sha256:7a57c69fe1e9d5b97c5fe649849e79f2cfc3bf11d10bbd5218b4eb61716aebe6", "linux/arm/v7": "sha256:ad18cfdb19dac67bf0072dacea661a817330e5c955d081f4d09914e743ae5d4a", "linux/arm64/v8": "sha256:537da24818633b45fcb65e5285a68c3ec1f3db25f5ae5476a7757bc8dfae92a3", "linux/ppc64le": "sha256:f23b7ade9f88f91c8d5932a48b721712ed509a607d9a05cdeae4cd06de09e5f7", "linux/s390x": "sha256:b351315d950a4da70f19d62f4da5dd7f9a445eb8c8d6851a5b6cdddbdafb13cf"}\n'
    assert err == ""
    paths.sort()
    assert paths == ['manifests/sha256:67211c14fa74f070d27cc59d69a7fa9aeff8e28ea118ef3babc295a0428a6d21']
    paths.clear()
    monkeypatch.setattr(dxf, 'DXF', DXF)
    assert dxf.main.doit(['del-blob', 'ubuntu', '@22.04'], dxf_regmain) == 0
    paths.sort()
    assert paths == ['blobs/sha256:15f635e04e894b7646b4ebca40424ddf244867fc663429ea8b877eca172a7cf1', 'blobs/sha256:2561b3b559ec9b25bafa07804afa433803291265f7dd847de711224b0f238237', 'blobs/sha256:2ab09b027e7f3a0c2e8bb1944ac46de38cebab7145f0bd6effebfe5492c818b6', 'blobs/sha256:aea1895b7fd03ef3bc263eef4b6f1dd219fc3286f3ff79495aadb81a88650723', 'blobs/sha256:cd741b12a7eaa64357041c2d3f4590c898313a7f8f65cd1577594e6ee03a8c38', 'manifests/sha256:537da24818633b45fcb65e5285a68c3ec1f3db25f5ae5476a7757bc8dfae92a3', 'manifests/sha256:67211c14fa74f070d27cc59d69a7fa9aeff8e28ea118ef3babc295a0428a6d21', 'manifests/sha256:7a57c69fe1e9d5b97c5fe649849e79f2cfc3bf11d10bbd5218b4eb61716aebe6', 'manifests/sha256:ad18cfdb19dac67bf0072dacea661a817330e5c955d081f4d09914e743ae5d4a', 'manifests/sha256:b351315d950a4da70f19d62f4da5dd7f9a445eb8c8d6851a5b6cdddbdafb13cf', 'manifests/sha256:f23b7ade9f88f91c8d5932a48b721712ed509a607d9a05cdeae4cd06de09e5f7']

@record_or_replay
def test_docker_image_platform(dxf_regmain, capsys):
    dxf_regmain['DXF_PLATFORM'] = 'linux/amd64'

    assert dxf.main.doit(['get-alias', 'ubuntu', '22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == 'sha256:2ab09b027e7f3a0c2e8bb1944ac46de38cebab7145f0bd6effebfe5492c818b6\n'
    assert err == ""

    assert dxf.main.doit(['get-digest', 'ubuntu', '22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == 'sha256:08d22c0ceb150ddeb2237c5fa3129c0183f3cc6f5eeb2e7aa4016da3ad02140a\n'
    assert err == ""

    assert dxf.main.doit(['blob-size', 'ubuntu', '@22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    assert out == '29533950\n'
    assert err == ""

@record_or_replay
def test_docker_manifest(dxf_regmain, capsys):
    assert dxf.main.doit(['get-manifest', 'ubuntu', '12.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out.encode('utf8'))
    assert sha256.hexdigest() == "18305429afa14ea462f810146ba44d4363ae76e4c8dfc38288cf73aa07485005"
    assert err == ""

    dxf_regmain['DXF_PLATFORM'] = 'linux/amd64'
    assert dxf.main.doit(['get-manifest', 'ubuntu', '22.04'], dxf_regmain) == 0
    out, err = capsys.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out.encode('utf8'))
    assert sha256.hexdigest() == "7a57c69fe1e9d5b97c5fe649849e79f2cfc3bf11d10bbd5218b4eb61716aebe6"
    assert err == ""
