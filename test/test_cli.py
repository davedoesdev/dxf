import os
import sys
import errno
import time
import hashlib
import requests.exceptions
import pytest
import tqdm
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

def _pull_blob(dxf_main, name, dgst, capfd):
    assert dxf.main.doit(['pull-blob', pytest.repo, name], dxf_main) == 0
    # pylint: disable=protected-access
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert 'sha256:' + sha256.hexdigest() == dgst
    assert err == ""

def test_pull_blob(dxf_main, capfd):
    environ = {'DXF_BLOB_INFO': '1'}
    environ.update(dxf_main)
    assert dxf.main.doit(['pull-blob', pytest.repo, pytest.blob1_hash, pytest.blob2_hash], environ) == 0
    # pylint: disable=protected-access
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
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
    assert err == ""
    _pull_blob(dxf_main, pytest.blob1_hash, pytest.blob1_hash, capfd)
    _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfd)
    _pull_blob(dxf_main, '@fooey', pytest.blob1_hash, capfd)

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

def test_list_aliases(dxf_main, capsys):
    assert dxf.main.doit(['list-aliases', pytest.repo], dxf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split(os.linesep)) == ['', 'fooey', 'hello', 'there', 'world']
    assert err == ""

def test_manifest(dxf_main, capfd, monkeypatch):
    assert dxf.main.doit(['set-alias', pytest.repo, 'mani_test', pytest.blob1_hash], dxf_main) == 0
    manifest, err = capfd.readouterr()
    assert manifest
    assert err == ""
    # pylint: disable=too-few-public-methods
    class FakeStdin(object):
        # pylint: disable=no-self-use
        def read(self):
            return manifest
    monkeypatch.setattr(sys, 'stdin', FakeStdin())
    assert dxf.main.doit(['get-alias', pytest.repo], dxf_main) == 0
    out, err = capfd.readouterr()
    assert out == pytest.blob1_hash + os.linesep
    assert err == ""
    assert dxf.main.doit(['blob-size', pytest.repo], dxf_main) == 0
    out, err = capfd.readouterr()
    assert out == str(pytest.blob1_size) + os.linesep
    assert err == ""
    assert dxf.main.doit(['pull-blob', pytest.repo], dxf_main) == 0
    # pylint: disable=protected-access
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert 'sha256:' + sha256.hexdigest() == pytest.blob1_hash
    assert err == ""
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
            expected += ['test/registry']
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

def test_del_blob(dxf_main, capfd):
    _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfd)
    assert dxf.main.doit(['del-blob', pytest.repo, pytest.blob2_hash], dxf_main) == 0
    _not_found(dxf_main, pytest.blob2_hash)
    assert dxf.main.doit(['del-blob', pytest.repo, pytest.blob2_hash], dxf_main) == errno.ENOENT

def test_del_alias(dxf_main, capsys):
    assert dxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + os.linesep
    assert err == ""
    if dxf_main['REGVER'] == 2.2:
        with pytest.raises(requests.exceptions.HTTPError) as ex:
            dxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main)
        assert ex.value.response.status_code == requests.codes.method_not_allowed
        assert dxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    else:
        assert dxf.main.doit(['del-alias', pytest.repo, 'world'], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == pytest.blob2_hash + os.linesep
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
    _num_args(dxf_main, 'set-alias', 2, None, capsys)
    _num_args(dxf_main, 'list-aliases', None, 0, capsys)
    with pytest.raises(SystemExit):
        dxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file, 'fooey'], dxf_main)
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
