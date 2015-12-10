import sys
import errno
import hashlib
import pytest
import requests.exceptions
import dxf.main

# pylint: disable=no-member

def test_empty(dxf_main, capsys):
    assert dxf.main.doit(['list-repos'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""

def test_push_blob(dxf_main, capsys):
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + "\n"
    assert err == ""
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob2_file], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + "\n"
    assert err == ""
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf.main.doit(['get-alias', pytest.repo, 'fooey'], dxf_main)
    assert ex.value.response.status_code == requests.codes.not_found
    assert dxf.main.doit(['push-blob', pytest.repo, pytest.blob1_file, '@fooey'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + "\n"
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'fooey'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + "\n"
    assert err == ""
    assert dxf.main.doit(['list-repos'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.repo + "\n"
    assert err == ""

def _pull_blob(dxf_main, name, dgst, capfd):
    assert dxf.main.doit(['pull-blob', pytest.repo, name], dxf_main) == 0
    # pylint: disable=protected-access
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert sha256.hexdigest() == dgst
    assert err == ""

def test_pull_blob(dxf_main, capfd):
    _pull_blob(dxf_main, pytest.blob1_hash, pytest.blob1_hash, capfd)
    _pull_blob(dxf_main, pytest.blob2_hash, pytest.blob2_hash, capfd)
    _pull_blob(dxf_main, '@fooey', pytest.blob1_hash, capfd)

def test_set_alias(dxf_main, capsys):
    assert dxf.main.doit(['set-alias', pytest.repo, 'hello', pytest.blob1_hash], dxf_main) == 0
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
    assert out == pytest.blob1_hash + '\n'
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'there'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob1_hash + '\n' + pytest.blob2_hash + '\n'
    assert err == ""
    assert dxf.main.doit(['get-alias', pytest.repo, 'world'], dxf_main) == 0
    out, err = capsys.readouterr()
    assert out == pytest.blob2_hash + '\n'
    assert err == ""

def test_list_aliases(dxf_main, capsys):
    assert dxf.main.doit(['list-aliases', pytest.repo], dxf_main) == 0
    out, err = capsys.readouterr()
    assert sorted(out.split('\n')) == ['', 'fooey', 'hello', 'there', 'world']
    assert err == ""

def test_manifest(dxf_main, capfd, monkeypatch):
    # pylint: disable=no-member
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
    assert out == pytest.blob1_hash + '\n'
    assert err == ""
    assert dxf.main.doit(['pull-blob', pytest.repo], dxf_main) == 0
    # pylint: disable=protected-access
    capfd._capture.out.tmpfile.encoding = None
    out, err = capfd.readouterr()
    sha256 = hashlib.sha256()
    sha256.update(out)
    assert sha256.hexdigest() == pytest.blob1_hash
    assert err == ""
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf.main.doit(['del-blob', pytest.repo], dxf_main)
    # pylint: disable=no-member
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_auth(dxf_main, capsys):
    if dxf_main['DXF_INSECURE']:
        environ = {
            'DXF_USERNAME': pytest.username,
            'DXF_PASSWORD': pytest.password
        }
        environ.update(dxf_main)
        with pytest.raises(dxf.exceptions.DXFAuthInsecureError):
            dxf.main.doit(['auth', pytest.repo], environ)
    elif dxf_main['TEST_DO_TOKEN']:
        dxf.main.doit(['auth', pytest.repo, '*'], dxf_main)
        token, err = capsys.readouterr()
        assert token
        assert err == ""
        environ = {}
        environ.update(dxf_main)
        del environ['DXF_USERNAME']
        del environ['DXF_PASSWORD']
        assert dxf.main.doit(['list-aliases', pytest.repo], environ) == errno.EACCES
        out, err = capsys.readouterr()
        assert out == ""
        environ['DXF_TOKEN'] = token.strip()
        assert dxf.main.doit(['list-aliases', pytest.repo], environ) == 0
        out, err = capsys.readouterr()
        assert sorted(out.split('\n')) == ['', 'fooey', 'hello', 'mani_test', 'there', 'world']
        assert err == ""
    else:
        assert dxf.main.doit(['auth', pytest.repo], dxf_main) == 0
        out, err = capsys.readouterr()
        assert out == ""
        assert err == ""

def _del_blob(dxf_main, dgst):
    # pylint: disable=no-member
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf.main.doit(['del-blob', pytest.repo, dgst], dxf_main)
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_del_blob(dxf_main):
    _del_blob(dxf_main, pytest.blob1_hash)
    _del_blob(dxf_main, pytest.blob2_hash)

def _del_alias(dxf_main, alias):
    # pylint: disable=no-member
    with pytest.raises(requests.exceptions.HTTPError) as ex:
        dxf.main.doit(['del-alias', pytest.repo, alias], dxf_main)
    assert ex.value.response.status_code == requests.codes.method_not_allowed

def test_del_alias(dxf_main):
    _del_alias(dxf_main, 'hello')
    _del_alias(dxf_main, 'there')
    _del_alias(dxf_main, 'world')

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
