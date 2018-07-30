"""
Module for accessing a Docker v2 Registry
"""

import base64
import hashlib
import json
import sys
import warnings

try:
    import urllib.parse as urlparse
    from urllib.parse import urlencode
except ImportError:
    # pylint: disable=import-error,no-name-in-module,wrong-import-order
    from urllib import urlencode
    import urlparse

import requests
try:
    from requests.packages import urllib3
except ImportError:
    import urllib3
from urllib3.exceptions import InsecureRequestWarning

from jwcrypto import jwk, jws
import www_authenticate
# pylint: disable=wildcard-import
from dxf import exceptions

_schema2_mimetype = 'application/vnd.docker.distribution.manifest.v2+json'

if sys.version_info < (3, 0):
    _binary_type = str
else:
    _binary_type = bytes
    # pylint: disable=redefined-builtin
    long = int

def _to_bytes_2and3(s):
    return s if isinstance(s, _binary_type) else s.encode('utf-8')

def hash_bytes(buf):
    """
    Hash bytes using the same method the registry uses (currently SHA-256).

    :param buf: Bytes to hash
    :type buf: binary str

    :rtype: str
    :returns: Hex-encoded hash of file's content (prefixed by ``sha256:``)
    """
    sha256 = hashlib.sha256()
    sha256.update(buf)
    return 'sha256:' + sha256.hexdigest()

def hash_file(filename):
    """
    Hash a file using the same method the registry uses (currently SHA-256).

    :param filename: Name of file to hash
    :type filename: str

    :rtype: str
    :returns: Hex-encoded hash of file's content (prefixed by ``sha256:``)
    """
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return 'sha256:' + sha256.hexdigest()

def _raise_for_status(r):
    # pylint: disable=no-member
    if r.status_code == requests.codes.unauthorized:
        raise exceptions.DXFUnauthorizedError()
    r.raise_for_status()

def split_digest(s):
    method, digest = s.split(':')
    if method != 'sha256':
        raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
    return method, digest

class _ReportingFile(object):
    def __init__(self, dgst, f, cb):
        self._dgst = dgst
        self._f = f
        self._cb = cb
        self._size = requests.utils.super_len(f)
        cb(dgst, b'', self._size)
    # define __iter__ so requests thinks we're a stream
    # (models.py, PreparedRequest.prepare_body)
    def __iter__(self):
        assert not "called"
    # define fileno, tell and mode so requests can find length
    # (utils.py, super_len)
    def fileno(self):
        return self._f.fileno()
    def tell(self):
        return self._f.tell()
    @property
    def mode(self):
        return self._f.mode
    def read(self, n):
        chunk = self._f.read(n)
        if chunk:
            self._cb(self._dgst, chunk, self._size)
        return chunk

class _ReportingChunks(object):
    # pylint: disable=too-few-public-methods
    def __init__(self, dgst, data, cb):
        self._dgst = dgst
        self._data = data
        self._cb = cb
    def __iter__(self):
        for chunk in self._data:
            if chunk:
                self._cb(self._dgst, chunk)
            yield chunk

class PaginatingResponse(object):
    # pylint: disable=too-few-public-methods
    def __init__(self, dxf_obj, req_meth, path, header, **kwargs):
        self._meth = getattr(dxf_obj, req_meth)
        self._path = path
        self._header = header
        self._kwargs = kwargs
    def __iter__(self):
        while self._path:
            response = self._meth('get', self._path, **self._kwargs)
            self._kwargs = {}
            for v in response.json()[self._header] or []:
                yield v
            nxt = response.links.get('next')
            self._path = nxt['url'] if nxt else None

def _ignore_warnings(obj):
    # pylint: disable=protected-access
    if obj._tlsverify is False:
        warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class DXFBase(object):
    # pylint: disable=too-many-instance-attributes
    """
    Class for communicating with a Docker v2 registry.
    Contains only operations which aren't related to repositories.

    Can act as a context manager. For each context entered, a new
    `requests.Session <http://docs.python-requests.org/en/latest/user/advanced/#session-objects>`_
    is obtained. Connections to the same host are shared by the session.
    When the context exits, all the session's connections are closed.

    If you don't use :class:`DXFBase` as a context manager, each request
    uses an ephemeral session. If you don't read all the data from an iterator
    returned by :meth:`DXF.pull_blob` then the underlying connection won't be
    closed until Python garbage collects the iterator.
    """
    def __init__(self, host, auth=None, insecure=False, auth_host=None, tlsverify=True):
        # pylint: disable=too-many-arguments
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DXFBase` object and a HTTP response object. It should call :meth:`authenticate` with a username, password and ``response`` before it returns.
        :type auth: function(dxf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str

        :param tlsverify: When set to False, do not verify TLS certificate. When pointed to a `<ca bundle>.crt` file use this for TLS verification. See `requests.verify <http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification>`_ for more details.
        :type tlsverify: bool or str
        """
        self._base_url = ('http' if insecure else 'https') + '://' + host + '/v2/'
        self._host = host
        self._auth = auth
        self._insecure = insecure
        self._auth_host = auth_host
        self._token = None
        self._headers = {}
        self._repo = None
        self._sessions = [requests]
        self._tlsverify = tlsverify

    @property
    def token(self):
        """
        str: Authentication token. This will be obtained automatically when
        you call :meth:`authenticate`. If you've obtained a token
        previously, you can also set it but be aware tokens expire quickly.
        """
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self._headers = {
            'Authorization': 'Bearer ' + value
        }

    def _base_request(self, method, path, **kwargs):
        def make_kwargs():
            r = {'allow_redirects': True, 'verify': self._tlsverify}
            r.update(kwargs)
            if 'headers' not in r:
                r['headers'] = {}
            r['headers'].update(self._headers)
            return r
        url = urlparse.urljoin(self._base_url, path)
        with warnings.catch_warnings():
            _ignore_warnings(self)
            r = getattr(self._sessions[0], method)(url, **make_kwargs())
        # pylint: disable=no-member
        if r.status_code == requests.codes.unauthorized and self._auth:
            headers = self._headers
            self._auth(self, r)
            if self._headers != headers:
                with warnings.catch_warnings():
                    _ignore_warnings(self)
                    r = getattr(self._sessions[0], method)(url, **make_kwargs())
        _raise_for_status(r)
        return r

    def authenticate(self,
                     username=None, password=None,
                     actions=None, response=None,
                     authorization=None):
        # pylint: disable=too-many-arguments
        """
        Authenticate to the registry using a username and password,
        an authorization header or otherwise as the anonymous user.

        :param username: User name to authenticate as.
        :type username: str

        :param password: User's password.
        :type password: str

        :param actions: If you know which types of operation you need to make on the registry, specify them here. Valid actions are ``pull``, ``push`` and ``*``.
        :type actions: list

        :param response: When the ``auth`` function you passed to :class:`DXFBase`'s constructor is called, it is passed a HTTP response object. Pass it back to :meth:`authenticate` to have it automatically detect which actions are required.
        :type response: requests.Response

        :param authorization: ``Authorization`` header value.
        :type authorization: str

        :rtype: str
        :returns: Authentication token, if the registry supports bearer tokens. Otherwise ``None``, and HTTP Basic auth is used (if the registry requires authentication).
        """
        if response is None:
            with warnings.catch_warnings():
                _ignore_warnings(self)
                response = self._sessions[0].get(self._base_url, verify=self._tlsverify)

        if response.ok:
            return None

        # pylint: disable=no-member
        if response.status_code != requests.codes.unauthorized:
            raise exceptions.DXFUnexpectedStatusCodeError(response.status_code,
                                                          requests.codes.unauthorized)

        if self._insecure:
            raise exceptions.DXFAuthInsecureError()

        parsed = www_authenticate.parse(response.headers['www-authenticate'])

        if username is not None and password is not None:
            headers = {
                'Authorization': 'Basic ' + base64.b64encode(_to_bytes_2and3(username + ':' + password)).decode('utf-8')
            }
        elif authorization is not None:
            headers = {
                'Authorization': authorization
            }
        else:
            headers = {}

        if 'bearer' in parsed:
            info = parsed['bearer']
            if actions and self._repo:
                scope = 'repository:' + self._repo + ':' + ','.join(actions)
            else:
                scope = info['scope']
            url_parts = list(urlparse.urlparse(info['realm']))
            query = urlparse.parse_qs(url_parts[4])
            query.update({
                'service': info['service'],
                'scope': scope
            })
            url_parts[4] = urlencode(query, True)
            url_parts[0] = 'https'
            if self._auth_host:
                url_parts[1] = self._auth_host
            auth_url = urlparse.urlunparse(url_parts)
            with warnings.catch_warnings():
                _ignore_warnings(self)
                r = self._sessions[0].get(auth_url, headers=headers, verify=self._tlsverify)
            _raise_for_status(r)
            self.token = r.json()['token']
            return self._token

        self._headers = headers
        return None

    def list_repos(self, batch_size=None, iterate=False):
        """
        List all repositories in the registry.

        :param batch_size: Number of repository names to ask the server for at a time.
        :type batch_size: int

        :param iterate: Whether to return iterator over the names or a list of all the names.
        :type iterate: bool

        :rtype: list or iterator of strings
        :returns: Repository names.
        """
        it = PaginatingResponse(self, '_base_request',
                                '_catalog', 'repositories',
                                params={'n': batch_size})
        return it if iterate else list(it)

    def __enter__(self):
        assert self._sessions
        session = requests.Session()
        session.__enter__()
        self._sessions.insert(0, session)
        return self

    def __exit__(self, *args):
        assert len(self._sessions) > 1
        session = self._sessions.pop(0)
        return session.__exit__(*args)

class DXF(DXFBase):
    """
    Class for operating on a Docker v2 repositories.
    """
    def __init__(self, host, repo, auth=None, insecure=False, auth_host=None, tlsverify=True):
        # pylint: disable=too-many-arguments
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param repo: Name of the repository to access on the registry. Typically this is of the form ``username/reponame`` but for your own registries you don't actually have to stick to that.
        :type repo: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DXF` object and a HTTP response object. It should call :meth:`DXFBase.authenticate` with a username, password and ``response`` before it returns.
        :type auth: function(dxf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool

        :param auth_host: Host to use for token authentication. If set, overrides host returned by then registry.
        :type auth_host: str

        :param tlsverify: When set to False, do not verify TLS certificate. When pointed to a `<ca bundle>.crt` file use this for TLS verification. See `requests.verify <http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification>`_ for more details.
        :type tlsverify: bool or str
        """
        super(DXF, self).__init__(host, auth, insecure, auth_host, tlsverify)
        self._repo = repo
        self._repo_path = (repo + '/') if repo else ''

    def _request(self, method, path, **kwargs):
        return super(DXF, self)._base_request(method,
                                              self._repo_path + path,
                                              **kwargs)

    def push_blob(self,
                  filename=None,
                  progress=None,
                  data=None, digest=None,
                  check_exists=True):
        # pylint: disable=too-many-arguments
        """
        Upload a file to the registry and return its (SHA-256) hash.

        The registry is content-addressable so the file's content (aka blob)
        can be retrieved later by passing the hash to :meth:`pull_blob`.

        :param filename: File to upload.
        :type filename: str

        :param data: Data to upload if ``filename`` isn't given. The data is uploaded in chunks and you must also pass ``digest``.
        :type data: Generator or iterator

        :param digest: Hash of the data to be uploaded in ``data``, if specified.
        :type digest: str (hex-encoded SHA-256, prefixed by ``sha256:``)

        :param progress: Optional function to call as the upload progresses. The function will be called with the hash of the file's content (or ``digest``), the blob just read from the file (or chunk from ``data``) and if ``filename`` is specified the total size of the file.
        :type progress: function(dgst, chunk, size)

        :param check_exists: Whether to check if a blob with the same hash already exists in the registry. If so, it won't be uploaded again.
        :type check_exists: bool

        :rtype: str
        :returns: Hash of file's content.
        """
        if filename is None:
            dgst = digest
        else:
            dgst = hash_file(filename)
        if check_exists:
            try:
                self._request('head', 'blobs/' + dgst)
                return dgst
            except requests.exceptions.HTTPError as ex:
                # pylint: disable=no-member
                if ex.response.status_code != requests.codes.not_found:
                    raise
        r = self._request('post', 'blobs/uploads/')
        upload_url = r.headers['Location']
        url_parts = list(urlparse.urlparse(upload_url))
        query = urlparse.parse_qs(url_parts[4])
        query.update({'digest': dgst})
        url_parts[4] = urlencode(query, True)
        url_parts[0] = 'http' if self._insecure else 'https'
        upload_url = urlparse.urlunparse(url_parts)
        if filename is None:
            data = _ReportingChunks(dgst, data, progress) if progress else data
            self._base_request('put', upload_url, data=data)
        else:
            with open(filename, 'rb') as f:
                data = _ReportingFile(dgst, f, progress) if progress else f
                self._base_request('put', upload_url, data=data)
        return dgst

    # pylint: disable=no-self-use
    def pull_blob(self, digest, size=False, chunk_size=None):
        """
        Download a blob from the registry given the hash of its content.

        :param digest: Hash of the blob's content (prefixed by ``sha256:``).
        :type digest: str

        :param size: Whether to return the size of the blob too.
        :type size: bool

        :param chunk_size: Number of bytes to download at a time. Defaults to 8192.
        :type chunk_size: int

        :rtype: iterator
        :returns: If ``size`` is falsey, a byte string iterator over the blob's content. If ``size`` is truthy, a tuple containing the iterator and the blob's size.
        """
        if chunk_size is None:
            chunk_size = 8192
        r = self._request('get', 'blobs/' + digest, stream=True)
        class Chunks(object):
            # pylint: disable=too-few-public-methods
            def __iter__(self):
                sha256 = hashlib.sha256()
                for chunk in r.iter_content(chunk_size):
                    sha256.update(chunk)
                    yield chunk
                dgst = 'sha256:' + sha256.hexdigest()
                if dgst != digest:
                    raise exceptions.DXFDigestMismatchError(dgst, digest)
        return (Chunks(), long(r.headers['content-length'])) if size else Chunks()

    def blob_size(self, digest):
        """
        Return the size of a blob in the registry given the hash of its content.

        :param digest: Hash of the blob's content (prefixed by ``sha256:``).
        :type digest: str

        :rtype: long
        :returns: Whether the blob exists.
        """
        r = self._request('head', 'blobs/' + digest)
        return long(r.headers['content-length'])

    def del_blob(self, digest):
        """
        Delete a blob from the registry given the hash of its content.

        :param digest: Hash of the blob's content (prefixed by ``sha256:``).
        :type digest: str
        """
        self._request('delete', 'blobs/' + digest)

    # For dtuf; highly unlikely anyone else will want this
    def make_manifest(self, *digests):
        layers = [{
            'mediaType': 'application/octet-stream',
            'size': self.blob_size(dgst),
            'digest': dgst
        } for dgst in digests]
        return json.dumps({
            'schemaVersion': 2,
            'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
            # V2 Schema 2 insists on a config dependency. We're just using the
            # registry as a blob store so to save us uploading extra blobs,
            # use the first layer.
            'config': {
                'mediaType': 'application/octet-stream',
                'size': layers[0]['size'],
                'digest': layers[0]['digest']
            },
            'layers': layers
        }, sort_keys=True)

    def set_manifest(self, alias, manifest_json):
        """
        Give a name (alias) to a manifest.

        :param alias: Alias name
        :type alias: str

        :param manifest_json: A V2 Schema 2 manifest JSON string
        :type digests: list
        """
        self._request('put',
                      'manifests/' + alias,
                      data=manifest_json,
                      headers={'Content-Type': _schema2_mimetype})

    def set_alias(self, alias, *digests):
        # pylint: disable=too-many-locals
        """
        Give a name (alias) to a set of blobs. Each blob is specified by
        the hash of its content.

        :param alias: Alias name
        :type alias: str

        :param digests: List of blob hashes (prefixed by ``sha256:``).
        :type digests: list of strings

        :rtype: str
        :returns: The registry manifest used to define the alias. You almost definitely won't need this.
        """
        try:
            manifest_json = self.make_manifest(*digests)
            self.set_manifest(alias, manifest_json)
            return manifest_json
        except requests.exceptions.HTTPError as ex:
            # pylint: disable=no-member
            if ex.response.status_code != requests.codes.bad_request:
                raise
            manifest_json = self.make_unsigned_manifest(alias, *digests)
            signed_json = _sign_manifest(manifest_json)
            self._request('put', 'manifests/' + alias, data=signed_json)
            return signed_json

    def get_manifest_and_response(self, alias):
        """
        Request the manifest for an alias and return the manifest and the
        response.

        :param alias: Alias name.
        :type alias: str

        :rtype: tuple
        :returns: Tuple containing the manifest as a string (JSON) and the `requests.Response <http://docs.python-requests.org/en/master/api/#requests.Response>`_
        """
        r = self._request('get',
                          'manifests/' + alias,
                          headers={'Accept': _schema2_mimetype + ', ' +
                                             _schema1_mimetype})
        return r.content.decode('utf-8'), r

    def get_manifest(self, alias):
        """
        Get the manifest for an alias

        :param alias: Alias name.
        :type alias: str

        :rtype: str
        :returns: The manifest as string (JSON)
        """
        manifest, _ = self.get_manifest_and_response(alias)
        return manifest

    def _get_alias(self, alias, manifest, verify, sizes, dcd, get_digest):
        # pylint: disable=too-many-arguments
        if alias:
            manifest, r = self.get_manifest_and_response(alias)
            dcd = r.headers['docker-content-digest']

        parsed_manifest = json.loads(manifest)

        if parsed_manifest['schemaVersion'] == 1:
            # https://github.com/docker/distribution/issues/1662#issuecomment-213101772
            # "A schema1 manifest should always produce the same image id but
            # defining the steps to produce directly from the manifest is not
            # straight forward."
            if get_digest:
                raise exceptions.DXFDigestNotAvailableForSchema1()

            r = _verify_manifest(manifest,
                                 parsed_manifest,
                                 dcd,
                                 verify)

            return [(dgst, self.blob_size(dgst)) for dgst in r] if sizes else r

        if dcd:
            method, expected_dgst = split_digest(dcd)
            hasher = hashlib.new(method)
            hasher.update(r.content)
            dgst = hasher.hexdigest()
            if dgst != expected_dgst:
                raise exceptions.DXFDigestMismatchError(
                    method + ':' + dgst,
                    method + ':' + expected_dgst)

        if get_digest:
            dgst = parsed_manifest['config']['digest']
            split_digest(dgst)
            return dgst

        r = []
        for layer in parsed_manifest['layers']:
            dgst = layer['digest']
            split_digest(dgst)
            r.append((dgst, layer['size']) if sizes else dgst)
        return r

    def get_alias(self,
                  alias=None,
                  manifest=None,
                  verify=True,
                  sizes=False,
                  dcd=None):
        # pylint: disable=too-many-arguments
        """
        Get the blob hashes assigned to an alias.

        :param alias: Alias name. You almost definitely will only need to pass this argument.
        :type alias: str

        :param manifest: If you previously obtained a manifest, specify it here instead of ``alias``. You almost definitely won't need to do this.
        :type manifest: str

        :param verify: (v1 schema only) Whether to verify the integrity of the alias definition in the registry itself. You almost definitely won't need to change this from the default (``True``).
        :type verify: bool

        :param sizes: Whether to return sizes of the blobs along with their hashes
        :type sizes: bool

        :param dcd: (if ``manifest`` is specified) The Docker-Content-Digest header returned when getting the manifest. If present, this is checked against the manifest.
        :type dcd: str

        :rtype: list
        :returns: If ``sizes`` is falsey, a list of blob hashes (strings) which are assigned to the alias. If ``sizes`` is truthy, a list of (hash,size) tuples for each blob.
        """
        return self._get_alias(alias, manifest, verify, sizes, dcd, False)

    def get_digest(self,
                   alias=None,
                   manifest=None,
                   verify=True,
                   dcd=None):
        """
        (v2 schema only) Get the hash of an alias's configuration blob.

        For an alias created using ``dxf``, this is the hash of the first blob
        assigned to the alias.

        For a Docker image tag, this is the same as
        ``docker inspect alias --format='{{.Id}}'``.

        :param alias: Alias name. You almost definitely will only need to pass this argument.
        :type alias: str

        :param manifest: If you previously obtained a manifest, specify it here instead of ``alias``. You almost definitely won't need to do this.
        :type manifest: str

        :param verify: (v1 schema only) Whether to verify the integrity of the alias definition in the registry itself. You almost definitely won't need to change this from the default (``True``).
        :type verify: bool

        :param dcd: (if ``manifest`` is specified) The Docker-Content-Digest header returned when getting the manifest. If present, this is checked against the manifest.
        :type dcd: str

        :rtype: str
        :returns: Hash of the alias's configuration blob.
        """
        return self._get_alias(alias, manifest, verify, False, dcd, True)

    def _get_dcd(self, alias):
        """
        Get the Docker-Content-Digest header for an alias.

        :param alias: Alias name.
        :type alias: str

        :rtype: str
        :returns: DCD header for the alias.
        """
        # https://docs.docker.com/registry/spec/api/#deleting-an-image
        # Note When deleting a manifest from a registry version 2.3 or later,
        # the following header must be used when HEAD or GET-ing the manifest
        # to obtain the correct digest to delete:
        # Accept: application/vnd.docker.distribution.manifest.v2+json
        return self._request(
            'head',
            'manifests/{}'.format(alias),
            headers={'Accept': _schema2_mimetype},
        ).headers.get('Docker-Content-Digest')

    def del_alias(self, alias):
        """
        Delete an alias from the registry. The blobs it points to won't be deleted. Use :meth:`del_blob` for that.

        .. Note::
           On private registry, garbage collection might need to be run manually; see:
           https://docs.docker.com/registry/garbage-collection/

        :param alias: Alias name.
        :type alias: str

        :rtype: list
        :returns: A list of blob hashes (strings) which were assigned to the alias.
        """
        dcd = self._get_dcd(alias)
        dgsts = self.get_alias(alias)
        self._request('delete', 'manifests/{}'.format(dcd))
        return dgsts

    def list_aliases(self, batch_size=None, iterate=False):
        """
        List all aliases defined in the repository.

        :param batch_size: Number of alias names to ask the server for at a time.
        :type batch_size: int

        :param iterate: Whether to return iterator over the names or a list of all the names.
        :type iterate: bool

        :rtype: list or iterator of strings
        :returns: Alias names.
        """
        it = PaginatingResponse(self, '_request',
                                'tags/list', 'tags',
                                params={'n': batch_size})
        return it if iterate else list(it)

    @classmethod
    def from_base(cls, base, repo):
        """
        Create a :class:`DXF` object which uses the same host, settings and
        session as an existing :class:`DXFBase` object.

        :param base: Existing :class:`DXFBase` object.
        :type base: :class:`DXFBase`

        :param repo: Name of the repository to access on the registry. Typically this is of the form ``username/reponame`` but for your own registries you don't actually have to stick to that.
        :type repo: str

        :returns: :class:`DXF` object which shares configuration and session with ``base`` but which can also be used to operate on the ``repo`` repository.
        :rtype: :class:`DXF`
        """
        # pylint: disable=protected-access
        r = cls(base._host, repo, base._auth, base._insecure, base._auth_host, base._tlsverify)
        r._token = base._token
        r._headers = base._headers
        r._sessions = [base._sessions[0]]
        return r

# v1 schema support functions below

    def make_unsigned_manifest(self, alias, *digests):
        return json.dumps({
            'schemaVersion': 1,
            'name': self._repo,
            'tag': alias,
            'fsLayers': [{'blobSum': dgst} for dgst in digests],
            'history': [{'v1Compatibility': '{}'} for dgst in digests]
        }, sort_keys=True)

_schema1_mimetype = 'application/vnd.docker.distribution.manifest.v1+json'

def _urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(_to_bytes_2and3(s)).rstrip(b'=').decode('utf-8')

def _pad64(s):
    return s + b'=' * (-len(s) % 4)

def _urlsafe_b64decode(s):
    return base64.urlsafe_b64decode(_pad64(_to_bytes_2and3(s)))

def _import_key(expkey):
    if expkey['kty'] != 'EC':
        raise exceptions.DXFUnexpectedKeyTypeError(expkey['kty'], 'EC')
    if expkey['crv'] != 'P-256':
        raise exceptions.DXFUnexpectedKeyTypeError(expkey['crv'], 'P-256')
    return jwk.JWK(kty='EC', crv='P-256', x=expkey['x'], y=expkey['y'])

def _sign_manifest(manifest_json):
    format_length = manifest_json.rfind('}')
    format_tail = manifest_json[format_length:]
    key = jwk.JWK.generate(kty='EC', crv='P-256')
    jwstoken = jws.JWS(manifest_json.encode('utf-8'))
    jkey = json.loads(key.export_public())
    # Docker expects 32 bytes for x and y
    jkey['x'] = _urlsafe_b64encode(_urlsafe_b64decode(jkey['x']).rjust(32, b'\0'))
    jkey['y'] = _urlsafe_b64encode(_urlsafe_b64decode(jkey['y']).rjust(32, b'\0'))
    jwstoken.add_signature(key, None, {
        'formatLength': format_length,
        'formatTail': _urlsafe_b64encode(format_tail)
    }, {
        'jwk': jkey,
        'alg': 'ES256'
    })
    return manifest_json[:format_length] + \
           ', "signatures": [' + jwstoken.serialize() + ']' + \
           format_tail

def _verify_manifest(content,
                     manifest,
                     content_digest=None,
                     verify=True):
    # pylint: disable=too-many-locals,too-many-branches

    # Adapted from https://github.com/joyent/node-docker-registry-client

    if verify or ('signatures' in manifest):
        signatures = []
        for sig in manifest['signatures']:
            protected64 = sig['protected']
            protected = _urlsafe_b64decode(protected64).decode('utf-8')
            protected_header = json.loads(protected)

            format_length = protected_header['formatLength']
            format_tail64 = protected_header['formatTail']
            format_tail = _urlsafe_b64decode(format_tail64).decode('utf-8')

            alg = sig['header']['alg']
            if alg.lower() == 'none':
                raise exceptions.DXFDisallowedSignatureAlgorithmError('none')
            if sig['header'].get('chain'):
                raise exceptions.DXFSignatureChainNotImplementedError()

            signatures.append({
                'alg': alg,
                'signature': sig['signature'],
                'protected64': protected64,
                'key': _import_key(sig['header']['jwk']),
                'format_length': format_length,
                'format_tail': format_tail
            })

        payload = content[:signatures[0]['format_length']] + \
                  signatures[0]['format_tail']
        payload64 = _urlsafe_b64encode(payload)
    else:
        payload = content

    if content_digest:
        method, expected_dgst = split_digest(content_digest)
        hasher = hashlib.new(method)
        hasher.update(payload.encode('utf-8'))
        dgst = hasher.hexdigest()
        if dgst != expected_dgst:
            raise exceptions.DXFDigestMismatchError(
                method + ':' + dgst,
                method + ':' + expected_dgst)

    if verify:
        for sig in signatures:
            jwstoken = jws.JWS()
            jwstoken.deserialize(json.dumps({
                'payload': payload64,
                'protected': sig['protected64'],
                'signature': sig['signature']
            }), sig['key'], sig['alg'])

    dgsts = []
    for layer in manifest['fsLayers']:
        dgst = layer['blobSum']
        split_digest(dgst)
        dgsts.append(dgst)
    return dgsts
