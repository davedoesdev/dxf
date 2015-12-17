"""
Module for accessing a Docker v2 Registry
"""

import base64
import hashlib
import json
import sys

try:
    import urllib.parse as urlparse
    from urllib.parse import urlencode
except ImportError:
    # pylint: disable=import-error,no-name-in-module,wrong-import-order
    from urllib import urlencode
    import urlparse

import requests
import www_authenticate
import ecdsa
import jws
# pylint: disable=wildcard-import
from dxf import exceptions

if sys.version_info < (3, 0):
    _binary_type = str
else:
    _binary_type = bytes
    # pylint: disable=redefined-builtin
    long = int

def _to_bytes_2and3(s):
    return s if isinstance(s, _binary_type) else s.encode('utf-8')

jws.utils.to_bytes_2and3 = _to_bytes_2and3
jws.algos.to_bytes_2and3 = _to_bytes_2and3

def _urlsafe_b64encode(s):
    return base64.urlsafe_b64encode(_to_bytes_2and3(s)).rstrip(b'=').decode('utf-8')

def _pad64(s):
    return s + b'=' * (-len(s) % 4)

def _urlsafe_b64decode(s):
    return base64.urlsafe_b64decode(_pad64(_to_bytes_2and3(s)))

def _num_to_base64(n):
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    # need to pad to 32 bytes
    while len(b) < 32:
        b.insert(0, 0)
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

def _base64_to_num(s):
    b = bytearray(_urlsafe_b64decode(s))
    m = len(b) - 1
    return sum((1 << ((m - bi)*8)) * bb for (bi, bb) in enumerate(b))

def _jwk_to_key(jwk):
    if jwk['kty'] != 'EC':
        raise exceptions.DXFUnexpectedKeyTypeError(jwk['kty'], 'EC')
    if jwk['crv'] != 'P-256':
        raise exceptions.DXFUnexpectedKeyTypeError(jwk['crv'], 'P-256')
    # pylint: disable=bad-continuation
    return ecdsa.VerifyingKey.from_public_point(
            ecdsa.ellipticcurve.Point(ecdsa.NIST256p.curve,
                                      _base64_to_num(jwk['x']),
                                      _base64_to_num(jwk['y'])),
            ecdsa.NIST256p)

def hash_bytes(buf):
    """
    Hash bytes using the same method the registry uses (currently SHA-256).

    :param filename: Bytes to hash
    :type filename: str

    :rtype: str
    :returns: Hex-encoded hash of file's content
    """
    sha256 = hashlib.sha256()
    sha256.update(buf)
    return sha256.hexdigest()

def hash_file(filename):
    """
    Hash a file using the same method the registry uses (currently SHA-256).

    :param filename: Name of file to hash
    :type filename: str

    :rtype: str
    :returns: Hex-encoded hash of file's content
    """
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def _verify_manifest(content,
                     content_digest=None,
                     verify=True):
    # pylint: disable=too-many-locals,too-many-branches

    # Adapted from https://github.com/joyent/node-docker-registry-client
    manifest = json.loads(content)

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
                'key': _jwk_to_key(sig['header']['jwk']),
                'format_length': format_length,
                'format_tail': format_tail
            })

        payload = content[:signatures[0]['format_length']] + \
                  signatures[0]['format_tail']
        payload64 = _urlsafe_b64encode(payload)
    else:
        payload = content

    if content_digest:
        method, expected_dgst = content_digest.split(':')
        if method != 'sha256':
            raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
        hasher = hashlib.new(method)
        hasher.update(payload.encode('utf-8'))
        dgst = hasher.hexdigest()
        if dgst != expected_dgst:
            raise exceptions.DXFDigestMismatchError(dgst, expected_dgst)

    if verify:
        for sig in signatures:
            data = {
                'key': sig['key'],
                'header': {
                    'alg': sig['alg']
                }
            }
            jws.header.process(data, 'verify')
            sig64 = sig['signature']
            data['verifier']("%s.%s" % (sig['protected64'], payload64),
                             _urlsafe_b64decode(sig64),
                             sig['key'])

    dgsts = []
    for layer in manifest['fsLayers']:
        method, dgst = layer['blobSum'].split(':')
        if method != 'sha256':
            raise exceptions.DXFUnexpectedDigestMethodError(method, 'sha256')
        dgsts.append(dgst)
    return dgsts

def _raise_for_status(r):
    # pylint: disable=no-member
    if r.status_code == requests.codes.unauthorized:
        raise exceptions.DXFUnauthorizedError()
    r.raise_for_status()

class _ReportingFile(object):
    def __init__(self, dgst, f, cb):
        self._dgst = dgst
        self._f = f
        self._cb = cb
        self._size = requests.utils.super_len(f)
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
        self._cb(self._dgst, chunk, self._size)
        return chunk

class DXFBase(object):
    # pylint: disable=too-many-instance-attributes
    """
    Class for communicating with a Docker v2 registry.
    Contains only operations which aren't related to repositories.
    """
    def __init__(self, host, auth=None, insecure=False):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DXFBase` object and a HTTP response object. It should call :meth:`auth_by_password` with a username, password and ``response`` before it returns.
        :type auth: function(dxf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool
        """
        self._base_url = ('http' if insecure else 'https') + '://' + host + '/v2/'
        self._auth = auth
        self._insecure = insecure
        self._token = None
        self._headers = {}
        self._repo = None

    @property
    def token(self):
        """
        str: Authentication token. This will be obtained automatically when
        you call :meth:`auth_by_password`. If you've obtained a token
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
        url = urlparse.urljoin(self._base_url, path)
        r = getattr(requests, method)(url, headers=self._headers, **kwargs)
        # pylint: disable=no-member
        if r.status_code == requests.codes.unauthorized and self._auth:
            headers = self._headers
            self._auth(self, r)
            if self._headers != headers:
                r = getattr(requests, method)(url, headers=self._headers, **kwargs)
        _raise_for_status(r)
        return r

    def auth_by_password(self, username, password, actions=None, response=None):
        """
        Authenticate to the registry using a username and password.

        :param username: User name to authenticate as.
        :type username: str

        :param password: User's password.
        :type password: str

        :param actions: If you know which types of operation you need to make on the registry, specify them here. Valid actions are ``pull``, ``push`` and ``*``.
        :type actions: list

        :param response: When the ``auth`` function you passed to :class:`DXFBase`'s constructor is called, it is passed a HTTP response object. Pass it back to :meth:`auth_by_password` to have it automatically detect which actions are required.
        :type response: requests.Response

        :rtype: str
        :returns: Authentication token, if the registry supports bearer tokens. Otherwise ```None```, and HTTP Basic auth is used.
        """
        if self._insecure:
            raise exceptions.DXFAuthInsecureError()
        if response is None:
            response = requests.get(self._base_url)
        # pylint: disable=no-member
        if response.status_code != requests.codes.unauthorized:
            raise exceptions.DXFUnexpectedStatusCodeError(response.status_code,
                                                          requests.codes.unauthorized)
        parsed = www_authenticate.parse(response.headers['www-authenticate'])
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(_to_bytes_2and3(username + ':' + password)).decode('utf-8')
        }
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
            auth_url = urlparse.urlunparse(url_parts)
            r = requests.get(auth_url, headers=headers)
            _raise_for_status(r)
            self.token = r.json()['token']
            return self._token
        else:
            self._headers = headers

    def list_repos(self):
        """
        List all repositories in the registry.

        :rtype: list
        :returns: List of repository names.
        """
        return self._base_request('get', '_catalog').json()['repositories']

class DXF(DXFBase):
    """
    Class for operating on a Docker v2 repositories.
    """
    def __init__(self, host, repo, auth=None, insecure=False):
        """
        :param host: Host name of registry. Can contain port numbers. e.g. ``registry-1.docker.io``, ``localhost:5000``.
        :type host: str

        :param repo: Name of the repository to access on the registry. Typically this is of the form ``username/reponame`` but for your own registries you don't actually have to stick to that.
        :type repo: str

        :param auth: Authentication function to be called whenever authentication to the registry is required. Receives the :class:`DXF` object and a HTTP response object. It should call :meth:`DXFBase.auth_by_password` with a username, password and ``response`` before it returns.
        :type auth: function(dxf_obj, response)

        :param insecure: Use HTTP instead of HTTPS (which is the default) when connecting to the registry.
        :type insecure: bool
        """
        super(DXF, self).__init__(host, auth, insecure)
        self._repo = repo

    def _request(self, method, path, **kwargs):
        return super(DXF, self)._base_request(method, self._repo + '/' + path, **kwargs)

    def push_blob(self, filename, progress=None):
        """
        Upload a file to the registry and return its (SHA-256) hash.

        The registry is content-addressable so the file's content (aka blob)
        can be retrieved later by passing the hash to :meth:`pull_blob`.

        :param filename: File to upload.
        :type filename: str

        :rtype: str
        :returns: Hash of file's content.
        """
        dgst = hash_file(filename)
        try:
            self._request('head', 'blobs/sha256:' + dgst)
            return dgst
        except requests.exceptions.HTTPError as ex:
            # pylint: disable=no-member
            if ex.response.status_code != requests.codes.not_found:
                raise
        r = self._request('post', 'blobs/uploads/')
        upload_url = r.headers['Location']
        url_parts = list(urlparse.urlparse(upload_url))
        query = urlparse.parse_qs(url_parts[4])
        query.update({'digest': 'sha256:' + dgst})
        url_parts[4] = urlencode(query, True)
        url_parts[0] = 'http' if self._insecure else 'https'
        upload_url = urlparse.urlunparse(url_parts)
        with open(filename, 'rb') as f:
            self._base_request('put',
                               upload_url,
                               data=_ReportingFile(dgst, f, progress) if progress else f)
        return dgst

    # pylint: disable=no-self-use
    def pull_blob(self, digest, size=False):
        """
        Download a blob from the registry given the hash of its content.

        :param digest: Hash of the blob's content.
        :type digest: str

        :param size: Whether to return the size of the blob too
        :type size: bool

        :rtype: iterator
        :returns: If ```size``` is falsey, a byte string iterator over the file's content. If ```size``` is truthy, a tuple containing the iterator and the blob's size.
        """
        r = self._request('get', 'blobs/sha256:' + digest, stream=True)
        # pylint: disable=too-few-public-methods
        class Chunks(object):
            def __iter__(self):
                sha256 = hashlib.sha256()
                for chunk in r.iter_content(8192):
                    sha256.update(chunk)
                    yield chunk
                dgst = sha256.hexdigest()
                if dgst != digest:
                    raise exceptions.DXFDigestMismatchError(dgst, digest)
        return (Chunks(), long(r.headers['content-length'])) if size else Chunks()

    def blob_size(self, digest):
        """
        Return the size of a blob in the registry given the hash of its content.

        :param digest: Hash of the blob's content.
        :type digest: str

        :rtype: long
        :returns: Whether the blob exists.
        """
        r = self._request('head', 'blobs/sha256:' + digest)
        return long(r.headers['content-length'])

    def del_blob(self, digest):
        """
        Delete a blob from the registry given the hash of its content.

        Note that the registry doesn't support deletes yet so expect an error.

        :param digest: Hash of the blob's content.
        :type digest: str
        """
        self._request('delete', 'blobs/sha256:' + digest)

    # For dtuf; highly unlikely anyone else will want this
    def make_unsigned_manifest(self, alias, *digests):
        return json.dumps({
            'name': self._repo,
            'tag': alias,
            'fsLayers': [{'blobSum': 'sha256:' + dgst} for dgst in digests],
            'history': [{'v1Compatibility': '{}'} for dgst in digests]
        }, sort_keys=True)

    def set_alias(self, alias, *digests):
        # pylint: disable=too-many-locals
        """
        Give a name (alias) to a set of blobs. Each blob is specified by
        the hash of its content.

        :param alias: Alias name
        :type alias: str

        :param digests: List of blob hashes (strings).
        :type digests: list

        :rtype: str
        :returns: The registry manifest used to define the alias. You almost definitely won't need this.
        """
        manifest_json = self.make_unsigned_manifest(alias, *digests)
        manifest64 = _urlsafe_b64encode(manifest_json)
        format_length = manifest_json.rfind('}')
        format_tail = manifest_json[format_length:]
        protected_json = json.dumps({
            'formatLength': format_length,
            'formatTail': _urlsafe_b64encode(format_tail)
        })
        protected64 = _urlsafe_b64encode(protected_json)
        key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        point = key.privkey.public_key.point
        data = {
            'key': key,
            'header': {
                'alg': 'ES256'
            }
        }
        jws.header.process(data, 'sign')
        sig = data['signer']("%s.%s" % (protected64, manifest64), key)
        signatures = [{
            'header': {
                'jwk': {
                    'kty': 'EC',
                    'crv': 'P-256',
                    'x': _num_to_base64(point.x()),
                    'y': _num_to_base64(point.y())
                },
                'alg': 'ES256'
            },
            'signature': _urlsafe_b64encode(sig),
            'protected': protected64
        }]
        signed_json = manifest_json[:format_length] + \
                        ', "signatures": ' + json.dumps(signatures) + \
                        format_tail
        #print _verify_manifest(signed_json)
        self._request('put', 'manifests/' + alias, data=signed_json)
        return signed_json

    def get_alias(self,
                  alias=None,
                  manifest=None,
                  verify=True,
                  sizes=False):
        """
        Get the blob hashes assigned to an alias.

        :param alias: Alias name. You almost definitely will only need to pass this argument.
        :type alias: str

        :param manifest: If you previously obtained a manifest, specify it here instead of ``alias``. You almost definitely won't need to do this.
        :type manifest: str

        :param verify: Whether to verify the integrity of the alias definition in the registry itself. You almost definitely won't need to change this from the default (``True``).
        :type verify: bool

        :param sizes: Whether to return sizes of the blobs along with their hashes
        :type sizes: bool

        :rtype: list
        :returns: If ```sizes``` is falsey, a list of blob hashes (strings) which are assigned to the alias. If ```sizes``` is truthy, a list of (hash,size) tuples for each blob.
        """
        if alias:
            r = self._request('get', 'manifests/' + alias)
            manifest = r.content.decode('utf-8')
            dcd = r.headers['docker-content-digest']
        else:
            dcd = None
        dgsts = _verify_manifest(manifest, dcd, verify)
        if not sizes:
            return dgsts
        # V2 Schema 2 will put the size in the manifest, so we wouldn't need
        # to make separate requests to get the size of each blob.
        # Instead, we could get _verify_manifest to return them.
        return [(dgst, self.blob_size(dgst)) for dgst in dgsts]

    def del_alias(self, alias):
        """
        Delete an alias from the registry. The blobs it points to won't be deleted. Use :meth:`del_blob` for that.

        Note that the registry doesn't support deletes yet so expect an error.

        :param alias: Alias name.
        :type alias: str

        :rtype: list
        :returns: A list of blob hashes (strings) which were assigned to the alias.
        """
        dgsts = self.get_alias(alias)
        self._request('delete', 'manifests/' + alias)
        return dgsts

    def list_aliases(self):
        """
        List all aliases defined in the repository.

        :rtype: list
        :returns: List of alias names (strings).
        """
        return self._request('get', 'tags/list').json()['tags']
