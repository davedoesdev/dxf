import urlparse
import urllib
import base64
import hashlib
import json
import requests
import www_authenticate
import jws
import ecdsa
from exceptions import *

def _parse_www_auth(s):
    return www_authenticate.parse(s)['bearer']

def _num_to_base64(n):
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    if len(b) == 0:
        b.insert(0, 0)
    return base64.urlsafe_b64encode(b).rstrip('=')

def _base64_to_num(s):
    s = s.encode('utf-8')
    s = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    b = bytearray(s)
    m = len(b) - 1
    return sum((1 << ((m - bi)*8)) * bb for (bi, bb) in enumerate(b))

def _jwk_to_key(jwk):
    if jwk['kty'] != 'EC':
        raise DXFUnexpectedKeyTypeError(jwk['kty'], 'EC')
    if jwk['crv'] != 'P-256':
        raise DXFUnexpectedKeyTypeError(jwk['crv'], 'P-256')
    return ecdsa.VerifyingKey.from_public_point(
            ecdsa.ellipticcurve.Point(ecdsa.NIST256p.curve,
                                      _base64_to_num(jwk['x']),
                                      _base64_to_num(jwk['y'])),
            ecdsa.NIST256p)

def _pad64(s):
    return s + '=' * (-len(s) % 4)

def sha256_file(fname):
    sha256 = hashlib.sha256()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def _verify_manifest(content,
                     content_digest=None,
                     verify=True,
                     return_unsigned_manifest=False):
    # Adapted from https://github.com/joyent/node-docker-registry-client
    manifest = json.loads(content)

    if verify or ('signatures' in manifest):
        signatures = []
        for sig in manifest['signatures']:
            protected64 = sig['protected'].encode('utf-8')
            protected = base64.urlsafe_b64decode(_pad64(protected64))
            protected_header = json.loads(protected)

            format_length = protected_header['formatLength']
            format_tail64 = protected_header['formatTail'].encode('utf-8')
            format_tail = base64.urlsafe_b64decode(_pad64(format_tail64))

            alg = sig['header']['alg']
            if alg.lower() == 'none':
                raise DXFDisallowedSignatureAlgorithmError('none')
            if sig['header'].get('chain'):
                raise DXFChainNotImplementedError()

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
        payload64 = base64.urlsafe_b64encode(payload).rstrip('=')
    else:
        payload = content

    if content_digest:
        method, expected_dgst = content_digest.split(':')
        if method != 'sha256':
            raise DXFUnexpectedDigestMethodError(method, 'sha256')
        hasher = hashlib.new(method)
        hasher.update(payload)
        dgst = hasher.hexdigest()
        if dgst != expected_dgst:
            raise DXFDigestMismatchError(dgst, expected_dgst)

    if verify:
        for sig in signatures:
            data = {
                'key': sig['key'],
                'header': {
                    'alg': sig['alg']
                }
            }
            jws.header.process(data, 'verify')
            sig64 = sig['signature'].encode('utf-8')
            data['verifier']("%s.%s" % (sig['protected64'], payload64),
                             base64.urlsafe_b64decode(_pad64(sig64)),
                             sig['key'])

    if return_unsigned_manifest:
        return payload

    dgsts = []
    for layer in manifest['fsLayers']:
        method, dgst = layer['blobSum'].split(':')
        if method != 'sha256':
            raise DXFUnexpectedDigestMethodError(method, 'sha256')
        dgsts.append(dgst)
    return dgsts

def _raise_for_status(r):
    if r.status_code == requests.codes.unauthorized:
        raise DXFUnauthorizedError()
    r.raise_for_status()

class DXF(object):
    def __init__(self, host, repo, auth=None, insecure=False):
        self._repo_base_url = ('http' if insecure else 'https') + \
                              '://' + host + '/v2/'
        self._repo = repo
        self._repo_url = self._repo_base_url + repo + '/'
        self._token = None
        self._headers = {}
        self._auth = auth
        self._insecure = insecure

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self._headers = {
            'Authorization': 'Bearer ' + value
        }

    def _request(self, method, path, **kwargs):
        if path.startswith('/'):
            url = urlparse.urljoin(self._repo_base_url, path[1:])
        else:
            url = urlparse.urljoin(self._repo_url, path)
        r = getattr(requests, method)(url, headers=self._headers, **kwargs)
        if r.status_code == requests.codes.unauthorized and self._auth:
            token = self._token
            self._auth(self, r)
            if self._token != token:
                r = getattr(requests, method)(url, headers=self._headers, **kwargs)
        _raise_for_status(r)
        return r

    def auth_by_password(self, username, password, actions=[], response=None):
        if response is None:
            response = requests.get(self._repo_base_url)
        if response.status_code != requests.codes.unauthorized:
            raise DXFUnexpectedStatusCodeError(response.status_code,
                                               requests.codes.unauthorized)
        info = _parse_www_auth(response.headers['www-authenticate'])
        if actions:
            scope = 'repository:' + self._repo + ':' + ','.join(actions)
        else:
            scope = info['scope']    
        url_parts = list(urlparse.urlparse(info['realm']))
        query = urlparse.parse_qs(url_parts[4])
        query.update(
        {
            'service': info['service'],
            'scope': scope
        })
        url_parts[4] = urllib.urlencode(query, True)
        url_parts[0] = 'https'
        auth_url = urlparse.urlunparse(url_parts)
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(username + ':' + password)
        }
        r = requests.get(auth_url, headers=headers)
        _raise_for_status(r)
        self.token = r.json()['token']
        return self._token

    def push_blob(self, filename):
        dgst = sha256_file(filename)
        r = self._request('post', 'blobs/uploads/')
        upload_url = r.headers['Location']
        url_parts = list(urlparse.urlparse(upload_url))
        query = urlparse.parse_qs(url_parts[4])
        query.update({ 'digest': 'sha256:' + dgst })
        url_parts[4] = urllib.urlencode(query, True)
        url_parts[0] = 'http' if self._insecure else 'https'
        upload_url = urlparse.urlunparse(url_parts)
        with open(filename, 'rb') as f:
            r = self._request('put', upload_url, data=f)
        return dgst

    def pull_blob(self, digest):
        r = self._request('get', 'blobs/sha256:' + digest)
        sha256 = hashlib.sha256()
        for chunk in r.iter_content(8192):
            sha256.update(chunk)
            yield chunk
        dgst = sha256.hexdigest()
        if dgst != digest:
            raise DXFDigestMismatchError(dgst, digest)

    def del_blob(self, digest):
        self._request('delete', 'blobs/sha256:' + digest)

    def set_alias(self, alias, *digests, **kwargs):
        manifest = {
            'name': self._repo,
            'tag': alias,
            'fsLayers': [{ 'blobSum': 'sha256:' + dgst } for dgst in digests]
        }
        manifest_json = json.dumps(manifest)
        manifest64 = base64.urlsafe_b64encode(manifest_json).rstrip('=')
        format_length = manifest_json.rfind('}')
        format_tail = manifest_json[format_length:]
        protected_json = json.dumps({
            'formatLength': format_length,
            'formatTail': base64.urlsafe_b64encode(format_tail).rstrip('=')
        })
        protected64 = base64.urlsafe_b64encode(protected_json).rstrip('=')
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
            'signature': base64.urlsafe_b64encode(sig).rstrip('='),
            'protected': protected64
        }]
        signed_json = manifest_json[:format_length] + \
                        ', "signatures": ' + json.dumps(signatures) + \
                        format_tail
        #print _verify_manifest(signed_json)
        self._request('put', 'manifests/' + alias, data=signed_json)
        return manifest_json if kwargs.get('return_unsigned_manifest') \
               else signed_json

    def get_alias(self,
                  alias=None,
                  manifest=None,
                  verify=True,
                  return_unsigned_manifest=False):
        if alias:
            r = self._request('get', 'manifests/' + alias)
            manifest = r.content
            dcd = r.headers['docker-content-digest']
        else:
            dcd = None
        return _verify_manifest(manifest, dcd, verify, return_unsigned_manifest)

    def del_alias(self, alias):
        dgsts = self.get_alias(alias)
        self._request('delete', 'manifests/' + alias)
        return dgsts

    def list_aliases(self):
        return self._request('get', 'tags/list').json()['tags']

    def list_repos(self):
        return self._request('get', '/_catalog').json()['repositories']
