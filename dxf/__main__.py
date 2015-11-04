# dxf auth <repo> <action>...             auth with DXF_USERNAME/DXF_PASSWOWRD
#                                         and print token

# dxf push-blob <repo> <file> [@alias]    upload blob from file, print hash
#                                         and optionally set alias to it
# dxf pull-blob <repo> <hash>|@<alias>... download blobs to stdout
# dxf del-blob  <repo> <hash>|@<alias>... delete blobs

# dxf set-alias <repo> <alias> <hash>|<file>...  point alias to hashes,
#                                         print manifest. Use path with /
#                                         in to calculate hash from file 
# dxf get-alias <repo> <alias>...         print hashes aliases points to
# dxf del-alias <repo> <alias>...         delete aliases and print hashes they
#                                         were pointing to

# pass repo host through DXF_HOST
# pass token through DXF_TOKEN

# examples:
# DXF_TOKEN=$(dxf auth davedoesdev/rumptest push pull)
# hash=$(dxf push-blob davedoesdev/rumptest node.bin)
# dxf set-alias davedoesdev/rumptest nodejs-latest $hash
# dxf pull-blob davedoesdev/rumptest $hash > /tmp/node.bin
# dxf del-blob davedoesdev/rumptest $hash
# dxf del-alias davedoesdev/rumptest nodejs-latest
# dxf pull-blob davedoesdev/rumptest $(dxf get-alias davedoesdev/rumptest nodejs-latest)
# dxf del-blob davedoesdev/rumptest $(dxf del-alias davedoesdev/rumptest nodejs-latest)


# - what about when auth times out? need to ensure error code is same (401, or some permission denied exit code)

# separate out functions, turn into module

import os
import argparse
import requests
import urlparse
import urllib
import base64
import sys
import hashlib
import json
import ecdsa
import jws as python_jws

repo_url = "https://" + os.environ["DXF_HOST"] + "/v2/"

parser = argparse.ArgumentParser()
parser.add_argument("op", choices=['auth',
                                   'push-blob',
                                   'pull-blob',
                                   'del-blob',
                                   'set-alias',
                                   'get-alias',
                                   'del-alias'])
parser.add_argument("repo")
parser.add_argument('args', nargs='+')
args = parser.parse_args()

class DXFUnexpectedStatusCodeError(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected

    def __str__(self):
        return 'expected status code %d, got %d' % (self.expected, self.got)

class DXFDigestMismatchError(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected

    def __str__(self):
        return 'expected digest %s, got %s' % (self.expected, self.got)

class DXFUnexpectedKeyTypeError(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected

    def __str__(self):
        return 'expected key type %s, got %s' % (self.expected, self.got)

class DXFDisallowedSignatureAlgorithmError(Exception):
    def __init__(self, alg):
        self.alg = alg

    def __str__(self):
        return 'disallowed signature algorithm: %s' % self.alg

class DXFChainNotImplementedError(Exception):
    def __str__(self):
        return 'verification with a cert chain is not implemented'

class DXFUnexpectedDigestMethodError(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected

    def __str__(self):
        return 'expected digest method %s, got %s' % (self.expected, self.got)

def parse_www_auth(s):
    props = [x.split('=') for x in s.split(' ')[1].split(',')]
    return dict([(y[0], y[1].strip('"')) for y in props])

def base64_to_num(s):
    s = s.encode('utf-8')
    s = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    b = bytearray(s)
    m = len(b) - 1
    return sum((1 << ((m - bi)*8)) * bb for (bi, bb) in enumerate(b))

def num_to_bytearray(n):
    return b

def num_to_base64(n):
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    if len(b) == 0:
        b.insert(0, 0)
    return base64.urlsafe_b64encode(b).rstrip('=')    

def sha256_file(fname):
    sha256 = hashlib.sha256()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()        

def jwk_to_key(jwk):
    if jwk['kty'] != 'EC':
        raise DXFUnexpectedKeyTypeError(jwk['kty'], 'EC')
    if jwk['crv'] != 'P-256':
        raise DXFUnexpectedKeyTypeError(jwk['crv'], 'P-256')
    # TODO: Switch to RSA?
    return ecdsa.VerifyingKey.from_public_point(
            ecdsa.ellipticcurve.Point(ecdsa.NIST256p.curve,
                                      base64_to_num(jwk['x']), 
                                      base64_to_num(jwk['y'])), 
            ecdsa.NIST256p)

def verify_manifest(manifest, content, content_digest):
    # Algorithm from https://github.com/joyent/node-docker-registry-client
    jws = {
        'signatures': []
    }
    for sig in manifest['signatures']:
        protected64 = sig['protected'].encode('utf-8')
        protected = base64.urlsafe_b64decode(protected64 + '=' * (-len(protected64) % 4))
        protected_header = json.loads(protected)
        format_length = protected_header['formatLength']
        format_tail = protected_header['formatTail'].encode('utf-8')
        format_tail += '=' * (-len(format_tail) % 4)
        format_tail = base64.urlsafe_b64decode(format_tail)
        jws_sig = {
            'header': {
                'alg': sig['header']['alg'],
                'chain': sig['header'].get('chain'),
            },
            'signature': sig['signature'],
            'protected64': protected64
        }
        if sig['header']['jwk']:
            jws_sig['header']['jwk'] = jwk_to_key(sig['header']['jwk'])
        jws['signatures'].append(jws_sig)
    jws['payload'] = content[:format_length] + format_tail
    payload64 = base64.urlsafe_b64encode(jws['payload']).rstrip('=')
    if content_digest:
        method, expected_dgst = content_digest.split(':')
        # TODO shouldn't really pass method to new - should check
        hasher = hashlib.new(method)
        hasher.update(jws['payload'])
        dgst = hasher.hexdigest()
        if dgst != expected_dgst:
            raise DXFDigestMismatchError(dgst, expected_dgst)
    #keys = []
    for jws_sig in jws['signatures']:
        if jws_sig['header']['alg'] == 'none':
            raise DXFDisallowedSignatureAlgorithmError('none')
        if jws_sig['header'].get('chain'):
            raise DXFChainNotImplementedError()
        data = {
            'key': jws_sig['header']['jwk'],
            'header': {
                'alg': jws_sig['header']['alg']
            }
        }
        python_jws.header.process(data, 'verify')
        sig = jws_sig['signature'].encode('utf-8')
        sig = base64.urlsafe_b64decode(sig + '=' * (-len(sig) % 4))
        data['verifier']("%s.%s" % (jws_sig['protected64'], payload64),
                         sig,
                         jws_sig['header']['jwk'])
        #keys.append(jws_sig['header']['jwk'])
    dgsts = []
    for layer in manifest['fsLayers']:
        method, dgst = layer['blobSum'].split(':')
        if method != 'sha256':
            raise DXFUnexpectedDigestMethodError(method, 'sha256')
        dgsts.append(dgst)
    return dgsts#, keys[0].to_pem()

def get_alias(repo, headers, name):
    download_url = repo_url + repo + '/manifests/' + name
    r = requests.get(download_url, headers=headers)
    r.raise_for_status()
    return verify_manifest(r.json(), r.content, r.headers['docker-content-digest'])

def set_alias(repo, headers, name, dgsts):
    dgsts = [sha256_file(dgst) if os.sep in dgst else dgst for dgst in dgsts]
    manifest = {
        'name': args.repo,
        'tag': name,
        'fsLayers': [{ 'blobSum': 'sha256:' + dgst } for dgst in dgsts]
    }
    manifest_json = json.dumps(manifest)
    manifest64 = base64.urlsafe_b64encode(manifest_json).rstrip('=')
    format_length = manifest_json.rfind('}')
    format_tail = manifest_json[format_length:]
    protected = {
        'formatLength': format_length,
        'formatTail': base64.urlsafe_b64encode(format_tail).rstrip('=')
    }
    protected64 = base64.urlsafe_b64encode(json.dumps(protected)).rstrip('=')
    #inkey = sys.stdin.read()
    #if inkey:
    #    key = ecdsa.SigningKey.from_pem(sys.stdin.read())
    #else:
    #    key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    point = key.privkey.public_key.point
    data = {
        'key': key,
        'header': {
            'alg': 'ES256'
        }
    }
    python_jws.header.process(data, 'sign')
    sig = data['signer']("%s.%s" % (protected64, manifest64), key)
    signatures = [{
        'header': {
            'jwk': {
                'kty': 'EC',
                'crv': 'P-256',
                'x': num_to_base64(point.x()),
                'y': num_to_base64(point.y())
            },
            'alg': 'ES256'
        },
        'signature': base64.urlsafe_b64encode(sig).rstrip('='),
        'protected': protected64
    }]
    manifest_json = manifest_json[:format_length] + \
                    ', "signatures": ' + json.dumps(signatures) + \
                    format_tail
    upload_url = repo_url + repo + '/manifests/' + name
    #print verify_manifest(json.loads(manifest_json), manifest_json, None)
    r = requests.put(upload_url, headers=headers, data=manifest_json)
    r.raise_for_status()
    return manifest_json

if args.op == "auth":
    r = requests.get(repo_url)
    if r.status_code != requests.codes.unauthorized:
        raise DXFUnexpectedStatusCodeError(r.status_code, requests.codes.unauthorized)
    info = parse_www_auth(r.headers['www-authenticate'])
    url_parts = list(urlparse.urlparse(info['realm']))
    query = urlparse.parse_qs(url_parts[4])
    query.update(
    {
        'service': info['service'],
        'scope': 'repository:' + args.repo + ':' + ','.join(args.args)
    })
    url_parts[4] = urllib.urlencode(query, True)
    url_parts[0] = 'https'
    auth_url = urlparse.urlunparse(url_parts)
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(
            os.environ['DXF_USERNAME'] + ':' + os.environ['DXF_PASSWORD'])
    }
    r = requests.get(auth_url, headers=headers)
    r.raise_for_status()
    print r.json()['token']

elif args.op == "push-blob":
    if len(args.args) < 1:
        parser.error('too few arguments')
    if len(args.args) > 2:
        parser.error('too many arguments')
    if len(args.args) == 2 and not args.args[1].startswith('@'):
        parser.error('invalid alias')
    dgst = sha256_file(args.args[0])
    headers = {
        'Authorization': 'Bearer ' + os.environ['DXF_TOKEN']
    }
    start_url = repo_url + args.repo + '/blobs/uploads/'
    r = requests.post(start_url, headers=headers)
    r.raise_for_status()
    upload_url = r.headers['Location']
    url_parts = list(urlparse.urlparse(upload_url))
    query = urlparse.parse_qs(url_parts[4])
    query.update(
    {
        'digest': 'sha256:' + dgst
    })
    url_parts[4] = urllib.urlencode(query, True)
    url_parts[0] = 'https'
    upload_url = urlparse.urlunparse(url_parts)
    with open(args.args[0], 'rb') as f:
        r = requests.put(upload_url, data=f, headers=headers)
    r.raise_for_status()
    if len(args.args) > 1:
        set_alias(args.repo, headers, args.args[1][1:], [dgst])
    print dgst

elif args.op == "pull-blob":
    headers = {
        'Authorization': 'Bearer ' + os.environ['DXF_TOKEN']
    }
    for name in args.args:
        if name.startswith('@'):
            hashes = get_alias(args.repo, headers, name[1:])
        else:
            hashes = [name]
        for h in hashes:
            download_url = repo_url + args.repo + '/blobs/sha256:' + h
            r = requests.get(download_url, headers=headers)
            r.raise_for_status()
            sha256 = hashlib.sha256()
            for chunk in r.iter_content(8192):
                sys.stdout.write(chunk)
                sha256.update(chunk)
            dgst = sha256.hexdigest()
            if dgst != h:
                raise DXFDigestMismatchError(dgst, h)

elif args.op == 'del-blob':
    headers = {
        'Authorization': 'Bearer ' + os.environ['DXF_TOKEN']
    }
    for name in args.args:
        if name.startswith('@'):
            hashes = get_alias(args.repo, headers, name[1:])
        else:
            hashes = [name]
        for h in hashes:
            delete_url = repo_url + args.repo + '/blobs/sha256:' + h
            r = requests.delete(delete_url, headers=headers)
            r.raise_for_status()

elif args.op == "set-alias":
    if len(args.args) < 2:
        parser.error('too few arguments')
    headers = {
        'Authorization': 'Bearer ' + os.environ['DXF_TOKEN']
    }
    sys.stdout.write(set_alias(args.repo, headers, args.args[0], args.args[1:]))
    # TODO: we need to use tuf somehow, or use some trusted key

elif args.op == "get-alias":
    headers = {
        'Authorization': 'Bearer ' + os.environ['DXF_TOKEN']
    }
    for name in args.args:
        for dgst in get_alias(args.repo, headers, name):
            print dgst

elif args.op == "del-alias":
    headers = {
        'Authorization': 'Bearer ' + os.environ['DXF_TOKEN']
    }
    for name in args.args:
        download_url = repo_url + args.repo + '/manifests/' + name
        r = requests.get(download_url, headers=headers)
        r.raise_for_status()
        dcd = r.headers['docker-content-digest']
        dgsts = verify_manifest(r.json(), r.content, dcd)
        delete_url = repo_url + args.repo + '/manifests/' + dcd
        r = requests.delete(delete_url, headers=headers)
        r.raise_for_status()
        for dgst in dgsts:
            print dgst

# txf - have set up repo by hand.
# but when set-alias, had to > repository/targets
# and then add the targets again (what do about delete? just empty array and add dir again?)
# how trust root key in tuf?
# we need to add integration with tuf client so it can pull and then check the file hashes against targets.json etc

