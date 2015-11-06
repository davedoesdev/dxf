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
# DXF_TOKEN=$(dxf auth davedoesdev/rumptest '*')
# hash=$(dxf push-blob davedoesdev/rumptest node.bin)
# dxf set-alias davedoesdev/rumptest nodejs-latest $hash
# dxf push-blob davedoesdev/rumptest @nodejs-latest
# dxf pull-blob davedoesdev/rumptest $hash > /tmp/node.bin
# dxf pull-blob davedoesdev/rumptest @nodejs-latest > /tmp/node.bin
# dxf del-blob davedoesdev/rumptest $hash
# dxf del-blob davedoesdev/rumptest @nodejs-latest
# dxf del-alias davedoesdev/rumptest nodejs-latest

# - what about when auth times out? need to ensure error code is same (401, or some permission denied exit code)


import os
import dxf
import dxf.exceptions

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

def auth(dxf_obj, action):
    username = os.environ.get('DXF_USERNAME')
    password = os.environ.get('DXF_PASSWORD')
    if username and password:
        dxf_obj.auth_by_password(username, password, action)

dxf_obj = dxf.DXF(os.environ['DXF_HOST'], args.repo, auth)

def doit():
    if args.op == "auth":
        print dxf_obj.auth_by_password(os.environ['DXF_USERNAME'],
                                       os.environ['DXF_PASSWORD'],
                                       *args.args)
        return

    token = os.environ.get('DXF_TOKEN')
    if token:
        dxf_obj.token = token

    if args.op == "push-blob":
        if len(args.args) < 1:
            parser.error('too few arguments')
        if len(args.args) > 2:
            parser.error('too many arguments')
        if len(args.args) == 2 and not args.args[1].startswith('@'):
            parser.error('invalid alias')
        dgst = dxf_obj.push_blob(args.args[0])
        if len(args.args) == 2:
            dxf_obj.set_alias(args.args[1][1:], dgst)
        print dgst

    elif args.op == "pull-blob":
        for name in args.args:
            if name.startswith('@'):
                dgsts = dxf_obj.get_alias(name[1:])
            else:
                dgsts = [name]
            for dgst in dgsts:
                for chunk in dxf_obj.pull_blob(dgst):
                    sys.stdout.write(chunk)

    elif args.op == 'del-blob':
        for name in args.args:
            if name.startswith('@'):
                dgsts = dxf_obj.get_alias(name[1:])
            else:
                dgsts = [name]
            for dgst in dgsts:
                dxf_obj.del_blob(dgst)

    elif args.op == "set-alias":
        if len(args.args) < 2:
            parser.error('too few arguments')
        dgsts = [dxf.sha256_file(dgst) if os.sep in dgst else dgst
                 for dgst in args.args[1:]]
        sys.stdout.write(dxf_obj.set_alias(args.args[0], *dgsts))

    elif args.op == "get-alias":
        for name in args.args:
            for dgst in dxf_obj.get_alias(name):
                print dgst

    elif args.op == "del-alias":
        for name in args.args:
            for dgst in dxf_obj.del_alias(name):
                print dgst

try:
    doit()
except dxf.exceptions.DXFUnauthorizedError:
    import traceback
    traceback.print_exc()
    import errno
    exit(errno.EACCES)
