import os
import argparse
import sys
import dxf
import dxf.exceptions

#pylint: disable=wrong-import-position,wrong-import-order,superfluous-parens

def auth(dxf_obj, response):
    # pylint: disable=redefined-outer-name
    username = os.environ.get('DXF_USERNAME')
    password = os.environ.get('DXF_PASSWORD')
    if username and password:
        dxf_obj.auth_by_password(username, password, response=response)

choices = ['auth',
           'push-blob',
           'pull-blob',
           'del-blob',
           'set-alias',
           'get-alias',
           'del-alias',
           'list-aliases',
           'list-repos']

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='op')
for c in choices:
    sp = subparsers.add_parser(c)
    if c != 'list-repos':
        sp.add_argument("repo")
        sp.add_argument('args', nargs='*')

# pylint: disable=redefined-variable-type
args = parser.parse_args()
if args.op == 'list-repos':
    dxf_obj = dxf.DXFBase(os.environ['DXF_HOST'],
                          auth,
                          os.environ.get('DXF_INSECURE'))
else:
    dxf_obj = dxf.DXF(os.environ['DXF_HOST'],
                      args.repo,
                      auth,
                      os.environ.get('DXF_INSECURE'))

def _flatten(l):
    return [item for sublist in l for item in sublist]

def doit():
    # pylint: disable=too-many-branches
    if args.op == "auth":
        print(dxf_obj.auth_by_password(os.environ['DXF_USERNAME'],
                                       os.environ['DXF_PASSWORD'],
                                       actions=args.args))
        return

    token = os.environ.get('DXF_TOKEN')
    if token:
        dxf_obj.token = token

    # pylint: disable=no-member

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
        print(dgst)

    elif args.op == "pull-blob":
        if len(args.args) == 0:
            dgsts = dxf_obj.get_alias(manifest=sys.stdin.read())
        else:
            dgsts = _flatten([dxf_obj.get_alias(name[1:])
                              if name.startswith('@') else [name]
                              for name in args.args])
        for dgst in dgsts:
            for chunk in dxf_obj.pull_blob(dgst):
                sys.stdout.write(chunk)

    elif args.op == 'del-blob':
        if len(args.args) == 0:
            dgsts = dxf_obj.get_alias(manifest=sys.stdin.read())
        else:
            dgsts = _flatten([dxf_obj.del_alias(name[1:])
                              if name.startswith('@') else [name]
                              for name in args.args])
        for dgst in dgsts:
            dxf_obj.del_blob(dgst)

    elif args.op == "set-alias":
        if len(args.args) < 2:
            parser.error('too few arguments')
        dgsts = [dxf.sha256_file(dgst) if os.sep in dgst else dgst
                 for dgst in args.args[1:]]
        sys.stdout.write(dxf_obj.set_alias(args.args[0], *dgsts))

    elif args.op == "get-alias":
        if len(args.args) == 0:
            dgsts = dxf_obj.get_alias(manifest=sys.stdin.read())
        else:
            dgsts = _flatten([dxf_obj.get_alias(name) for name in args.args])
        for dgst in dgsts:
            print(dgst)

    elif args.op == "del-alias":
        for name in args.args:
            for dgst in dxf_obj.del_alias(name):
                print(dgst)

    elif args.op == 'list-aliases':
        if len(args.args) > 0:
            parser.error('too many arguments')
        for name in dxf_obj.list_aliases():
            print(name)

    elif args.op == 'list-repos':
        for name in dxf_obj.list_repos():
            print(name)

try:
    doit()
except dxf.exceptions.DXFUnauthorizedError:
    import traceback
    traceback.print_exc()
    import errno
    exit(errno.EACCES)
