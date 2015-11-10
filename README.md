This is in open development and definitely a work-in-progress!

Here are some rough notes.

The first module (in `dxf/__main__.py`) is a command line tool to push and pull
files from a Docker v2 registry:

```
dxf auth <repo> <action>...             auth with DXF_USERNAME/DXF_PASSWOWRD
                                        and print token

dxf push-blob <repo> <file> [@alias]    upload blob from file, print hash
                                        and optionally set alias to it
dxf pull-blob <repo> <hash>|@<alias>... download blobs to stdout
dxf del-blob  <repo> <hash>|@<alias>... delete blobs

dxf set-alias <repo> <alias> <hash>|<file>...  point alias to hashes,
                                        print manifest. Use path with /
                                        in to calculate hash from file 
dxf get-alias <repo> <alias>...         print hashes aliases points to
dxf del-alias <repo> <alias>...         delete aliases and print hashes they
                                        were pointing to
```

Set `DXF_HOST` to the registry host (e.g. `registry-1.docker.io`).

When you auth, set `DXF_USERNAME` and `DXF_PASSWORD` and set the output of that
to `DXF_TOKEN` for subsequent commands. Note the tokens expire quite quickly.

The command line tool makes use of a second module (in `dxf/__init__.py`)
which exports a class, `DXF`, that can be used in other programs. For example:

```
dxf_obj = dxf.DXF('registry-1.docker.io', 'davedoesdev/rumptest')
dxf_obj.auth_by_password('xxxxx', 'xxxxxx', 'push', 'pull')
hash = dxf_obj.push_blob('node.bin')
dxf_obj.pull_blob(hash)
dxf_obj.del_blob(hash)
dxf_obj.set_alias('nodejs-latest', hash)
dxf_obj.get_alias('nodejs-latest')
dxf_obj.del_alias('nodejs-latest')
```

Again, this isn't finished or ready for use yet but any comments or suggestions
are gratefully accepted.
