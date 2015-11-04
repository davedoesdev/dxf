This is in open development and definitely a work-in-progress!

Here are some rough notes.

The first module (`dxf/__main__.py`) is a command line tool to push and pull
files from a Docker v2 registry:

```
dxf auth <repo> <action>...             auth with DXF_USER/DXF_PASSWOWRD
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

I'm working on turning this into a proper module.

The second module (`dxf/dtuf.py`) is going to be registry bindings for
[The Update Framework](http://theupdateframework.com/). Basically, the idea is
to get TUF to use the first module so it can store its metadata and target files
in a Docker registry.

Again, this isn't finished or ready for use yet but any comments or suggestions
are gratefully accepted.
