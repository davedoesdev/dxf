# dxf&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/dxf.png)](https://travis-ci.org/davedoesdev/dxf) [![Coverage Status](https://coveralls.io/repos/davedoesdev/dxf/badge.png?branch=master)](https://coveralls.io/r/davedoesdev/dxf?branch=master) [![PyPI version](https://badge.fury.io/py/python-dxf.png)](http://badge.fury.io/py/python-dxf)

Python module and command-line tool for storing and retrieving data in a Docker registry.

- Store arbitrary data (blob-store)
- Content addressable
- Set up named aliases to blobs
- Supports Docker registry schema v1 and v2
- Works on Python 2.7 and 3.4

Command-line example:

```shell
dxf push-blob fred/datalogger logger.dat @may15-readings
dxf pull-blob fred/datalogger @may15-readings
```

which is the same as:

```shell
dxf set-alias fred/datalogger may15-readings $(dxf push-blob fred/datalogger logger.dat)
dxf pull-blob fred/datalogger $(dxf get-alias fred/datalogger may15-readings)
```

Module example:

```python
from dxf import DXF

def auth(dxf, response):
    dxf.authenticate('fred', 'somepassword', response=response)

dxf = DXF('registry-1.docker.io', 'fred/datalogger', auth)

dgst = dxf.push_blob('logger.dat')
dxf.set_alias('may15-readings', dgst)

assert dxf.get_alias('may15-readings') == [dgst]

for chunk in dxf.pull_blob(dgst):
    sys.stdout.write(chunk)
```

## Usage

The module API is described [here](http://rawgit.davedoesdev.com/davedoesdev/dxf/master/docs/_build/html/index.html).

The `dxf` command-line tool uses the following environment variables:

- `DXF_HOST` - Host where Docker registry is running.
- `DXF_INSECURE` - Set this to `1` if you want to connect to the registry using
   `http` rather than `https` (which is the default).
- `DXF_USERNAME` - Name of user to authenticate as.
- `DXF_PASSWORD` - User's password.
- `DXF_AUTHORIZATION` - HTTP `Authorization` header value.
- `DXF_AUTH_HOST` - If set, always perform token authentication to this host, overriding the value returned by the registry.
- `DXF_PROGRESS` - If this is set to `1`, a progress bar is displayed (on standard error) during `push-blob` and `pull-blob`. If this is set to `0`, a progress bar is not displayed. If this is set to any other value, a progress bar is only displayed if standard error is a terminal.
- `DXF_BLOB_INFO` - Set this to `1` if you want `pull-blob` to prepend each blob with its digest and size (printed in plain text, separated by a space and followed by a newline).
- `DXF_CHUNK_SIZE` - Number of bytes `pull-blob` should download at a time. Defaults to 8192.
- `DXF_SKIPTLSVERIFY` - Skip TLS certificate verification

You can use the following options with `dxf`. Supply the name of the repository
you wish to work with in each case as the second argument.

-   `dxf push-blob <repo> <file> [@alias]`

    > Upload a file to the registry and optionally give it a name (alias).
    > The blob's hash is printed to standard output.

    > The hash or the alias can be used to fetch the blob later using
    > `pull-blob`.

-   `dxf pull-blob <repo> <hash>|<@alias>...`

    > Download blobs from the registry to standard output. For each blob you
    > can specify its hash (remember the registry is content-addressable)
    > or an alias you've given it (using `push-blob` or `set-alias`).

-   `dxf blob-size <repo> <hash>|<@alias>...`

    > Print the size of blobs in the registry. If you specify an alias, the
    > sum of all the blobs it points to will be printed.

-   `dxf del-blob <repo> <hash>|<@alias>...`

    > Delete blobs from the registry. If you specify an alias the blobs it
    > points to will be deleted, not the alias itself. Use `del-alias` for that.

-   `dxf set-alias <repo> <alias> <hash>|<file>...`

    > Give a name (alias) to a set of blobs. For each blob you can either
    > specify its hash (as printed by `get-blob`) or, if you have the blob's
    > contents on disk, its filename (including a path separator to
    > distinguish it from a hash).

-   `dxf get-alias <repo> <alias>...`

    > For each alias you specify, print the hashes of all the blobs it points
    > to.

-   `dxf del-alias <repo> <alias>...`

    > Delete each specified alias. The blobs they point to won't be deleted
    > (use `del-blob` for that), but their hashes will be printed.

-   `dxf list-aliases <repo>`

    > Print all the aliases defined in the repository.

-   `dxf list-repos [last_repo] [repos_per_request]`

    > Print the names of all the repositories in the registry. Not all versions
    > of the registry support this. For big repositories it is possible to use
    > pagination.

## Certificates

If your registry uses SSL with a self-issued certificate, you'll need to supply
`dxf` with a set of trusted certificate authorities.

Set the `REQUESTS_CA_BUNDLE` environment variable to the path of a PEM file
containing the trusted certificate authority certificates.

Both the module and command-line tool support `REQUESTS_CA_BUNDLE`.

## Authentication tokens

`dxf` automatically obtains Docker registry authentication tokens using your
`DXF_USERNAME` and `DXF_PASSWORD`, or `DXF_AUTHORIZATION`, environment variables
as necessary.

However, if you wish to override this then you can use the following command:

-   `dxf auth <repo> <action>...`

    > Authenticate to the registry using `DXF_USERNAME` and `DXF_PASSWORD`,
    > or `DXF_AUTHORIZATION`, and print the resulting token.

    > `action` can be `pull`, `push` or `*`.

If you assign the token to the `DXF_TOKEN` environment variable, for example:

`DXF_TOKEN=$(dxf auth fred/datalogger pull)`

then subsequent `dxf` commands will use the token without needing
`DXF_USERNAME` and `DXF_PASSWORD`, or `DXF_AUTHORIZATION`, to be set.

Note however that the token expires after a few minutes, after which `dxf` will
exit with `EACCES`.

## Docker Cloud authentication

You can use the [`dockercloud`](https://github.com/docker/python-dockercloud)
library to read authentication information from your Docker configuration file
and pass it to `dxf`:

```python
auth = 'Basic ' + dockercloud.api.auth.load_from_file()
dxf_obj = dxf.DXF('index.docker.io', repo='myorganization/myimage')
dxf_obj.authenticate(authorization=auth, actions=['pull'])
dxf_obj.list_aliases()
```

Thanks to [cyrilleverrier](https://github.com/cyrilleverrier) for this tip.

## Installation

```shell
pip install python-dxf
```

## Licence

[MIT](https://raw.github.com/davedoesdev/dxf/master/LICENCE)

## Tests

```shell
make test
```

## Lint

```shell
make lint
```

## Code Coverage

```shell
make coverage
```

[coverage.py](http://nedbatchelder.com/code/coverage/) results are available [here](http://rawgit.davedoesdev.com/davedoesdev/dxf/master/htmlcov/index.html).

Coveralls page is [here](https://coveralls.io/r/davedoesdev/dxf).
