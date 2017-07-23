#!/usr/bin/env python

# Requires DOCKER_REG_USERNAME, DOCKER_REG_PASSWORD and DOCKER_REG_REPO env vars
# Defaults to using the Docker Hub unless you specify DOCKER_REG_HOST env var
# If using the Docker Hub, create $DOCKER_REG_REPO first

# pylint: disable=wrong-import-position,superfluous-parens
# pylint: disable=redefined-outer-name
import os
from os import path
import sys

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))
os.chdir('/tmp')


from dxf import DXF

def auth(dxf, response):
    dxf.authenticate(os.environ['DOCKER_REG_USERNAME'],
                     os.environ['DOCKER_REG_PASSWORD'],
                     response=response)

dxf = DXF(os.environ.get('DOCKER_REG_HOST', 'registry-1.docker.io'),
          os.environ['DOCKER_REG_REPO'],
          auth)

with open('logger.dat', 'wb') as f:
    f.write(b'2015-05 11\n')

dgst = dxf.push_blob('logger.dat')
dxf.set_alias('may15-readings', dgst)

assert dxf.get_alias('may15-readings') == [dgst]

s = b''
for chunk in dxf.pull_blob(dgst):
    s += chunk
assert s == b'2015-05 11\n'
print(s)
