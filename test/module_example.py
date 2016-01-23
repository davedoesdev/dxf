#!/usr/bin/env python

# Requires DOCKER_HUB_USERNAME, DOCKER_HUB_PASSWORD and DOCKER_HUB_REPO env vars
# $DOCKER_HUB_REPO should have been created on Docker Hub

# pylint: disable=wrong-import-position,superfluous-parens
# pylint: disable=redefined-outer-name,redefined-variable-type
import os
from os import path
import sys

sys.path.append(path.abspath(path.join(path.dirname(__file__), '..')))
os.chdir('/tmp')


from dxf import DXF

def auth(dxf, response):
    dxf.authenticate(os.environ['DOCKER_HUB_USERNAME'],
                     os.environ['DOCKER_HUB_PASSWORD'],
                     response=response)

dxf = DXF('registry-1.docker.io',
          os.environ['DOCKER_HUB_REPO'],
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
