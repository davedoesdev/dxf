#!/bin/bash
# Run module_example.py against a local registry using HTTPS and basic auth

set -e
cd "$(dirname "$0")"

# Make sure certificate is created
make -C .. test/registry/registry.pem

# Note: test/auth/htpasswd was created using instructions from
# https://docs.docker.com/registry/deploying/#/native-basic-auth

# Stop existing registry
./remove_container.sh dxf_registry

# On exit, stop registry
cleanup() {
    trap - EXIT
    ./remove_container.sh dxf_registry
}

trap cleanup EXIT

# Start registry
docker run -d -p 5000:5000 --name dxf_registry \
           -v "$PWD/registry:/registry" \
           -v "$PWD/auth:/auth" \
           -e REGISTRY_HTTP_TLS_CERTIFICATE=/registry/registry.pem \
           -e REGISTRY_HTTP_TLS_KEY=/registry/registry.key \
           -e REGISTRY_AUTH=htpasswd \
           -e 'REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm' \
           -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
           registry:2

# Set environment variables
export DOCKER_REG_HOST=localhost:5000
export DOCKER_REG_USERNAME=fred
export DOCKER_REG_PASSWORD='!WordPass0$'
export DOCKER_REG_REPO=fred/datalogger
export REQUESTS_CA_BUNDLE="$PWD/ca.pem"

# Run the example
./module_example.py
