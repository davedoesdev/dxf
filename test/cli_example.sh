#!/bin/bash
set -e
HERE="$(cd $(dirname "$0"); echo "$PWD")"
cd /tmp

dxf() {
  PYTHONPATH="$HERE/.." python -m dxf "$@"
}

cleanup() {
    trap - EXIT
    "$HERE/remove_container.sh" dxf_registry
}
trap cleanup EXIT
docker run -d -p 5000:5000 --name dxf_registry registry:2

export DXF_HOST=localhost:5000
export DXF_INSECURE=1

echo '2015-05 11' > logger.dat


dxf push-blob fred/datalogger logger.dat @may15-readings
dxf pull-blob fred/datalogger @may15-readings

dxf set-alias fred/datalogger may15-readings $(dxf push-blob fred/datalogger logger.dat)
dxf pull-blob fred/datalogger $(dxf get-alias fred/datalogger may15-readings)
