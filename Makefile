SHELL := /bin/bash

export PYTHONPATH := $(PYTHONPATH):.

fixtures = test/fixtures/blob1 \
           test/fixtures/blob2 \
           test/fixtures/blob3 \
           test/fixtures/blob4
registry_certs = test/registry/registry.key test/registry/registry.pem
auth_certs = test/auth/auth.key test/auth/auth.pem
ca_certs = test/ca.key test/ca.pem

name=$(shell grep name= setup.py | awk -F "'" '{print $$2}')
version=$(shell grep version= setup.py | awk -F "'" '{print $$2}')

all: lint typecheck test

docs: build_docs

.PHONY: build_docs
build_docs:
	cd docs && make html
	pandoc -t rst README.md | sed -e '1,1s/^[^|]*//' -e '2d' > README.rst

.PHONY: lint
lint:
	pylint dxf test/*.py

test: $(fixtures) run_test

.PHONY: run_test
run_test: $(registry_certs) $(auth_certs) $(ca_certs)
run_test: export HASH1=sha256:$(shell sha256sum test/fixtures/blob1 | cut -d ' ' -f1)
run_test: export HASH2=sha256:$(shell sha256sum test/fixtures/blob2 | cut -d ' ' -f1)
run_test: export HASH3=sha256:$(shell sha256sum test/fixtures/blob3 | cut -d ' ' -f1)
run_test: export HASH4=sha256:$(shell sha256sum test/fixtures/blob4 | cut -d ' ' -f1)
run_test: export REQUESTS_CA_BUNDLE=test/ca.pem
run_test:
	py.test -s $(test_args) test #/test_cli.py -m onlytest
	#py.test -s $(test_args) test -m record #-m onlytest

coverage: $(fixtures) run_coverage

.PHONY: run_coverage
run_coverage: test_args=--cov=dxf --cov-report=html --cov-report=term
run_coverage: run_test

test/fixtures/blob1:
	dd if=/dev/urandom of=$@ bs=1M count=1
test/fixtures/blob2:
	dd if=/dev/urandom of=$@ bs=1M count=2
test/fixtures/blob3:
	dd if=/dev/urandom of=$@ bs=1M count=2
test/fixtures/blob4:
	dd if=/dev/urandom of=$@ bs=1M count=2

$(ca_certs):
	openssl req -new -x509 -nodes -newkey rsa:4096 -keyout test/ca.key -out test/ca.pem -days 365 -subj "/CN=dxf CA/"

$(registry_certs): $(ca_certs)
	openssl req -new -nodes -newkey rsa:4096 -sha256 -keyout test/registry/registry.key -subj "/CN=localhost/" | openssl x509 -req -extfile <(echo subjectAltName=DNS:localhost) -days 365 -CA test/ca.pem -CAkey test/ca.key -CAcreateserial -out test/registry/registry.pem

$(auth_certs): $(ca_certs)
	openssl req -new -nodes -newkey rsa:4096 -sha256 -keyout test/auth/auth.key -subj "/CN=localhost/" | openssl x509 -req -extfile <(echo subjectAltName=DNS:localhost) -days 365 -CA test/ca.pem -CAkey test/ca.key -CAcreateserial -out test/auth/auth.pem

.PHONY: delete_certs
delete_certs:
	rm $(registry_certs) $(auth_certs) $(ca_certs)

dist: make_dist

.PHONY: make_dist
make_dist:
	python3 setup.py sdist
	python3 setup.py bdist_wheel --universal

upload:
	python3 -m twine upload dist/$(name)-$(version)*

.PHONY: typecheck
typecheck:
	mypy dxf
