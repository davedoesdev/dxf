export PYTHONPATH=.
fixtures = test/fixtures/blob1 test/fixtures/blob2
registry_certs = test/registry/registry.key test/registry/registry.pem
auth_certs = test/auth/auth.key test/auth/auth.pem
bundle = test/bundle.pem

all: lint test

docs: build_docs

.PHONY: build_docs
build_docs:
	cd docs && make html
	pandoc -t rst README.md | sed -e '1,1s/^[^\\]*//' -e '2d' > README.rst

.PHONY: lint
lint:
	pylint dxf test/*.py

test: run_test

.PHONY: run_test
run_test: $(fixtures) $(bundle)
run_test: export HASH1=$(shell sha256sum test/fixtures/blob1 | cut -d ' ' -f1)
run_test: export HASH2=$(shell sha256sum test/fixtures/blob2 | cut -d ' ' -f1)
run_test: export REQUESTS_CA_BUNDLE=test/bundle.pem
run_test:
	py.test $(test_args) -s

coverage: run_coverage

.PHONY: run_coverage
run_coverage: test_args=--cov=dxf/__init__.py --cov-report=html --cov-report=term --cov-fail-under=90
run_coverage: run_test

test/fixtures/blob1:
	dd if=/dev/urandom of=$@ bs=1M count=1

test/fixtures/blob2:
	dd if=/dev/urandom of=$@ bs=1M count=2

$(registry_certs):
	openssl req -newkey rsa:4096 -nodes -sha256 -keyout test/registry/registry.key -subj "/CN=localhost/" -x509 -days 365 -out test/registry/registry.pem

$(auth_certs):
	openssl req -newkey rsa:4096 -nodes -sha256 -keyout test/auth/auth.key -subj "/CN=localhost/" -x509 -days 365 -out test/auth/auth.pem

$(bundle): $(registry_certs) $(auth_certs)
	cat test/registry/registry.pem test/auth/auth.pem > $@

.PHONY: travis_test
travis_test: lint coverage
