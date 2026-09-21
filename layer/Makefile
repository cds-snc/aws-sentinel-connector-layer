.PHONY: build fmt install lint migrations test fmt-ci lint-ci install-dev verify-abi

# The compiled dependencies in this layer must match the Python the Lambda
# actually runs. terraform-modules//sentinel_forwarder hard-codes
# runtime = "python3.13" and does not expose it as a variable, so consumers
# cannot correct a mismatch from their side.
#
# A bare `pip3 install` builds for whichever interpreter the CI runner happens
# to ship — 3.12 on ubuntu-latest — and that is how layer 266 came to contain
# _cffi_backend.cpython-312-*.so. python3.13 looks only for cpython-313-*.so or
# abi3.so, so every v2 invocation died on `No module named '_cffi_backend'`
# while the Lambda's Errors metric stayed at 0. Name the target explicitly so
# the artifact no longer depends on the runner image.
#
# Keep PYTHON_VERSION in step with the module's runtime and with
# compatible_runtimes in ../terraform/layer.tf.
PYTHON_VERSION ?= 3.13
PLATFORM ?= manylinux2014_x86_64

ABI_TAG = $(subst .,,$(PYTHON_VERSION))
# --no-compile because pip would otherwise write .pyc for the *build* host's
# interpreter, which is a third Python in the mix and pure noise in the zip.
PIP_TARGET_FLAGS = --platform $(PLATFORM) --implementation cp --python-version $(PYTHON_VERSION) --only-binary=:all: --no-compile

build:
	rm -f ../terraform/layer.zip &&\
	rm -rf package &&\
	pip3 install $(PIP_TARGET_FLAGS) --target ./package/python -r requirements.txt &&\
	cp connector.py package/python/ &&\
	$(MAKE) verify-abi &&\
	cd package &&\
	zip -r ../../terraform/layer.zip .

# Fails the build if any compiled extension would be unimportable on the target
# runtime. abi3 wheels are version-independent by construction and are fine.
verify-abi:
	@bad=$$(find package/python -name '*.so' ! -name '*.abi3.so' ! -name '*cpython-$(ABI_TAG)-*' -print); \
	if [ -n "$$bad" ]; then \
		echo "ABI mismatch: the following extensions are not importable on python$(PYTHON_VERSION):"; \
		echo "$$bad"; \
		exit 1; \
	fi; \
	echo "ABI check passed: every compiled extension is cpython-$(ABI_TAG) or abi3."

fmt:
	black . $(ARGS)

install:
	pip3 install --user -r requirements.txt

install-dev:
	pip3 install --user -r requirements_dev.txt

lint:
	flake8 .

test:
	coverage run -m pytest -s -vv tests &&\
	coverage report -m

lint-ci:
	flake8 .

fmt-ci:
	black --check .
