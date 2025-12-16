.PHONY: build fmt install lint migrations test fmt-ci lint-ci install-dev

build:
	rm -f ../terraform/layer.zip &&\
	rm -rf package &&\
	pip3 install --target ./package/python -r requirements.txt &&\
	cp connector.py package/python/ &&\
	cd package &&\
	zip -r ../../terraform/layer.zip .

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