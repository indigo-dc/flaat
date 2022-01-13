
# this was for publishing to testpypi only
# TWINE_ARGS=--repository testpypi

.PHONY: dist
dist: clean
	python setup.py sdist bdist_wheel

.PHONY: upload
upload: dist
	twine upload $(TWINE_ARGS) dist/*

.PHONY: coverage
coverage:
	tox -e py310

.PHONY: clean
clean:
	@find . -type f -name '*.pyc' -delete
	@find . -type d -name '__pycache__' | xargs rm -rf
	@rm -rf *.egg-info
	@rm -rf build/
	@rm -rf dist/
	@rm -f src/*.egg*
	@rm -f MANIFEST
	@rm -rf docs/build doc/build
	@rm -f .coverage.*
	@rm -f ChangeLog
	@rm -f AUTHORS
