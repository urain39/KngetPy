#!/usr/bin/env make

.PHONY: all
all: knget

.PHONY: knget
knget: setup.py
	@ - sed -Ei 's,^ *(__version__.*debug.*),# \1,g' \
					knget/__version__.py
	@test -f dist/knget-*.tar.gz || python setup.py sdist

.PHONY: debug
debug: setup.py
	@ - sed -Ei 's,^# *(__version__.*debug.*),\1,g' \
					knget/__version__.py
	@test -f dist/knget-*.tar.gz || python setup.py sdist

.PHONY: clean
test: knget
	@: TODO: add task test here.

.PHONY: clean
clean:
	- rm -rf dist
	- rm -rf *.egg-info
