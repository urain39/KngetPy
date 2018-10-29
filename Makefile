#!/usr/bin/env make

.PHONY: all
all: knget

.PHONY: knget
knget: setup.py
	python setup.py sdist

.PHONY: clean
clean:
	- rm -rf dist
	- rm -rf *.egg-info

