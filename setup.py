#!/usr/bin/env python

# https://github.com/pypa/sampleproject

from knget import __author__
from knget import __email__
from knget import __license__
from knget import __version__

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# Description
with open('README') as fp:
    long_description = fp.read()

# Requirements
with  open('requirements.txt') as fp:
    requirements = fp.read().decode().split()

setup(name='knget',
      version=__version__,
      description='A simple light fast booru-like downloader written on Python',
      long_description=long_description,
      author=__author__,
      author_email=__email__,
      license=__license__,
      keywords='danbooru yandere sankaku booru knget kngetpy',
      url='https://github.com/urain39/KngetPy',
      packages=find_packages(exclude=['contrib', 'docs', 'tests']),
      install_requires=[requirements],
      platforms='any',
      classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
        "Topic :: Internet"
        ],
     )

