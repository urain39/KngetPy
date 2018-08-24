#!/usr/bin/env python

# https://github.com/pypa/sampleproject

# NOTE: Just a dummy varable here
#       It's a simple way to ignore error!
__author__ = None
__email__ = None
__version__ = None
__license__ = None

# NOTE: Now get the real value!
with open('kngetx/version.py') as fp:
    content = fp.read()
    exec(content)


# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# Description
with open('README') as fp:
    long_description = fp.read()

# Requirements
with  open('requirements.txt') as fp:
    requirements = fp.read().split()

setup(name='kngetx',
      version=__version__,
      description='A simple light fast booru-like downloader written on Python',
      long_description=long_description,
      author=__author__,
      author_email=__email__,
      license=__license__,
      keywords=['kngetx', 'kngetpyx', 'danbooru',
                'yandere', 'yande', 'konachan', 'sankaku'],
      url='https://github.com/urain39/KngetPyX',
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

