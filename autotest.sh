#!/usr/bin/env sh

cd ./src

# Python2
python2 knget.py 'loli' 1
python2 knget.py 'loli' 1 2
python2 knget.py 'loli game_cg' 1 3

# Python3
python3 knget.py 'loli' 1
python3 knget.py 'loli' 1 2
python3 knget.py 'loli game_cg' 1 3

# Cleanup
rm -rf kn-*
