#!/usr/bin/env sh

cd ./src

# Normal
python knget.py 'loli' 1
python knget.py 'loli' 2 3
python knget.py 'loli game_cg' 4 6

# Without config.ini
rm config.ini
python knget.py 'loli game_cg' 9 9

# Change the base_url
sed -i 's|^;\(base_url.*\)|\1|g' config.ini
python knget.py 'loli game_cg' 10 11

# Cleanup
rm -rf kn-*
cd ../
