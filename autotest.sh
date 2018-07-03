#!/usr/bin/env sh

HERE=$PWD
cd $HERE/src

echo "=== Normal test ==="
python knget.py 'loli' 1 && \
python knget.py 'loli' 2 3 && \
python knget.py 'loli game_cg' 4 6 || exit $?

echo "== Change the base_url =="
sed -i 's|^;\(base_url.*\)|\1|g' config.ini && \
python knget.py 'loli game_cg' 10 11 || exit $?

echo "== Without config.ini =="
rm config.ini && \
python knget.py 'loli game_cg' 9 9 || exit $?

echo "====== KngetShell ======"
(echo "task seifuku sunflower 1 3" | python knget.py) || exit $?

# Cleanup
rm -rf kn-*
cd $HERE
exit 0
