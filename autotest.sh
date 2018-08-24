#!/usr/bin/env sh


alias knget='python -m knget'

cp knget/config.ini ~/knget.ini

echo "=== Normal test ==="
knget 'loli' 1 && \
knget 'loli' 2 3 && \
knget 'loli game_cg' 4 6 || exit $?

echo "== Change the base_url =="
sed -i 's|^;\(base_url.*\)|\1|g' ~/knget.ini && \
knget 'loli game_cg' 10 11 || exit $?

echo "== Without config.ini =="
rm ~/knget.ini && \
knget 'loli game_cg' 9 9 || exit $?

echo "====== KngetShell ======"
(echo "run 'seifuku sunflower' 1 3" | knget) || exit $?


knget <<EOF
run tagme 1 1
reload
exit
EOF

echo "===== Test Build ====="
python setup.py sdist install --user || exit $?

# Cleanup
rm -rf kn-*
cd $HERE
exit 0
