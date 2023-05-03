#!/usr/bin/env bash

[[ ! -e alienpy/alien.py ]] && { echo "alien.py was not found"; exit 1; }

./update_version
git commit -m "alien.py update version info" alienpy/*.py
git push
git push xjalienfs master

VER=$(python3 -c 'from alienpy.version import *;print(ALIENPY_VERSION_STR)') # '
[[ -z ${VER} ]] && { echo "Something is wrong, could not get the version number"; exit 1; }

tag_list="$(git --no-pager tag --sort=committerdate)"
tag_present=$(echo "${tag_list}" | grep "${VER}")

[[ -n "${tag_present}" ]] && { echo "tag ${ver} already done"; exit 1; }

git tag ${VER}
git push --tags
git push --tags xjalienfs master

#tag=$(git describe --tags --abbrev=0 --exact-match)

