#!/bin/bash

usage() { echo "Usage: $0 [-r]" 1>&2; exit 1; }

r=Debug

while getopts "rh" o; do
    case "${o}" in
        r)
            r=Release
            ;;
        *)
            usage
            ;;
    esac
done

set -x
cmake -DCMAKE_BUILD_TYPE=$r -B build
ln -fs "$PWD/build/compile_commands.json" .
