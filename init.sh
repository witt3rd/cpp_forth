#!/bin/bash

cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .
ln -fs "$PWD/build/compile_commands.json" .
