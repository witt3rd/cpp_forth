# Porth++

 [![](https://img.shields.io/github/issues-raw/witt3rd/cpp_porth.svg?style=flat-square)](https://github.com/witt3rd/cpp_porth/issues)
[![MIT](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)


Port of [Tsoding's Porth](https://github.com/tsoding/porth) simulator/compiler from Python to C++.

## Build

``` sh
cmake -DCMAKE_BUILD_TYPE=Debug -B build
cd build
make
```

## Run

### Simulate

``` sh
./porth++ sim ../tests/01-arithmetics.porth
```

### Compile

``` sh
./porth++ com ../tests/01-arithmetics.porth
../01-arithmetics
```
