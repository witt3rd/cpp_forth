# Porth++

Port of [Tsoding's Porth](https://github.com/tsoding/porth) simulator/compiler from Python to CPP.

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
