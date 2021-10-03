# Porth++

Port of [Tsoding's Porth](https://github.com/tsoding/porth) simulator/compiler from Python to CPP.

## Quick Start

``` shell
./porth++ sim ../examples/test.porth
./porth++ com ../examples/test.porth
../examples/test
```

## Words

### `<x> (PUSH)`

By default, any word that is not a keyword is pushed onto the stack.

#### Example

``` forth
69 420
```

will result in the values `69` and `420` being pushed onto the stack.

### `. (DUMP)`

Pop and display the top value on the stack.

#### Example

``` forth
69 .
```

Pushes the value `69` onto the stack, then pops and displays it.

### `+ (PLUS)`

Pops two values from the stack, adds them, and pushes the result onto the stack.

#### Example

``` forth
34 35 + .
```

Pushes the values `34` and `35` onto the stack, pops and adds them, pushes the value `69` onto the stack, pops and displays it.

### `- (MINUS)`

Pops two values from the stack, subtracts the first from the second, and pushes the result onto the stack.

#### Example

``` forth
500 80 - .
```

Pushes the values `500` and `80` onto the stack, pops and subtracts them, pushes the value `420` onto the stack, pops and displays it.
