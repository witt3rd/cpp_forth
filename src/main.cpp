#include "bar.h"
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <iostream>

int main() {
  int c = bar(1, 2);
  int d = bar(2, 3);
  int e = bar(4, 5);
  std::cout << "Hello World! => " << c << d << e << std::endl;
  std::cout << fmt::format("Hello {}!", "World");
  return 0;
}
