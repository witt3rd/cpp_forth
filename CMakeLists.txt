cmake_minimum_required(VERSION 3.19)

project(porth++ VERSION 0.0.1 LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

fetchcontent_declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG master
)
fetchcontent_makeavailable(fmt)

find_package(Threads REQUIRED) # for pthread

file(GLOB_RECURSE SOURCE "src/*.cpp")

add_executable(${CMAKE_PROJECT_NAME} ${SOURCE})

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC
  $<INSTALL_INTERFACE:inc>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
)

target_link_libraries(
  ${CMAKE_PROJECT_NAME}
  PRIVATE
  fmt::fmt
  Threads::Threads
)
