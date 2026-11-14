cmake_minimum_required(VERSION 3.20)
project(bincheck VERSION 0.2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(bincheck
  src/main.cpp
  src/elf.cpp
  src/pe.cpp
)

target_include_directories(bincheck PRIVATE src)
target_compile_definitions(bincheck PRIVATE
  BINCHECK_VERSION="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(bincheck PRIVATE /W4)
else()
  target_compile_options(bincheck PRIVATE -Wall -Wextra)
endif()

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(
    NAME bincheck_tests
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py
            $<TARGET_FILE:bincheck>
            ${CMAKE_CURRENT_BINARY_DIR}/test-work
  )
endif()
