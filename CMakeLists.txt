cmake_minimum_required(VERSION 3.25)
project(Chain_of_Trust VERSION 1.0.0 LANGUAGES C CXX ASM)

option(BUILD_KERNEL   "Build kernel driver" ON)
option(BUILD_TESTS    "Build tests" OFF) # Disabled for CI stability

# Detours often doesn't provide a CMake config in some vcpkg versions
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)

find_package(GTest CONFIG REQUIRED)

add_subdirectory(src/edr_agent)
add_subdirectory(src/common)
if(BUILD_KERNEL)
    add_subdirectory(src/edr_kernel)
endif()
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()