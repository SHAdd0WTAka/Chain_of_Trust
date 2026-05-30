cmake_minimum_required(VERSION 3.25)
project(Chain_of_Trust VERSION 1.2.0 LANGUAGES C CXX ASM)

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 UNICODE _UNICODE)
add_link_options(/DEFAULTLIB:ole32 /DEFAULTLIB:oleaut32)

option(BUILD_KERNEL   "Build kernel driver" OFF)
option(BUILD_TESTS    "Build tests" ON)

find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)
find_package(GTest CONFIG REQUIRED)

add_subdirectory(src/common)
add_subdirectory(src/edr_agent)

if(BUILD_KERNEL)
    add_subdirectory(src/edr_kernel)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
