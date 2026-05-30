add_executable(ChainOfTrust_Tests
    agent_test.cpp
    ../src/common/AdminAuth.cpp
    ../src/common/IntegrityGuard.cpp
    ../src/common/FsTxRecovery.cpp
    ../src/common/crypto.cpp
    ../src/common/ipc.cpp
)

target_include_directories(ChainOfTrust_Tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/common
    ${DETOURS_INCLUDE_DIRS}
)

target_link_libraries(ChainOfTrust_Tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    ${DETOURS_LIBRARY}
    bcrypt
    ntdll
    psapi
)

include(GoogleTest)
gtest_discover_tests(ChainOfTrust_Tests)
