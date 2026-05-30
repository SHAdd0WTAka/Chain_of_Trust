add_executable(ChainOfTrust_Tests
    agent_test.cpp
    ../src/common/AdminAuth.cpp
    ../src/common/IntegrityGuard.cpp
    ../src/common/FsTxRecovery.cpp
    ../src/common/crypto.cpp
    ../src/common/ipc.cpp
    ../src/common/shamir.cpp
    ../src/common/bitlocker.cpp
    ../src/common/peer_discovery.cpp
    ../src/common/dkg.cpp
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
    ws2_32
    wbemuuid
)

include(GoogleTest)
gtest_discover_tests(ChainOfTrust_Tests)
