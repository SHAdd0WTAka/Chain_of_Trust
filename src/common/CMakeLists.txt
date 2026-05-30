add_library(common
    crypto.cpp
    ipc.cpp
    AdminAuth.cpp
    IntegrityGuard.cpp
    FsTxRecovery.cpp
    shamir.cpp
    bitlocker.cpp
    peer_discovery.cpp
    dkg.cpp
)

target_include_directories(common PUBLIC .)
target_link_libraries(common PRIVATE bcrypt ntdll ws2_32 wbemuuid)
