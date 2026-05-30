add_library(common
    crypto.cpp
    ipc.cpp
    AdminAuth.cpp
    IntegrityGuard.cpp
    FsTxRecovery.cpp
)

target_include_directories(common PUBLIC .)
target_link_libraries(common PRIVATE bcrypt ntdll)
