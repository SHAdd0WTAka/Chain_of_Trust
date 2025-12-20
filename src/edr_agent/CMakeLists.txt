add_executable(EDRAgent main.cpp)
target_link_libraries(EDRAgent PRIVATE Detours::Detours common)
