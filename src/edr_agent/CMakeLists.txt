add_executable(EDRAgent
    main.cpp
    c2_server.cpp
    service_manager.cpp
)
target_include_directories(EDRAgent PRIVATE ${DETOURS_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/src/common)
target_link_libraries(EDRAgent PRIVATE ${DETOURS_LIBRARY} common psapi ws2_32)
