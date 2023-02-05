
project(check-unlock)

add_subdirectory(ThirdParty/openssl-cmake EXCLUDE_FROM_ALL)

file(GLOB SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/*)
add_executable(${PROJECT_NAME} ${SRCS})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} ssl crypto)
