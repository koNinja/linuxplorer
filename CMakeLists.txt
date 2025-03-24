cmake_minimum_required(VERSION 3.31)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

project(linuxplorer CXX)

find_package(GTest CONFIG REQUIRED)
find_package(libssh2 CONFIG REQUIRED)

enable_testing()
include(GoogleTest)
include_directories(${PROJECT_SOURCE_DIR}/include)

add_subdirectory(${PROJECT_SOURCE_DIR}/src)
add_subdirectory(${PROJECT_SOURCE_DIR}/test)