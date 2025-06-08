cmake_minimum_required(VERSION 3.31)

if (NOT WIN32)
	message(FATAL_ERROR "Linuxplorer is only supported on Windows.")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(linuxplorer CXX)

find_package(GTest CONFIG REQUIRED)
find_package(libssh2 CONFIG REQUIRED)
find_package(boost_uuid REQUIRED CONFIG)

enable_testing()
include(GoogleTest)
include_directories(${PROJECT_SOURCE_DIR}/include)

add_subdirectory(${PROJECT_SOURCE_DIR}/src)
add_subdirectory(${PROJECT_SOURCE_DIR}/test)