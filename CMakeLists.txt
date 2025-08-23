cmake_minimum_required(VERSION 3.31)

if (NOT WIN32)
	message(FATAL_ERROR "Linuxplorer is only supported on Windows.")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(linuxplorer VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)

set(ESCAPED_INSTALL_PREFIX)
string(REPLACE "/" "\\\\" ESCAPED_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

set(LINUXPLORER_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(LINUXPLORER_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
set(LINUXPLORER_APP_DIR ${PROJECT_SOURCE_DIR}/app)

find_package(OpenSSL REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(libssh2 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(boost_uuid CONFIG REQUIRED)

enable_testing()
include(GoogleTest)
include_directories(${LINUXPLORER_INCLUDE_DIR})

add_subdirectory(${LINUXPLORER_SOURCE_DIR})
# add_subdirectory(${PROJECT_SOURCE_DIR}/test)