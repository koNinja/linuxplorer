cmake_minimum_required(VERSION 3.31)

if (NOT WIN32)
	message(FATAL_ERROR "Linuxplorer is only supported on Windows.")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(linuxplorer VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)

set(LINUXPLORER_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(LINUXPLORER_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
set(LINUXPLORER_APP_DIR ${PROJECT_SOURCE_DIR}/app)

find_package(OpenSSL REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(libssh2 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(boost_uuid CONFIG REQUIRED)
find_package(boost_program_options REQUIRED CONFIG)
find_package(quill REQUIRED CONFIG)

set(LINUXPLORER_APP_MAIN_NAME ${PROJECT_NAME})
set(LINUXPLORER_APP_SERVICE_NAME lxpsvc)

enable_testing()
include(GoogleTest)
include_directories(${LINUXPLORER_INCLUDE_DIR})

add_subdirectory(${LINUXPLORER_SOURCE_DIR})
add_subdirectory(${LINUXPLORER_APP_DIR})
# add_subdirectory(${PROJECT_SOURCE_DIR}/test)

set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VENDOR "koNinja")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_NSIS_INSTALL_ROOT "${CMAKE_INSTALL_PREFIX}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "${PROJECT_NAME}")

set(CPACK_GENERATOR "ZIP")
include(CPack)