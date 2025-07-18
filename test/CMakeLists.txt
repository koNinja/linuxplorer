add_executable(configtest ${CMAKE_CURRENT_SOURCE_DIR}/configtest.cpp)
target_compile_definitions(configtest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(configtest PRIVATE GTest::gtest GTest::gtest_main linuxplorer::util::config)

add_test(NAME configtest COMMAND configtest)
gtest_discover_tests(configtest)