add_executable(sshtest ${CMAKE_CURRENT_SOURCE_DIR}/sshtest.cpp)
target_link_libraries(sshtest PRIVATE ws2_32 GTest::gtest GTest::gtest_main linuxplorer::ssh)

add_test(NAME sshtest COMMAND sshtest)

gtest_discover_tests(sshtest)