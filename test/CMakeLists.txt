add_executable(sshtest ${PROJECT_SOURCE_DIR}/test/sshtest.cpp)
target_link_libraries(sshtest PRIVATE GTest::gtest GTest::gtest_main linuxplorer::ssh linuxplorer::util::charset)
target_compile_definitions(sshtest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
add_custom_command(TARGET sshtest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:sshtest> $<TARGET_FILE_DIR:sshtest>
    COMMAND_EXPAND_LISTS
)
add_test(NAME sshtest COMMAND sshtest)

gtest_discover_tests(sshtest)

add_executable(cftest ${PROJECT_SOURCE_DIR}/test/cftest.cpp ${PROJECT_SOURCE_DIR}/test/cftest_impl.cpp)
target_link_libraries(cftest PRIVATE GTest::gtest GTest::gtest_main linuxplorer::shell cldapi)
add_custom_command(TARGET cftest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:cftest> $<TARGET_FILE_DIR:cftest>
    COMMAND_EXPAND_LISTS
)

add_test(cftest cftest)

gtest_discover_tests(cftest)

add_executable(configtest ${PROJECT_SOURCE_DIR}/test/configtest.cpp)
target_compile_definitions(configtest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(configtest PRIVATE GTest::gtest GTest::gtest_main linuxplorer::util::config)
add_custom_command(TARGET configtest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:configtest> $<TARGET_FILE_DIR:configtest>
    COMMAND_EXPAND_LISTS
)

add_test(NAME configtest COMMAND configtest)
gtest_discover_tests(configtest)