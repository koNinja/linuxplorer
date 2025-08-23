add_executable(sshtest ${CMAKE_CURRENT_SOURCE_DIR}/sshtest.cpp)
target_link_libraries(sshtest PRIVATE GTest::gtest GTest::gtest_main linuxplorer::ssh linuxplorer::util::charset)
target_compile_definitions(sshtest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
add_custom_command(TARGET sshtest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:sshtest> $<TARGET_FILE_DIR:sshtest>
    COMMAND_EXPAND_LISTS
)
add_test(NAME sshtest COMMAND sshtest)

gtest_discover_tests(sshtest)
