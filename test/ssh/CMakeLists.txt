add_executable(ssh_test)
target_sources(ssh_test PRIVATE
)
target_link_libraries(ssh_test PRIVATE 
    GTest::gtest
    GTest::gtest_main
    linuxplorer::ssh
    linuxplorer::util::charset
    linuxplorer::util::config
)
target_compile_definitions(ssh_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
add_custom_command(TARGET ssh_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:ssh_test> $<TARGET_FILE_DIR:ssh_test>
    COMMAND_EXPAND_LISTS
)
add_test(NAME ssh_test COMMAND ssh_test)

gtest_discover_tests(ssh_test)