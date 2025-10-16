add_executable(lxptest ${PROJECT_SOURCE_DIR}/test/lxptest.cpp)
target_link_libraries(lxptest PRIVATE 
    GTest::gtest
    GTest::gtest_main
    linuxplorer::ssh
    linuxplorer::shell
    linuxplorer::util::charset
    linuxplorer::util::config
)
target_compile_definitions(lxptest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
add_custom_command(TARGET lxptest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:lxptest> $<TARGET_FILE_DIR:lxptest>
    COMMAND_EXPAND_LISTS
)
add_test(NAME lxptest COMMAND lxptest)

gtest_discover_tests(lxptest)