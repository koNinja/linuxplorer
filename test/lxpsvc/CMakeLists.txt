add_executable(lxpsvc_test)
target_sources(lxpsvc_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/watcher.cpp
)
target_link_libraries(lxpsvc_test PRIVATE 
    GTest::gtest
    GTest::gtest_main
    linuxplorer::ssh
    linuxplorer::shell
    linuxplorer::util::charset
    linuxplorer::util::config
    quill::quill
    ${LINUXPLORER_APP_SERVICE_NAME}
)
target_compile_definitions(lxpsvc_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
add_custom_command(TARGET lxpsvc_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:lxpsvc_test> $<TARGET_FILE_DIR:lxpsvc_test>
    COMMAND_EXPAND_LISTS
)
add_test(NAME lxpsvc_test COMMAND lxpsvc_test)

gtest_discover_tests(lxpsvc_test)