add_executable(cftest ${PROJECT_SOURCE_DIR}/test/cftest.cpp ${PROJECT_SOURCE_DIR}/test/cftest_impl.cpp)
target_link_libraries(cftest PRIVATE GTest::gtest GTest::gtest_main linuxplorer::shell cldapi)
add_custom_command(TARGET cftest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:cftest> $<TARGET_FILE_DIR:cftest>
    COMMAND_EXPAND_LISTS
)

add_test(cftest cftest)

gtest_discover_tests(cftest)