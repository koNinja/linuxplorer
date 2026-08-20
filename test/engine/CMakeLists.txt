add_executable(engine_test)
target_sources(engine_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/result_adapter.cpp
)
target_link_libraries(engine_test PRIVATE 
    GTest::gtest
    GTest::gtest_main
    linuxplorer::engine
)
target_compile_definitions(engine_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
add_custom_command(TARGET engine_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
		$<TARGET_RUNTIME_DLLS:engine_test> $<TARGET_FILE_DIR:engine_test>
    COMMAND_EXPAND_LISTS
)
add_test(NAME engine_test COMMAND engine_test)

gtest_discover_tests(engine_test)