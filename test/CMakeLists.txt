add_executable(cftest ${CMAKE_CURRENT_SOURCE_DIR}/cftest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/cftest_impl.cpp)
target_link_libraries(cftest PRIVATE GTest::gtest GTest::gtest_main shell)

add_test(cftest cftest)

gtest_discover_tests(cftest)