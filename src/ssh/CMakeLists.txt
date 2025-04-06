add_library(ssh STATIC)
target_link_libraries(ssh PUBLIC libssh2::libssh2)
target_sources(ssh PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/ssh_session.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/ssh_address.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/internal/ssh_library_resource_manager.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/auth/ssh_knownhosts.cpp
)