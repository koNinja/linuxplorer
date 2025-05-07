add_library(ssh STATIC)
add_library(linuxplorer::ssh ALIAS ssh)
target_link_libraries(ssh PUBLIC libssh2::libssh2 linuxplorer::util::charset)
target_sources(ssh PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/ssh_session.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/ssh_address.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/auth/ssh_knownhosts.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/sftp/io/sftpstream.cpp
)
target_sources(ssh PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/internal/ssh_library_resource_manager.cpp)