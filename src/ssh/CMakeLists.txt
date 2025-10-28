add_library(linuxplorer.ssh SHARED)
add_library(linuxplorer::ssh ALIAS linuxplorer.ssh)
set(LINUXPLORER_SHELL_DIR ssh)
target_compile_definitions(linuxplorer.ssh PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN LINUXPLORER_SSH_API_IMPLEMENTATION)
target_sources(linuxplorer.ssh 
	PRIVATE
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/ssh_session.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/ssh_exception.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/ssh_address.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/auth/ssh_knownhosts.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/sftp_session.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/io/sftpstream.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/filesystem/sftp_entity.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/filesystem/sftp_manip.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/internal/ssh_library_resource_manager.cpp
	# header
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/internal/ssh_library_resource_manager.hpp
	PUBLIC
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/sshfwd.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/ssh_session.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/ssh_address.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/auth/ssh_knownhosts.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/sftp_session.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/io/sftpstream.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/filesystem/sftp_entity.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/sftp/filesystem/sftp_manip.hpp
)
target_link_libraries(linuxplorer.ssh PUBLIC libssh2::libssh2 linuxplorer::util::charset Boost::uuid ws2_32)
install(TARGETS linuxplorer.ssh RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})