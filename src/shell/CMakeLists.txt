add_library(linuxplorer.shell SHARED)
add_library(linuxplorer::shell ALIAS linuxplorer.shell)
set(LINUXPLORER_SHELL_DIR shell)
target_compile_definitions(linuxplorer.shell PRIVATE NOMINMAX LINUXPLORER_SHELL_API_IMPLEMENTATION)
target_sources(linuxplorer.shell 
	PRIVATE
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/cloud_provider_session.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/filesystem/cloud_provider_registrar.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/filesystem/cloud_filter_placeholder.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/filesystem/placeholder_info.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/functional/cloud_provider_callback.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_SHELL_DIR}/functional/callback_parameters.cpp
	PUBLIC
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/shellfwd.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/functional/cloud_provider_callback.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/functional/callback_parameters.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/models/chunked_callback_generator.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/cloud_provider_session.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/cloud_provider_exception.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/filesystem/cloud_filter_placeholder.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/filesystem/cloud_provider_registrar.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_SHELL_DIR}/filesystem/placeholder_info.hpp
)
target_link_libraries(linuxplorer.shell PRIVATE cldapi)
install(TARGETS linuxplorer.shell RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})