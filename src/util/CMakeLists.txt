add_library(linuxplorer.util.charset STATIC)
add_library(linuxplorer::util::charset ALIAS linuxplorer.util.charset)
set(LINUXPLORER_UTIL_CHARSET_DIR util/charset)
target_sources(linuxplorer.util.charset 
	PRIVATE 
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_UTIL_CHARSET_DIR}/multibyte_wide_compat_helper.cpp
	PUBLIC
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CHARSET_DIR}/multibyte_wide_compat_helper.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CHARSET_DIR}/case_insensitive_char_traits.hpp
)

add_library(linuxplorer.util.config SHARED)
add_library(linuxplorer::util::config ALIAS linuxplorer.util.config)
set(LINUXPLORER_UTIL_CONFIG_DIR util/config)
target_compile_definitions(linuxplorer.util.config 
	PRIVATE 
	WIN32_LEAN_AND_MEAN 
	NOMINMAX
	LINUXPLORER_APP_SERVICE_NAME=${LINUXPLORER_APP_SERVICE_NAME}
	LINUXPLORER_CONFIG_API_IMPLEMENTATION
)
target_sources(linuxplorer.util.config
	PRIVATE
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/app_settings.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/startup_config.cpp
	${LINUXPLORER_SOURCE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/profiles.cpp
	PUBLIC
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/configfwd.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/config_exception.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/app_settings.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/startup_config.hpp
	${LINUXPLORER_INCLUDE_DIR}/${LINUXPLORER_UTIL_CONFIG_DIR}/profiles.hpp
)
target_link_libraries(linuxplorer.util.config 
	PUBLIC OpenSSL::Crypto OpenSSL::SSL linuxplorer::util::charset crypt32 nlohmann_json::nlohmann_json
)
install(TARGETS linuxplorer.util.config RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})