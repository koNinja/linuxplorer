add_library(util.charset STATIC)
add_library(linuxplorer::util::charset ALIAS util.charset)
target_sources(util.charset PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/charset/multibyte_wide_compat_helper.cpp
)

add_library(util.config STATIC)
add_library(linuxplorer::util::config ALIAS util.config)
target_link_libraries(util.config PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto OpenSSL::SSL linuxplorer::util::charset crypt32)
target_compile_definitions(util.config PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_sources(util.config PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/config/app_settings.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/config/credentials.cpp
)