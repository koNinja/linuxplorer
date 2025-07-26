add_library(util.charset STATIC)
add_library(linuxplorer::util::charset ALIAS util.charset)
target_sources(util.charset 
	PRIVATE 
	${PROJECT_SOURCE_DIR}/src/util/charset/multibyte_wide_compat_helper.cpp
	PUBLIC
	${PROJECT_SOURCE_DIR}/include/util/charset/multibyte_wide_compat_helper.hpp
	${PROJECT_SOURCE_DIR}/include/util/charset/case_insensitive_char_traits.hpp
)

add_library(util.config STATIC)
add_library(linuxplorer::util::config ALIAS util.config)
target_compile_definitions(util.config PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX PROJECT_INSTALL_DIR=${CMAKE_INSTALL_PREFIX} APP_SERVICE_NAME=${APP_SERVICE_NAME})
target_sources(util.config
	PRIVATE
	${PROJECT_SOURCE_DIR}/src/util/config/app_settings.cpp
	${PROJECT_SOURCE_DIR}/src/util/config/credentials.cpp
	${PROJECT_SOURCE_DIR}/src/util/config/startup_config.cpp
	PUBLIC
	${PROJECT_SOURCE_DIR}/include/util/config/app_settings.hpp
	${PROJECT_SOURCE_DIR}/include/util/config/credentials.hpp
	${PROJECT_SOURCE_DIR}/include/util/config/startup_config.hpp
)
target_link_libraries(util.config 
	PRIVATE OpenSSL::Crypto OpenSSL::SSL linuxplorer::util::charset crypt32
	PUBLIC nlohmann_json::nlohmann_json
)