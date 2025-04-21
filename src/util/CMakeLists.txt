add_library(util.charset STATIC)
add_library(linuxplorer::util::charset ALIAS util.charset)
target_sources(util.charset PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/charset/multibyte_wide_compat_helper.cpp
)