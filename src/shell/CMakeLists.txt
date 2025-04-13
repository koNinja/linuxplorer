add_library(shell STATIC)
target_sources(shell PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/cloud_provider_session.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/cloud_provider_callback.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/filesystem/cloud_provider_registrar.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/filesystem/cloud_filter_placeholder.cpp
)
target_link_libraries(shell PRIVATE cldapi)