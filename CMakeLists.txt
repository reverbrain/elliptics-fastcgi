cmake_minimum_required(VERSION 2.6)
set(TARGET elliptics-fastcgi)
project(${TARGET})

file(READ "${PROJECT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -Wall -pedantic -std=c++0x")

set(SOURCES 
	${PROJECT_SOURCE_DIR}/src/proxy.hpp
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	${PROJECT_SOURCE_DIR}/src/embed_processor.hpp
	${PROJECT_SOURCE_DIR}/src/embed_processor.cpp
	${PROJECT_SOURCE_DIR}/src/component_base.hpp
	${PROJECT_SOURCE_DIR}/src/component_base.cpp
	)

add_library(${TARGET} SHARED ${SOURCES})

target_link_libraries(
	${TARGET}
	mastermind
	fastcgi-daemon2 
	)

set_target_properties(
    ${TARGET} PROPERTIES
        PREFIX ""
        INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib/fastcgi2"
    )

install(
	TARGETS
	${TARGET}
    LIBRARY DESTINATION lib/fastcgi2 COMPONENT runtime)


