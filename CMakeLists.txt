cmake_minimum_required(VERSION 2.6)
set(TARGET elliptics-fastcgi)
project(${TARGET})

file(READ "${PROJECT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -Wall -pedantic -std=c++0x")

include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)

set(SOURCES 
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	${PROJECT_SOURCE_DIR}/src/data_container.cpp
	${PROJECT_SOURCE_DIR}/src/lookup_result.cpp
	)

add_library(${TARGET} SHARED ${SOURCES})

target_link_libraries(
	${TARGET}
	fastcgi-daemon2 
	elliptics_cpp
	magic
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

install(
	DIRECTORY
	include/
	DESTINATION include
	COMPONENT development)

