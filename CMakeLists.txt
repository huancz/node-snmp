cmake_minimum_required(VERSION 2.4)

set(cmake_allow_loose_loop_constructs 1)

if(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
endif()

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/libev)
INCLUDE_DIRECTORIES("/usr/include/node")

ADD_LIBRARY(snmp_binding MODULE
	src/snmp_binding.cc
	)

IF(NOT DEFINED CONF_SYNC)
	SET(CONF_SYNC false
		CACHE BOOL "build synchronous interface (requires custom node.js)" FORCE
    )
ENDIF()

IF(NOT DEFINED NODE_ROOT)
	SET(NODE_ROOT "/usr/local"
		CACHE STRING "where to look for node.js include files" FORCE)
ENDIF()


ADD_DEFINITIONS(
	# -D_LARGEFILE_SOURCE
	-D_FILE_OFFSET_BITS=64
	# -D_GNU_SOURCE
	-DEV_STANDALONE=1
	)

IF(CONF_SYNC)
	ADD_DEFINITIONS(-DEV_MULTIPLICITY=1)
ELSE()
	ADD_DEFINITIONS(-DEV_MULTIPLICITY=0)
ENDIF()

INCLUDE_DIRECTORIES("${NODE_ROOT}/include/node")

# these are needed when node has not been installed yet. Highly unusual situation.
#INCLUDE_DIRECTORIES("${NODE_ROOT}/deps/libev")
#INCLUDE_DIRECTORIES("${NODE_ROOT}/deps/v8/src")
#INCLUDE_DIRECTORIES("${NODE_ROOT}/deps/libeio")
#INCLUDE_DIRECTORIES("${NODE_ROOT}/src")

SET_TARGET_PROPERTIES(snmp_binding PROPERTIES
	PREFIX "" SUFFIX ".node")

TARGET_LINK_LIBRARIES(snmp_binding
	netsnmp
	)

