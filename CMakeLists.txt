cmake_minimum_required(VERSION 2.4)

if(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/libev)
INCLUDE_DIRECTORIES("/usr/include/node")

ADD_LIBRARY(snmp_binding MODULE
	snmp_binding.cc
	)

ADD_DEFINITIONS(
	# -DPIC
	# -D_LARGEFILE_SOURCE
	# -D_FILE_OFFSET_BITS=64
	# -D_GNU_SOURCE
	-DEV_MULTIPLICITY=1
	-DEV_STANDALONE=1
	)

SET_TARGET_PROPERTIES(snmp_binding PROPERTIES
	PREFIX "" SUFFIX ".node")

TARGET_LINK_LIBRARIES(snmp_binding
	netsnmp
	)

