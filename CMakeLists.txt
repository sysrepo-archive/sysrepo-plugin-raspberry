cmake_minimum_required(VERSION 2.8)
project(sysrepo-raspberry-pi)
set(SYSREPO_DESC "Sysrepo plugins that allow Raspberry Pi management via NETCONF")

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

if(NOT UNIX)
    message(FATAL_ERROR "Only Unix-like systems are supported.")
endif()

if(NOT LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR "lib")
endif()
if(NOT BIN_INSTALL_DIR)
    set(BIN_INSTALL_DIR "bin")
endif()
if(NOT INCLUDE_INSTALL_DIR)
    set(INCLUDE_INSTALL_DIR "include")
endif()
set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/sysrepo/plugins/" CACHE PATH "Sysrepo plugins directory.")

# raspberry-demo plugin
add_library(raspberry-demo SHARED src/raspberry-demo.c)
target_link_libraries(raspberry-demo sysrepo)

install(TARGETS raspberry-demo DESTINATION ${PLUGINS_DIR})
