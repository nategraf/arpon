#
# Copyright (C) 2008-2016 Andrea Di Pasquale <spikey.it@gmail.com>
# Copyright (C) 2008-2016 Giuseppe Marco Randazzo <gmrandazzo@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#
# $ArpON: CMakeLists.txt,v 3.0-ng 01/29/2016 02:52:15 spikey Exp $
#

#
# The following variables can be modified:
#
# CMAKE_BUILD_TYPE     - Set build type: release or debug
# CMAKE_INCLUDE_PATH   - Set the include path
# CMAKE_LIBRARY_PATH   - Set the library path
# CMAKE_C_FLAGS        - Set flags for the C compiler
# CMAKE_INSTALL_PREFIX - Set the install prefix for ArpON.
#                        By default ArpON will be installed to / path.
#

cmake_minimum_required(VERSION 2.6)

project(ArpON C)
set(AUTHOR "Andrea Di Pasquale <spikey.it@gmail.com>" INTERNAL "Author")
set(VERSION "3.0-ng")

set(CMAKE_INCLUDE_PATH
    /usr/include;
    /usr/local/include;
    /usr/local/include/libnet11;
    /usr/local/include/libnet-1.1;
    ${CMAKE_INCLUDE_PATH})

set(CMAKE_LIBRARY_PATH
    /lib;
    /usr/lib;
    /usr/lib32;
    /usr/lib64;
    /usr/local/lib;
    /usr/local/lib32;
    /usr/local/lib64;
    /usr/local/lib/libnet11;
    /usr/local/lib/libnet-1.1;
    ${CMAKE_LIBRARY_PATH})

include_directories(
    ${PROJECT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_INCLUDE_PATH})

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")

find_package(System)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release
        CACHE STRING "Choose the type of build, options are: Debug Release"
        FORCE)
endif(NOT CMAKE_BUILD_TYPE)

string(TOLOWER "${CMAKE_BUILD_TYPE}" cmake_build_type_tolower)

if(cmake_build_type_tolower STREQUAL "debug")
    message(STATUS "Build type: Debug")

    set(CMAKE_BUILD_TYPE "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -Wformat=2 -Winit-self -Wreturn-type -Wswitch-default -Wswitch-enum -Wunused-parameter -Wuninitialized -Wstrict-aliasing=3 -Wstrict-overflow=5 -Wdeclaration-after-statement -Wundef -Wpointer-arith -Wunsafe-loop-optimizations -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Wsizeof-pointer-memaccess -Wlogical-op -Waggregate-return -Wstrict-prototypes -Wold-style-declaration -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -Winline -Wlong-long -Wvariadic-macros -Wvarargs -Wvla -Wdisabled-optimization -Woverlength-strings -O0 -g -ggdb")
else(cmake_build_type_tolower STREQUAL "debug")
    message(STATUS "Build type: Release")

    set(CMAKE_BUILD_TYPE "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wextra -O3 -DNDEBUG")
endif(cmake_build_type_tolower STREQUAL "debug")

find_package(Headers)
find_package(Pthreads)
find_package(Librt)
find_package(Libpcap)
find_package(Libnet1)
find_package(Libdnet)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/" CACHE PATH "ArpON install prefix" FORCE)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

if(cmake_build_type_tolower STREQUAL "debug")
    message(STATUS "Include path: ${CMAKE_INCLUDE_PATH}")
    message(STATUS "Library path: ${CMAKE_LIBRARY_PATH}")
    message(STATUS "C compiler flags: ${CMAKE_C_FLAGS}")
    message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
endif(cmake_build_type_tolower STREQUAL "debug")

add_subdirectory(src)
add_subdirectory(doc)
add_subdirectory(man8)
add_subdirectory(etc)
add_subdirectory(log)
add_subdirectory(run)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/scripts/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")

add_custom_target(clean-all
    COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_SOURCE_DIR}/cmake/scripts/cmake_clean-all.cmake")

#
# EOF
#
# vim:ts=4:expandtab
#
