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
# $ArpON: FindLibnet1.cmake,v 3.0-ng 01/29/2016 02:50:18 spikey Exp $
#

#
# FindLibnet1 search and find the Libnet1 library path and header path
#
# Usage:
#
#  find_package(Libnet1)
#  ...
#  target_link_libraries(... ${NET_LIB})
#
# The following variables are to be set:
#
#   CMAKE_INCLUDE_PATH - find the libnet.h
#   CMAKE_LIBRARY_PATH - find the library
#
# Variable defined by this module:
#
#   NET_INCLUDE_DIR - header directory
#   NET_LIB         - library to link
#

find_path(NET_INCLUDE_DIR NAMES libnet.h HINTS ${CMAKE_INCLUDE_PATH})
find_library(NET_LIB NAMES net HINTS ${CMAKE_LIBRARY_PATH})

if(NET_INCLUDE_DIR AND NET_LIB)
    #
    # Match only for Libnet1 (not for Libnet0).
    #
    file(READ "${NET_INCLUDE_DIR}/libnet.h" FILE_CONTENT)
    string(REGEX MATCH
        ".*#define[ \t]+LIBNET_VERSION[ \t]+\"([0-9.a-zA-Z-]+)\".*"
        LIBNET_VERSION "${FILE_CONTENT}")

    if(LIBNET_VERSION STREQUAL "")
        message(FATAL_ERROR "Could not find Libnet1! Please see in the ArpON 'README' file.")
    endif(LIBNET_VERSION STREQUAL "")

    include_directories(${NET_INCLUDE_DIR})

    message(STATUS "Found library: Libnet1")
else(NET_INCLUDE_DIR AND NET_LIB)
    message(FATAL_ERROR "Could not find Libnet1! Please see in the ArpON 'README' file.")
endif(NET_INCLUDE_DIR AND NET_LIB)

#
# EOF
#
# vim:ts=4:expandtab
#
