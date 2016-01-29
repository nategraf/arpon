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
# $ArpON: FindLibdnet.cmake,v 3.0-ng 01/29/2016 02:48:07 spikey Exp $
#

#
# FindLibdnet search and find the Libdnet library path and header path
#
# Usage:
#
#  find_package(Libdnet)
#  ...
#  target_link_libraries(... ${DNET_LIB})
#
# The following variables are to be set:
#
#   CMAKE_INCLUDE_PATH - find the dnet.h or dumbnet.h
#   CMAKE_LIBRARY_PATH - find the library
#
# Variable defined by this module:
#
#   DNET_INCLUDE_DIR - header directory
#   DNET_LIB         - library to link
#

set(libdnet_h dumbnet.h dnet.h)
set(libdnet_names dumbnet dnet)

set(DNET_H)

foreach(header ${libdnet_h})
    find_path(DNET_INCLUDE_DIR NAMES ${header} HINTS ${CMAKE_INCLUDE_PATH})

    if(DNET_INCLUDE_DIR)
        set(DNET_H "${header}")
        break()
    endif(DNET_INCLUDE_DIR)
endforeach(header ${libdnet_h})

foreach(libname ${libdnet_names})
    find_library(DNET_LIB NAMES ${libname} HINTS ${CMAKE_LIBRARY_PATH})

    if(DNET_LIB)
        break()
    endif(DNET_LIB)
endforeach(libname ${libdnet_names})

if(DNET_INCLUDE_DIR AND DNET_LIB)
    #
    # If dnet.h is called dumbnet.h set the correct CFLAGS compiler parameter.
    #
    if(DNET_H STREQUAL "dumbnet.h")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_DUMBNET_H")
    endif(DNET_H STREQUAL "dumbnet.h")

    include_directories(${DNET_INCLUDE_DIR})

    message(STATUS "Found library: Libdnet")
else(DNET_INCLUDE_DIR AND DNET_LIB)
    message(FATAL_ERROR "Could not find Libdnet! Please see in the ArpON 'README' file.")
endif(DNET_INCLUDE_DIR AND DNET_LIB)

#
# EOF
#
# vim:ts=4:expandtab
#
