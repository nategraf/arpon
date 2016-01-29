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
# $ArpON: FindLibrt.cmake,v 3.0-ng 01/29/2016 02:48:55 spikey Exp $
#

#
# FindLibrt search and find the Librt library path and header path
#
# Usage:
#
#  find_package(Librt)
#  ...
#  target_link_libraries(... ${RT_LIB})
#
# The following variables are to be set:
#
#   CMAKE_INCLUDE_PATH - find the time.h
#   CMAKE_LIBRARY_PATH - find the library
#
# Variable defined by this module:
#
#   RT_INCLUDE_DIR - header directory
#   RT_LIB         - library to link
#

find_path(RT_INCLUDE_DIR NAMES time.h HINTS ${CMAKE_INCLUDE_PATH})
find_library(RT_LIB NAMES rt HINTS ${CMAKE_LIBRARY_PATH})

if(RT_INCLUDE_DIR AND RT_LIB)
    include_directories(${RT_INCLUDE_DIR})

    message(STATUS "Found library: Librt")
else(RT_INCLUDE_DIR AND RT_LIB)
    message(FATAL_ERROR "Could not found Librt! Please see in the ArpON 'README' file.")
endif(RT_INCLUDE_DIR AND RT_LIB)

#
# EOF
#
# vim:ts=4:expandtab
#
