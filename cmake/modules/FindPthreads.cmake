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
# $ArpON: FindPthreads.cmake,v 3.0-ng 01/29/2016 02:51:08 spikey Exp $
#

#
# FindPthreads search and find the Pthreads library path and header path
#
# Usage:
#
#  find_package(Pthreads)
#  ...
#  target_link_libraries(... ${PTHREADS_LIB})
#
# The following variables are to be set:
#
#   CMAKE_INCLUDE_PATH - find the pthread.h
#   CMAKE_LIBRARY_PATH - find the library
#
# Variable defined by this module:
#
#   PTHREADS_INCLUDE_DIR - header directory
#   PTHREADS_LIB         - library to link
#

find_path(PTHREADS_INCLUDE_DIR NAMES pthread.h HINTS ${CMAKE_INCLUDE_PATH})
find_library(PTHREADS_LIB NAMES pthread HINTS ${CMAKE_LIBRARY_PATH})

if(PTHREADS_INCLUDE_DIR AND PTHREADS_LIB)
    include_directories(${PTHREADS_INCLUDE_DIR})

    message(STATUS "Found library: Pthreads")
else(PTHREADS_INCLUDE_DIR AND PTHREADS_LIB)
    message(FATAL_ERROR "Could not found Pthreads! Please see in the ArpON 'README' file.")
endif(PTHREADS_INCLUDE_DIR AND PTHREADS_LIB)

#
# EOF
#
# vim:ts=4:expandtab
#
