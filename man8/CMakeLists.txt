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
# $ArpON: CMakeLists.txt,v 3.0-ng 01/29/2016 02:55:15 spikey Exp $
#

set(arpon_man_src "${CMAKE_SOURCE_DIR}/man8/arpon.8")

if(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    set(ARPON_DOC_FILE
        "/usr/share/doc/arpon/index.html")
    set(ARPON_ETC_FILE
        "/etc/arpon.conf")
    set(ARPON_LOG_FILE
        "/var/log/arpon.log")
    set(ARPON_PID_FILE
        "/var/run/arpon.pid")
else(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    set(ARPON_DOC_FILE
        "${CMAKE_INSTALL_PREFIX}/share/doc/arpon/index.html")
    set(ARPON_ETC_FILE
        "${CMAKE_INSTALL_PREFIX}/etc/arpon.conf")
    set(ARPON_LOG_FILE
        "${CMAKE_INSTALL_PREFIX}/log/arpon.log")
    set(ARPON_PID_FILE
        "${CMAKE_INSTALL_PREFIX}/run/arpon.pid")
endif(${CMAKE_INSTALL_PREFIX} STREQUAL "/")

file(READ ${arpon_man_src} FILE_CONTENT)
string(REGEX REPLACE "ARPON_DOC" "${ARPON_DOC_FILE}"
    MODIFIED_FILE_CONTENT1 "${FILE_CONTENT}")

string(REGEX REPLACE "ARPON_ETC" "${ARPON_ETC_FILE}"
    MODIFIED_FILE_CONTENT2 "${MODIFIED_FILE_CONTENT1}")

string(REGEX REPLACE "ARPON_LOG" "${ARPON_LOG_FILE}"
    MODIFIED_FILE_CONTENT3 "${MODIFIED_FILE_CONTENT2}")

string(REGEX REPLACE "ARPON_PID" "${ARPON_PID_FILE}"
    MODIFIED_FILE_CONTENT4 "${MODIFIED_FILE_CONTENT3}")
file(WRITE ${PROJECT_BINARY_DIR}/man8/arpon.8 "${MODIFIED_FILE_CONTENT4}")

if(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    install(FILES
        ${PROJECT_BINARY_DIR}/man8/arpon.8 DESTINATION /usr/share/man/man8
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
        COMPONENT Man)
else(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    install(FILES
        ${PROJECT_BINARY_DIR}/man8/arpon.8 DESTINATION
        ${CMAKE_INSTALL_PREFIX}/share/man/man8
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
        COMPONENT Man)
endif(${CMAKE_INSTALL_PREFIX} STREQUAL "/")

#
# EOF
#
# vim:ts=4:expandtab
#
