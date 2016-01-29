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
# $ArpON: CMakeLists.txt,v 3.0-ng 01/29/2016 03:07:40 spikey Exp $
#

if(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    set(ARPON_SBIN /sbin/arpon)
    set(ARPON_DOC /usr/share/doc/arpon/index.html)
    set(ARPON_ETC /etc/arpon.conf)
    set(ARPON_LOG /var/log/arpon.log)
    set(ARPON_PID /var/run/arpon.pid)
    set(install_prefix /sbin)
else(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    set(ARPON_SBIN ${CMAKE_INSTALL_PREFIX}/sbin/arpon)
    set(ARPON_DOC ${CMAKE_INSTALL_PREFIX}/share/doc/arpon/index.html)
    set(ARPON_ETC ${CMAKE_INSTALL_PREFIX}/etc/arpon.conf)
    set(ARPON_LOG ${CMAKE_INSTALL_PREFIX}/log/arpon.log)
    set(ARPON_PID ${CMAKE_INSTALL_PREFIX}/run/arpon.pid)
    set(install_prefix ${CMAKE_INSTALL_PREFIX}/sbin)
endif(${CMAKE_INSTALL_PREFIX} STREQUAL "/")

configure_file(
    "${PROJECT_SOURCE_DIR}/src/config.h.in"
    "${PROJECT_BINARY_DIR}/src/config.h")

include_directories("${PROJECT_BINARY_DIR}/src")
add_executable(
    arpon
    arpca.c
    arpca.h
    config.h.in
    darpi.c
    darpica.c
    darpica.h
    darpi.h
    dmn.c
    dmn.h
    env.c
    env.h
    exit.c
    exit.h
    harpi.c
    harpi.h
    intf.c
    intf.h
    ispn.c
    ispn.h
    main.c
    msg.c
    msg.h
    opt.c
    opt.h
    proc.c
    proc.h
    queue.h
    rt.c
    rt.h
    sarpi.c
    sarpica.c
    sarpica.h
    sarpi.h
    sig.c
    sig.h
    std.c
    std.h
    thd.c
    thd.h
    unused.h
    ver.h)

target_link_libraries(arpon
    ${PTHREADS_LIB} ${RT_LIB} ${PCAP_LIB} ${NET_LIB} ${DNET_LIB})

set_target_properties(arpon
    PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)

install(TARGETS arpon
        RUNTIME DESTINATION ${install_prefix}
        COMPONENT Application)

#
# EOF
#
# vim:ts=4:expandtab
#
