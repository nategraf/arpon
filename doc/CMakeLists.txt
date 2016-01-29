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
# $ArpON: CMakeLists.txt,v 3.0-ng 01/29/2016 02:53:30 spikey Exp $
#

set(arpon_doc_src "${CMAKE_SOURCE_DIR}/doc/arpon")

if(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    install(DIRECTORY ${arpon_doc_src}
        DESTINATION /usr/share/doc
        FILE_PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
        COMPONENT Doc)
else(${CMAKE_INSTALL_PREFIX} STREQUAL "/")
    install(DIRECTORY ${arpon_doc_src}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/doc
        FILE_PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
        COMPONENT Doc)
endif(${CMAKE_INSTALL_PREFIX} STREQUAL "/")

#
# EOF
#
# vim:ts=4:expandtab
#
