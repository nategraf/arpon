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
# $ArpON: FindHeaders.cmake,v 3.0-ng 01/29/2016 02:49:20 spikey Exp $
#

include(CheckIncludeFile)

check_include_file(net/ethernet.h HAVE_NET_ETHERNET_H)
if(NOT HAVE_NET_ETHERNET_H)
    message(FATAL_ERROR "Could not find net/ethernet.h!")
endif(NOT HAVE_NET_ETHERNET_H)

check_include_file(net/if.h HAVE_NET_IF_H)
if(NOT HAVE_NET_IF_H)
    message(FATAL_ERROR "Could not find net/if.h!")
endif(NOT HAVE_NET_IF_H)

check_include_file(net/if_arp.h HAVE_NET_IF_ARP_H)
if(NOT HAVE_NET_IF_ARP_H)
    message(FATAL_ERROR "Could not find net/if_arp.h!")
endif(NOT HAVE_NET_IF_ARP_H)

check_include_file(netinet/ether.h HAVE_NETINET_ETHER_H)
if(NOT HAVE_NETINET_ETHER_H)
    message(FATAL_ERROR "Could not find netinet/ether.h!")
endif(NOT HAVE_NETINET_ETHER_H)

check_include_file(netinet/if_ether.h HAVE_NETINET_IF_ETHER_H)
if(NOT HAVE_NETINET_IF_ETHER_H)
    message(FATAL_ERROR "Could not find netinet/if_ether.h!")
endif(NOT HAVE_NETINET_IF_ETHER_H)

check_include_file(netinet/in.h HAVE_NETINET_IN_H)
if(NOT HAVE_NETINET_IN_H)
    message(FATAL_ERROR "Could not find netinet/in.h!")
endif(NOT HAVE_NETINET_IN_H)

check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
if(NOT HAVE_ARPA_INET_H)
    message(FATAL_ERROR "Could not find arpa/inet.h!")
endif(NOT HAVE_ARPA_INET_H)

check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
if(NOT HAVE_SYS_SOCKET_H)
    message(FATAL_ERROR "Could not find sys/socket.h!")
endif(NOT HAVE_SYS_SOCKET_H)

check_include_file(sys/types.h HAVE_SYS_TYPES_H)
if(NOT HAVE_SYS_TYPES_H)
    message(FATAL_ERROR "Could not find sys/types.h!")
endif(NOT HAVE_SYS_TYPES_H)

check_include_file(sys/stat.h HAVE_SYS_STAT_H)
if(NOT HAVE_SYS_STAT_H)
    message(FATAL_ERROR "Could not find sys/stat.h!")
endif(NOT HAVE_SYS_STAT_H)

check_include_file(sys/time.h HAVE_SYS_TIME_H)
if(NOT HAVE_SYS_TIME_H)
    message(FATAL_ERROR "Could not find sys/time.h")
endif(NOT HAVE_SYS_TIME_H)

check_include_file(sys/select.h HAVE_SYS_SELECT_H)
if(NOT HAVE_SYS_SELECT_H)
    message(FATAL_ERROR "Could not find sys/select.h")
endif(NOT HAVE_SYS_SELECT_H)

check_include_file(sys/ioctl.h HAVE_SYS_IOCTL_H)
if(NOT HAVE_SYS_IOCTL_H)
    message(FATAL_ERROR "Could not find sys/ioctl.h")
endif(NOT HAVE_SYS_IOCTL_H)

check_include_file(stdio.h HAVE_STDIO_H)
if(NOT HAVE_STDIO_H)
    message(FATAL_ERROR "Could not find stdio.h!")
endif(NOT HAVE_STDIO_H)

check_include_file(stdlib.h HAVE_STDLIB_H)
if(NOT HAVE_STDLIB_H)
    message(FATAL_ERROR "Could not find stdlib.h!")
endif(NOT HAVE_STDLIB_H)

check_include_file(stdbool.h HAVE_STDBOOL_H)
if(NOT HAVE_STDBOOL_H)
    message(FATAL_ERROR "Could not find stdbool.h!")
endif(NOT HAVE_STDBOOL_H)

check_include_file(stdarg.h HAVE_STDARG_H)
if(NOT HAVE_STDARG_H)
    message(FATAL_ERROR "Could not find stdarg.h!")
endif(NOT HAVE_STDARG_H)

check_include_file(unistd.h HAVE_UNISTD_H)
if(NOT HAVE_UNISTD_H)
    message(FATAL_ERROR "Could not find unistd.h!")
endif(NOT HAVE_UNISTD_H)

check_include_file(string.h HAVE_STRING_H)
if(NOT HAVE_STRING_H)
    message(FATAL_ERROR "Could not find string.h!")
endif(NOT HAVE_STRING_H)

check_include_file(getopt.h HAVE_GETOPT_H)
if(NOT HAVE_GETOPT_H)
    message(FATAL_ERROR "Could not find getopt.h!")
endif(NOT HAVE_GETOPT_H)

check_include_file(fcntl.h HAVE_FCNTL_H)
if(NOT HAVE_FCNTL_H)
    message(FATAL_ERROR "Could not find fcntl.h!")
endif(NOT HAVE_FCNTL_H)

check_include_file(time.h HAVE_TIME_H)
if(NOT HAVE_TIME_H)
    message(FATAL_ERROR "Could not find time.h!")
endif(NOT HAVE_TIME_H)

check_include_file(signal.h HAVE_SIGNAL_H)
if(NOT HAVE_SIGNAL_H)
    message(FATAL_ERROR "Could not find signal.h!")
endif(NOT HAVE_SIGNAL_H)

check_include_file(errno.h HAVE_ERRNO_H)
if(NOT HAVE_ERRNO_H)
    message(FATAL_ERROR "Could not find errno.h!")
endif(NOT HAVE_ERRNO_H)

check_include_file(assert.h HAVE_ASSERT_H)
if(NOT HAVE_ASSERT_H)
    message(FATAL_ERROR "Could not find assert.h!")
endif(NOT HAVE_ASSERT_H)

#
# EOF
#
# vim:ts=4:expandtab
#
