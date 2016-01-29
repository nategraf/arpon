/*
 * Copyright (C) 2008-2016 Andrea Di Pasquale <spikey.it@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $ArpON: std.c,v 3.0-ng 01/29/2016 03:07:22 spikey Exp $
 */

#include <stdio.h>

#include "msg.h"
#include "std.h"
#include "ver.h"

/*
 * Print the version.
 */
void
std_version(void)
{

    INFO("%s \"%s\" %s (%s)", VER_NAMESHORT, VER_NAMELONG, VER_NUMBER, VER_URL);

    MSG_DEBUG("Print version successful");
}

/*
 * Print the help screen.
 */
void
std_help(void)
{

    /* Print the version. */
    std_version();

    INFO("Usage: %s [OPTIONS] [SARPI | DARPI | HARPI]", VER_NAMECASE);
    INFO("");
    INFO("GENERAL OPTIONS");
    INFO("  -d, --daemon                Daemonize the %s", VER_NAMECASE);
    INFO("  -i, --interface <interface> Use the specified network interface");
    INFO("");
    INFO("SARPI 'STATIC ARP INSPECTION' OPTION");
    INFO("  -S, --sarpi                 Run SARPI anti ARP spoofing technique");
    INFO("")
    INFO("DARPI 'DYNAMIC ARP INSPECTION' OPTION");
    INFO("  -D, --darpi                 Run DARPI anti ARP spoofing technique");
    INFO("");
    INFO("HARPI 'HYBRID ARP INSPECTION' OPTION");
    INFO("  -H, --harpi                 Run HARPI anti ARP spoofing technique");
    INFO("");
    INFO("STANDARD OPTIONS");
    INFO("  -v, --version               Print the version and exit");
    INFO("  -h, --help                  Print this help screen and exit");
    INFO("");
    INFO("SEE THE MAN PAGE FOR MANY DESCRIPTIONS AND EXAMPLES.");

    MSG_DEBUG("Print help successful");
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
