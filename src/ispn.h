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
 * $ArpON: ispn.h,v 3.0-ng 01/29/2016 03:04:54 spikey Exp $
 */

#ifndef _ISPN_H_
#define _ISPN_H_

/*
 * ARP Inspection codes exported.
 */
#define ISPN_NONE       (1 << 0)    /* No ARP Inspection. */
#define ISPN_SARPI      (1 << 1)    /* Static ARP Inspection. */
#define ISPN_DARPI      (1 << 2)    /* Dynamic ARP Inspection. */
#define ISPN_HARPI      (1 << 3)    /* Hybrid ARP Inspection. */

/*
 * ARP Inspection code to string.
 */
#define ISPN_ATOA(x)    x == ISPN_SARPI ? "SARPI" :                 \
                        x == ISPN_DARPI ? "DARPI" :                 \
                        x == ISPN_HARPI ? "HARPI" : "NONE"

/*
 * Print the CLEAN policy info message to standard output and log file.
 */
#define ISPN_CLEAN(ip, mac) do {                                    \
    MSG_INFO("CLEAN, %s was at %s on %s", ip, mac, interface);      \
} while (0)

/*
 * Print the UPDATE policy info message to standard output and log file.
 */
#define ISPN_UPDATE(ip, mac) do {                                   \
    MSG_INFO("UPDATE, %s is at %s on %s", ip, mac, interface);      \
} while (0)

/*
 * Print the REFRESH policy info message to standard output and log file.
 */
#define ISPN_REFRESH(ip, mac) do {                                  \
    MSG_INFO("REFRESH, %s is at %s on %s", ip, mac, interface);     \
} while (0)

/*
 * Print the ALLOW policy info message to standard output and log file.
 */
#define ISPN_ALLOW(ip, mac) do {                                    \
    MSG_INFO("ALLOW, %s is at %s on %s", ip, mac, interface);       \
} while (0)

/*
 * Print the DENY policy info message to standard output and log file.
 */
#define ISPN_DENY(ip, mac) do {                                     \
    MSG_INFO("DENY, %s was at %s on %s", ip, mac, interface);       \
} while (0)

/*
 * Function prototype exported.
 */
extern void ispn_start(void);

#endif  /* !_ISPN_H_ */

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
