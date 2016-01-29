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
 * $ArpON: intf.h,v 3.0-ng 01/29/2016 02:56:56 spikey Exp $
 */

#ifndef _INTF_H_
#define _INTF_H_

/*
 * MAC addr string length.
 */
#define INTF_ETHERSTRLEN            18          /* 18 bytes. */

/*
 * ARP packet op codes exported.
 */
#define INTF_ARPOP_INIT             0x00        /* No ARP. */
#define INTF_ARPOP_REQUEST          0x01        /* ARP request. */
#define INTF_ARPOP_REPLY            0x02        /* ARP reply. */
#define INTF_ARPOP_GRATUITOUS       0x04        /* Gratuitous ARP. */
#define INTF_ARPOP_PROBE            0x08        /* Probe ARP. */
#define INTF_ARPOP_OUTBOUND         0x10        /* ARP outbound. */
#define INTF_ARPOP_INBOUND          0x20        /* ARP inbound. */

/*
 * Print the outbound packet info message to standard output and log file.
 */
#define INTF_OUTBOUND(type) do {                                            \
    MSG_DEBUG(">>>>>>>>>>>>>>>>>>>>> PACKET TRACER >>>>>>>>>>>>>>>>>>>>>"); \
    MSG_DEBUG("%s, outbound on %s", type, interface);                       \
    MSG_DEBUG("src mac = %s, src ip = %s", smacsrc, sipsrc);                \
    MSG_DEBUG("dst mac = %s, dst ip = %s", smacdst, sipdst);                \
} while (0)

/*
 * Print the inbound packet info message to standard output and log file.
 */
#define INTF_INBOUND(type) do {                                             \
    MSG_DEBUG("<<<<<<<<<<<<<<<<<<<<< PACKET TRACER <<<<<<<<<<<<<<<<<<<<<"); \
    MSG_DEBUG("%s, inbound on %s", type, interface);                        \
    MSG_DEBUG("src mac = %s, src ip = %s", smacsrc, sipsrc);                \
    MSG_DEBUG("dst mac = %s, dst ip = %s", smacdst, sipdst);                \
} while (0)

/*
 * Function prototypes exported.
 */
extern void              intf_configure(void);
extern struct in_addr   *intf_getnetwork(void);
extern struct in_addr   *intf_getnetmask(void);
extern void             *intf_capture(void *callback);
extern void              intf_inject(int op, struct in_addr *ip);

#endif  /* !_INTF_H_ */

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
