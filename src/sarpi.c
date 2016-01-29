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
 * $ArpON: sarpi.c,v 3.0-ng 01/29/2016 03:03:55 spikey Exp $
 */

#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "arpca.h"
#include "intf.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"
#include "sarpica.h"
#include "sarpi.h"
#include "unused.h"

/*
 * SARPI live capture handler of the I/O ARP packets
 * read from the network traffic of the interface.
 */
void
sarpi_handler(int op, struct ether_addr *macsrc, struct in_addr *ipsrc,
    UNUSED(struct ether_addr *macdst), UNUSED(struct in_addr *ipdst))
{

    do {
        char smacsrc[INTF_ETHERSTRLEN], sipsrc[INET_ADDRSTRLEN],
            UNUSED(smacdst[INTF_ETHERSTRLEN]), UNUSED(sipdst[INET_ADDRSTRLEN]),
            *interface = NULL;
        struct ether_addr *macentry = NULL;

        MSG_DEBUG("Start SARPI live capture handler");

        /* Get the interface name command option. */
        interface = opt_getinterface();

        /* MAC src addr network byte order to string. */
        strncpy(smacsrc, ether_ntoa(macsrc), INTF_ETHERSTRLEN);

        /* IP src addr network byte order to string. */
        strncpy(sipsrc, inet_ntoa(*ipsrc), INET_ADDRSTRLEN);

#ifndef NDEBUG
        /* MAC dst addr network byte order to string. */
        strncpy(smacdst, ether_ntoa(macdst), INTF_ETHERSTRLEN);

        /* IP dst addr network byte order to string. */
        strncpy(sipdst, inet_ntoa(*ipdst), INET_ADDRSTRLEN);
#endif  /* !NDEBUG */

        /* Check the type of the ARP packet read. */
        if (op & INTF_ARPOP_REQUEST) {
            /*
             * Check the I/O bound direction of the ARP request
             * packet read (sent by us or sent to us).
             */
            if (op & INTF_ARPOP_OUTBOUND) {
                /*
                 * Check if the ARP request packet is a gratuitous
                 * ARP request packet, probe ARP request packet or
                 * simple ARP request packet.
                 */
                if (op & INTF_ARPOP_GRATUITOUS) {
                    /* Gratuitous ARP request packet to outbound. */
                    INTF_OUTBOUND("Gratuitous ARP request");
                } else if (op & INTF_ARPOP_PROBE) {
                    /* Probe ARP request packet to outbound. */
                    INTF_OUTBOUND("Probe ARP request");
                } else {
                    /* Simple ARP request packet to outbound. */
                    INTF_OUTBOUND("ARP request");
                }

                /* Break immediately. */
                break;
            } else if (op & INTF_ARPOP_INBOUND) {
                /*
                 * Check if the ARP request packet is a gratuitous
                 * ARP request packet, probe ARP request packet or
                 * simple ARP request packet.
                 */
                if (op & INTF_ARPOP_GRATUITOUS) {
                    /* Gratuitous ARP request packet from inbound. */
                    INTF_INBOUND("Gratuitous ARP request");
                } else if (op & INTF_ARPOP_PROBE) {
                    /* Probe ARP request packet from inbound. */
                    INTF_INBOUND("Probe ARP request");

                    /*
                     * Send a probe ARP reply to source IP (with MAC
                     * broadcast) address of the ARP request packet
                     * (in the next ARP packet read, follow the
                     * outbound ARP reply).
                     */
                    intf_inject(ARPOP_REPLY, ipsrc);

                    /* Break immediately. */
                    break;
                } else {
                    /* Simple ARP request packet from inbound. */
                    INTF_INBOUND("ARP request");

                    /*
                     * Send an ARP reply to source IP (with MAC broadcast)
                     * address of the ARP request packet (in the next ARP
                     * packet read, follow the outbound ARP reply).
                     */
                    intf_inject(ARPOP_REPLY, ipsrc);
                }
            }
        } else if (op & INTF_ARPOP_REPLY) {
            /*
             * Check the I/O bound direction of the ARP reply
             * packet read (sent by us or sent to us).
             */
            if (op & INTF_ARPOP_OUTBOUND) {
                /*
                 * Check if the ARP reply packet is a gratuitous
                 * ARP reply packet, probe ARP reply packet or
                 * simple ARP reply packet.
                 */
                if (op & INTF_ARPOP_GRATUITOUS) {
                    /* Gratuitous ARP reply packet to outbound. */
                    INTF_OUTBOUND("Gratuitous ARP reply");
                } else if (op & INTF_ARPOP_PROBE) {
                    /* Probe ARP reply packet to outbound. */
                    INTF_OUTBOUND("Probe ARP reply");
                } else {
                    /* Simple ARP reply packet to outbound. */
                    INTF_OUTBOUND("ARP reply");
                }

                /* Break immediately. */
                break;
            } else if (op & INTF_ARPOP_INBOUND) {
                /*
                 * Check if the ARP reply packet is a gratuitous
                 * ARP reply packet, probe ARP reply packet or
                 * simple ARP reply packet.
                 */
                if (op & INTF_ARPOP_GRATUITOUS) {
                    /* Gratuitous ARP reply packet from inbound. */
                    INTF_INBOUND("Gratuitous ARP reply");
                } else if (op & INTF_ARPOP_PROBE) {
                    /* Probe ARP reply packet from inbound. */
                    INTF_INBOUND("Probe ARP reply");

                    /* Break immediately. */
                    break;
                } else {
                    /* Simple ARP reply packet from inbound. */
                    INTF_INBOUND("ARP reply");
                }
            }
        }

        /*
         * Check if the source IP address of the ARP packet
         * exists in the SARPI cache.
         */
        if ((macentry = sarpica_ismember(ipsrc)) == NULL) {
            /*
             * Overwrite the not permanent IP entry in the ARP cache of
             * the source IP address of the ARP packet with the same
             * source <IP, MAC> addresses (POLICY: ALLOW).
             */
            arpca_overwrite(macsrc, ipsrc, ARPCA_NOTPERMANENT);

            /* Print the ALLOW policy info message. */
            ISPN_ALLOW(sipsrc, smacsrc);
        } else {
            char *smacentry = NULL;

            /*
             * Overwrite the permanent IP entry in the ARP cache of the
             * source IP address of the ARP packet with the <IP, MAC>
             * entry from the SARPI cache (POLICY: REFRESH).
             */
            arpca_overwrite(macentry, ipsrc, ARPCA_PERMANENT);

            /* MAC entry addr network byte order to string. */
            smacentry = ether_ntoa(macentry);

            /* Print the REFRESH policy info message. */
            ISPN_REFRESH(sipsrc, smacentry);
        }
    } while (0);

    MSG_DEBUG("End SARPI live capture handler");
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
