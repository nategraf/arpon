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
 * $ArpON: arpca.c,v 3.0-ng 01/29/2016 03:06:19 spikey Exp $
 */

#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else   /* !HAVE_DUMBNET_H */
#include <dnet.h>
#endif  /* HAVE_DUMBNET_H */

#include "arpca.h"
#include "exit.h"
#include "intf.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"
#include "unused.h"

/*
 * ARP cache structure definition.
 */
typedef struct arp_cache {
    arp_t *dnet;        /* Dnet ARP cache handle. */
    int fd;             /* ARP cache file descriptor. */
} arpc_t;

/*
 * Function prototypes not exported.
 */
static void arpca_init(void);
static void arpca_destroy(void);
static void arpca_loop(void);
static int  arpca_clean(const struct arp_entry *entry, void *arg);
static void arpca_add(const struct arp_entry *entry);

/*
 * Initialize the ARP cache structure.
 */
static arpc_t *arp = NULL;

/*
 * Initialize the ARP cache mutex.
 */
static pthread_mutex_t arpca_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * Initialize and cleanup the ARP cache.
 */
void
arpca_cleanup(void)
{

    MSG_DEBUG("Start ARP cache cleanup");

    /* Initialize the ARP cache structure. */
    arpca_init();

    MSG_DEBUG("Clean up the ARP cache (possible entries poisoned)..");

    /* Open, loop and cleanup the ARP cache. */
    arpca_loop();

    MSG_DEBUG("End ARP cache cleanup");
}

/*
 * Initialize the ARP cache structure.
 */
static void
arpca_init(void)
{

    /* Allocate the ARP cache structure. */
    if ((arp = (arpc_t *)malloc(sizeof(arpc_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("arpc_t *arp allocate in the memory");

    /* Initialize the dnet ARP cache handle. */
    arp->dnet = NULL;
    MSG_DEBUG("arp->dnet = NULL");

    /* Initialize the ARP cache file descriptor. */
    arp->fd = -1;
    MSG_DEBUG("arp->fd = -1");

    /* Push arpca_destroy() to be called on exit_clean(). */
    exit_push(arpca_destroy, "arpca_destroy");
}

/*
 * Destroy the ARP cache structure.
 */
static void
arpca_destroy(void)
{

    do {
        /* Unlock the mutex of the ARP cache before the destruction. */
        if (pthread_mutex_unlock(&arpca_mtx) != 0)
            break;

        /* ARP cache structure previously allocated? */
        if (arp != NULL) {
            /* Dnet ARP cache handle previously open? */
            if (arp->dnet != NULL) {
                /* Close the dnet ARP cache handle. */
                arp_close(arp->dnet);

                /* Set the dnet ARP cache handle to NULL. */
                arp->dnet = NULL;

                MSG_DEBUG("Close arp->dnet successful");
            }

            /* ARP cache file descriptor previously open? */
            if (arp->fd != -1) {
                /* Close the ARP cache file descriptor. */
                if (close(arp->fd) < 0)
                    break;

                MSG_DEBUG("Close arp->fd successful");
            }

            /* Deallocate the ARP cache structure. */
            free(arp);

            /* Set the ARP cache structure to NULL. */
            arp = NULL;

            MSG_DEBUG("arpc_t *arp deallocate from the memory");
        }

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Open, loop and cleanup the ARP cache.
 */
static void
arpca_loop(void)
{

    do {
        /* Open the dnet ARP cache handle. */
        if ((arp->dnet = arp_open()) == NULL)
            break;

        MSG_DEBUG("Open arp->dnet successful");

        /* Open the ARP cache file descriptor. */
        if ((arp->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
            break;

        MSG_DEBUG("Open arp->fd successful");

        /*
         * Cleanup the current IP entries from the dnet
         * ARP cache handle (possible entries poisoned).
         */
        if (arp_loop(arp->dnet, arpca_clean, NULL) < 0)
            break;

        MSG_DEBUG("Cleanup the ARP cache successful");

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Cleanup the current IP entry from the ARP cache (possible entry poisoned).
 */
static int
arpca_clean(const struct arp_entry *entry, UNUSED(void *arg))
{

    do {
        struct in_addr ip;
        uint32_t network, netmask;
        char *smac = NULL, *sip = NULL, *interface = NULL;

        /* MAC network byte order to string. */
        if ((smac = addr_ntoa(&entry->arp_ha)) == NULL)
            break;

        /* IP network byte order to string. */
        if ((sip = addr_ntoa(&entry->arp_pa)) == NULL)
            break;

        /* Get the IP addr from the entry. */
        ip.s_addr = entry->arp_pa.addr_ip;

        /* Get the Net addr from the interface. */
        network = (intf_getnetwork())->s_addr;

        /* Get the Mask addr from the interface. */
        netmask = (intf_getnetmask())->s_addr;

        /*
         * IP entry is not part of the same network of the interface?
         * Therefore:
         *
         * IP entry is not part of the same network of the interface =
         *      (IP entry addr & Interface Mask addr) != Interface Net addr
         */
        if ((ip.s_addr & netmask) != network) {
            MSG_DEBUG("Skip clean, %s is at %s", sip, smac);
            return 0;
        }

        /*
         * Delete the current IP entry from the ARP cache
         * (possible entry poisoned) (POLICY: CLEAN).
         */
        arpca_delete(&ip);

        /* Get the interface name command option. */
        interface = opt_getinterface();

        /* Print the CLEAN policy info message. */
        ISPN_CLEAN(sip, smac);

        MSG_DEBUG("Cleanup %s from the ARP cache successful", sip);

        return 0;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Delete the IP entry from the ARP cache.
 */
void
arpca_delete(struct in_addr *ip)
{

    do {
        struct arp_entry entry;
        char UNUSED(*sip) = NULL;

        /* Lock the mutex of the ARP cache. */
        if (pthread_mutex_lock(&arpca_mtx) != 0)
            break;

        /* Struct in_addr to struct addr format. */
        addr_pack(&entry.arp_pa, ADDR_TYPE_IP, IP_ADDR_BITS,
            &ip->s_addr, IP_ADDR_LEN);

        /* Restore the value of the errno. */
        errno = 0;

        /* Delete the IP entry from ARP cache via the dnet ARP cache handle. */
        if (arp_delete(arp->dnet, &entry) < 0) {
            /* IP entry not found in the ARP cache or error? */
            if (errno != ENXIO)
                break;
        }

#ifndef NDEBUG
        /* IP network byte order to string. */
        if ((sip = addr_ntoa(&entry.arp_pa)) == NULL)
            break;

        /* IP entry not found in the ARP cache? */
        if (errno == ENXIO)
            MSG_DEBUG("Skip delete %s from the ARP cache successful", sip);
        else
            MSG_DEBUG("Delete %s from the ARP cache successful", sip);
#endif  /* !NDEBUG */

        /* Unlock the mutex of the ARP cache. */
        if (pthread_mutex_unlock(&arpca_mtx) != 0)
            break;

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Overwrite the IP entry as permanent (or not)
 * in the ARP cache with the <IP, MAC> addresses.
 */
void
arpca_overwrite(struct ether_addr *mac, struct in_addr *ip, int op)
{

    do {
        struct arp_entry entry;
        char UNUSED(*smac) = NULL, UNUSED(*sip) = NULL;

        /* Lock the mutex of the ARP cache. */
        if (pthread_mutex_lock(&arpca_mtx) != 0)
            break;

        /* Struct ether_addr to struct addr format. */
        addr_pack(&entry.arp_ha, ADDR_TYPE_ETH, ETH_ADDR_BITS,
            mac->ether_addr_octet, ETH_ADDR_LEN);

        /* Struct in_addr to struct addr format. */
        addr_pack(&entry.arp_pa, ADDR_TYPE_IP, IP_ADDR_BITS,
            &ip->s_addr, IP_ADDR_LEN);

        /* Overwrite the IP entry in the ARP cache as permanent? */
        if (op == ARPCA_PERMANENT) {
            /*
             * Overwrite the permanent IP entry in the
             * ARP cache via the dnet ARP cache handle.
             */
            if (arp_add(arp->dnet, &entry) < 0)
                break;

            MSG_DEBUG("Overwrite as permanent in the ARP cache successful");
        } else {
            /*
             * Overwrite the not permanent IP entry in the
             * ARP cache via the ARP cache file descriptor.
             */
            arpca_add(&entry);
        }

#ifndef NDEBUG
        /* MAC network byte order to string. */
        if ((smac = addr_ntoa(&entry.arp_ha)) == NULL)
            break;

        /* IP network byte order to string. */
        if ((sip = addr_ntoa(&entry.arp_pa)) == NULL)
            break;
#endif  /* !NDEBUG */

        MSG_DEBUG("Overwrite %s at %s in the ARP cache successful", sip, smac);

        /* Unlock the mutex of the ARP cache. */
        if (pthread_mutex_unlock(&arpca_mtx) != 0)
            break;

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * The dnet provides the arp_add() function in order to add a permanent IP
 * entry in the ARP cache. Therefore, this our function provides the same
 * behavior in order to add a not permanent IP entry in the ARP cache.
 */
static void
arpca_add(const struct arp_entry *entry)
{

    do {
        struct arpreq ar;
        char *interface = NULL;

        /* Initialize the ARP request structure. */
        memset(&ar, 0, sizeof(struct arpreq));

        /* Set the protocol address (IP addr) in the ARP request structure. */
        if (addr_ntos(&entry->arp_pa, &ar.arp_pa) < 0)
            break;

        /* Set the hardware address (MAC addr) in the ARP request structure. */
        if (addr_ntos(&entry->arp_ha, &ar.arp_ha) < 0)
            break;

        /*
         * Set the ethernet hardware address format
         * (MAC addr) in the ARP request structure.
         */
        ar.arp_ha.sa_family = ARP_HRD_ETH;

        /*
         * Set the completed entry (the hardware address
         * is valid) flag in the ARP request structure.
         */
        ar.arp_flags = ATF_COM;

        /* Get the interface name command option. */
        interface = opt_getinterface();

        /* Copy the interface in the ARP request structure. */
        strncpy(ar.arp_dev, interface, IF_NAMESIZE);

        /*
         * Overwrite the IP entry in the ARP cache
         * via the ARP cache file descriptor.
         */
        if (ioctl(arp->fd, SIOCSARP, &ar) < 0)
            break;

        MSG_DEBUG("Overwrite as not permanent in the ARP cache successful");

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
