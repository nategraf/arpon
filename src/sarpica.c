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
 * $ArpON: sarpica.c,v 3.0-ng 01/29/2016 03:09:44 spikey Exp $
 */

#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "arpca.h"
#include "config.h"
#include "exit.h"
#include "intf.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"
#include "queue.h"
#include "sarpica.h"
#include "thd.h"
#include "unused.h"

/*
 * Configuration file permissions to 644.
 */
#define SARPICA_ETCPERMS        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

/*
 * Max configuration file line length.
 */
#define SARPICA_LINESIZE        512     /* 512 bytes. */

/*
 * SARPI timeout of the SARPI cache
 * (Expiry for each loop of the SARPI cache handler).
 */
#define SARPICA_LOOPTIMEOUT     600     /* 600 seconds = 10 minuts. */

/*
 * SARPI cache queue structure definition.
 */
typedef struct sca_queue {
    struct ether_addr mac;              /* SARPI cache MAC addr entry. */
    struct in_addr ip;                  /* SARPI cache IP addr entry. */

    TAILQ_ENTRY(sca_queue) next;        /* Next SARPI cache queue element. */
} sca_t;

/*
 * Function prototypes not exported.
 */
static void  sarpica_init(void);
static void  sarpica_destroy(void);
static void  sarpica_dequeuetop(void);
static FILE *sarpica_initconf(void);
static void  sarpica_loadconf(FILE *conf);
static void  sarpica_enqueue(struct ether_addr *mac, struct in_addr *ip);
static void  sarpica_destroyconf(FILE **conf);
static void *sarpica_handler(void *arg);

/*
 * Initialize the SARPI cache queue structure.
 */
static TAILQ_HEAD(sca, sca_queue) sca_head = TAILQ_HEAD_INITIALIZER(sca_head);

/*
 * Configure the SARPI cache.
 */
void
sarpica_configure(void)
{
    FILE *conf = NULL;

    MSG_DEBUG("Start SARPI cache configure");

    /* Initialize the SARPI cache queue structure. */
    sarpica_init();

    /* Initialize the configuration file stream. */
    conf = sarpica_initconf();

    /* Load the SARPI cache queue structure from the config file stream. */
    sarpica_loadconf(conf);

    /* Destroy the configuration file stream. */
    sarpica_destroyconf(&conf);

    /* Register the SARPI cache handler thread. */
    thd_register(sarpica_handler, NULL, "sarpica_handler");

    MSG_DEBUG("End SARPI cache configure");
}

/*
 * Initialize the SARPI cache queue structure.
 */
static void
sarpica_init(void)
{

    /* Set the SARPI cache queue structure to NULL. */
    TAILQ_INIT(&sca_head);
    MSG_DEBUG("Initialize SARPI cache queue successful");

    /* Push sarpica_destroy() to be called on exit_clean(). */
    exit_push(sarpica_destroy, "sarpica_destroy");
}

/*
 * Destroy the SARPI cache queue structure.
 */
static void
sarpica_destroy(void)
{

    /* No empty SARPI cache queue structure? */
    if (TAILQ_EMPTY(&sca_head) == 0) {
        /* Loop until the SARPI cache queue structure is empty. */
        do {
            /* Dequeue the SARPI cache entry. */
            sarpica_dequeuetop();
        } while (TAILQ_EMPTY(&sca_head) == 0);

        /* Re-initialize the SARPI cache queue structure to NULL. */
        TAILQ_INIT(&sca_head);
    }

    MSG_DEBUG("Destroy SARPI cache queue successful");
}

/*
 * Dequeue the SARPI cache queue element from the SARPI cache queue structure.
 */
static void
sarpica_dequeuetop(void)
{
    sca_t *cur = NULL;
    char UNUSED(*smac) = NULL, UNUSED(*sip) = NULL;

    /* Get the first SARPI cache queue element. */
    cur = TAILQ_FIRST(&sca_head);

    /* Dequeue the first SARPI cache queue element. */
    TAILQ_REMOVE(&sca_head, cur, next);

#ifndef NDEBUG
    /* Get the SARPI cache MAC addr entry. */
    smac = ether_ntoa(&cur->mac);
#endif  /* !NDEBUG */

    MSG_DEBUG("cur->mac = %s", smac);

#ifndef NDEBUG
    /* Get the SARPI cache IP addr entry. */
    sip = inet_ntoa(cur->ip);
#endif  /* !NDEBUG */

    MSG_DEBUG("cur->ip = %s", sip);

    /* Deallocate the SARPI cache queue element. */
    free(cur);

    MSG_DEBUG("sca_t *cur deallocate from the memory");
    MSG_DEBUG("Dequeue <%s, %s> SARPI cache entry successful", smac, sip);
}

/*
 * Initialize the configuration file stream.
 */
static FILE *
sarpica_initconf(void)
{

    do {
        struct stat stats;
        FILE *conf = NULL;

        /* Check if the configuration file exist. */
        if (stat(ETC_FILE, &stats) < 0) {
            if (errno == ENOENT) {
                MSG_WARN("%s is not exist", ETC_FILE);
                exit(EXIT_FAILURE);
            } else {
                break;
            }
        }

        /* Check if the configuration file is a regular file. */
        if (S_ISREG(stats.st_mode) == 0) {
            MSG_WARN("%s is not a regular file", ETC_FILE);
            exit(EXIT_FAILURE);
        }

        /* Fix the configuration file perms to 644. */
        if (chmod(ETC_FILE, SARPICA_ETCPERMS) < 0)
            break;

        /* Open the configuration file stream to read. */
        if ((conf = fopen(ETC_FILE, "r")) == NULL)
            break;

        MSG_DEBUG("Open %s successful", ETC_FILE);

        return conf;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Add the <IP, MAC> entries in the SARPI cache queue structure
 * with the <IP, MAC> entries from the configuration file stream.
 */
static void
sarpica_loadconf(FILE *conf)
{
    char line[SARPICA_LINESIZE];
    int linenum = 0;

    MSG_DEBUG("Start configuration file loader");

    /* Loop until the end of configuration file is reached. */
    while (fgets(line, SARPICA_LINESIZE, conf) != NULL) {
        char sip[INET_ADDRSTRLEN], smac[INTF_ETHERSTRLEN];
        struct in_addr ip;
        struct ether_addr *mac = NULL;
        char *p = NULL, *q = NULL;
        uint32_t network, netmask;

        /* Update the line number counter. */
        linenum++;

        /* Skip the comment line. */
        if (strchr(line, '#') != NULL)
            continue;

        /* Trim out the new line. */
        if ((p = strchr(line, '\n')))
            *p = '\0';

        /* Set q pointer to line. */
        q = line;

        /* Trim out the initial spaces of the line. */
        while (q < line + sizeof(line) && *q == ' ')
            q++;

        /* Skip the empty line. */
        if (line[0] == '\0' || *q == '\0')
            continue;

        /* Get the IP and MAC addrs from the line. */
        if (sscanf(q, "%15s %17s", sip, smac) != 2) {
            MSG_WARN("Invalid line in %s at %d line", ETC_FILE, linenum);
            exit(EXIT_FAILURE);
        }

        /* MAC addr string to MAC addr network byte order. */
        if ((mac = ether_aton(smac)) == NULL) {
            MSG_WARN("Invalid MAC address in %s at %d line", ETC_FILE, linenum);
            exit(EXIT_FAILURE);
        }

        /* IP addr string to IP addr network byte order. */
        if (inet_aton(sip, &ip) == 0) {
            MSG_WARN("Invalid IP address in %s at %d line", ETC_FILE, linenum);
            exit(EXIT_FAILURE);
        }

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
            MSG_DEBUG("Skip line read = %s %s", sip, smac);
            continue;
        }

        MSG_DEBUG("Line read = %s %s", sip, smac);

        /* Add the <IP, MAC> entry in the SARPI cache queue structure. */
        sarpica_enqueue(mac, &ip);
    }

    MSG_DEBUG("End configuration file loader");
}

/*
 * Enqueue the SARPI cache queue element in the SARPI cache queue structure.
 */
static void
sarpica_enqueue(struct ether_addr *mac, struct in_addr *ip)
{
    sca_t *new = NULL;
    char UNUSED(*smac) = NULL, UNUSED(*sip) = NULL;

    /* Allocate the SARPI cache queue element. */
    if ((new = (sca_t *)malloc(sizeof(sca_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("sca_t *new allocate in the memory");

    /* Initialize the SARPI cache MAC addr entry. */
    new->mac = *mac;

#ifndef NDEBUG
    /* MAC addr network byte order to string. */
    smac = ether_ntoa(&new->mac);
#endif  /* !NDEBUG */

    MSG_DEBUG("new->mac = %s", smac);

    /* Initialize the SARPI cache IP addr entry. */
    new->ip = *ip;

#ifndef NDEBUG
    /* IP addr network byte order to string. */
    sip = inet_ntoa(new->ip);
#endif  /* !NDEBUG */

    MSG_DEBUG("new->ip = %s", sip);

    /* Empty SARPI cache queue structure? */
    if (TAILQ_EMPTY(&sca_head) != 0) {
        /* Enqueue the SARPI cache queue element in the head. */
        TAILQ_INSERT_HEAD(&sca_head, new, next);
        MSG_DEBUG("H-Enqueue <%s, %s> SARPI cache entry successful", smac, sip);
    } else {
        /* Enqueue the SARPI cache queue element in the tail. */
        TAILQ_INSERT_TAIL(&sca_head, new, next);
        MSG_DEBUG("T-Enqueue <%s, %s> SARPI cache entry successful", smac, sip);
    }
}

/*
 * Find a SARPI cache queue element in the SARPI cache queue structure.
 */
struct ether_addr *
sarpica_ismember(struct in_addr *ip)
{
    char UNUSED(*smac) = NULL, UNUSED(*sip) = NULL;

    /* No empty SARPI cache queue structure? */
    if (TAILQ_EMPTY(&sca_head) == 0) {
        sca_t *cur = NULL;

        /* Looking the IP addr in the SARPI cache queue structure. */
        TAILQ_FOREACH(cur, &sca_head, next) {
            if (ip->s_addr == cur->ip.s_addr) {
#ifndef NDEBUG
                /*
                 * IP addr network byte order of the
                 * SARPI cache queue element to string.
                 */
                sip = inet_ntoa(cur->ip);

                /*
                 * MAC addr network byte order of the
                 * SARPI cache queue element to string.
                 */
                smac = ether_ntoa(&cur->mac);
#endif  /* !NDEBUG */

                /* IP addr found, it is a SARPI cache queue element. */
                MSG_DEBUG("<%s, %s> SARPI cache entry found", smac, sip);

                return &cur->mac;
            }
        }
    }

#ifndef NDEBUG
    /* IP addr network byte order to string. */
    sip = inet_ntoa(*ip);
#endif  /* !NDEBUG */

    /* IP addr not found, it is not a SARPI cache queue element. */
    MSG_DEBUG("<%s> SARPI cache entry not found", sip);

    return NULL;
}

/*
 * Destroy the configuration file stream.
 */
static void
sarpica_destroyconf(FILE **conf)
{

    /* Close the configuration file stream. */
    if (fclose(*conf) == EOF) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Set the configuration file stream to NULL. */
    *conf = NULL;

    MSG_DEBUG("Close %s successful", ETC_FILE);
}

/*
 * Overwrite the IP entries in the ARP cache with the <IP, MAC>
 * entries from the SARPI cache queue structure.
 */
static void *
sarpica_handler(UNUSED(void *arg))
{
    char *interface = NULL;

    /* Initialize the thread. */
    thd_init();

    MSG_DEBUG("Start SARPI cache handler");

    /* Get the interface name command option. */
    interface = opt_getinterface();

    /* Loop each time that the SARPI timeout of the SARPI cache expires. */
    while (1) {
        /* No empty SARPI cache queue structure? */
        if (TAILQ_EMPTY(&sca_head) == 0) {
            sca_t *cur = NULL;

            MSG_DEBUG("Update of the static entries from the SARPI cache..");

            /*
             * Update all the IP entries in the ARP cache with the
             * <IP, MAC> entries from the SARPI cache queue structure.
             */
            TAILQ_FOREACH(cur, &sca_head, next) {
                char *smac = NULL, *sip = NULL;

                /* SARPI cache MAC addr entry network byte order to string. */
                smac = ether_ntoa(&cur->mac);

                /* SARPI cache IP addr entry network byte order to string. */
                sip = inet_ntoa(cur->ip);

                /*
                 * Overwrite the permanent IP entry in the ARP
                 * cache with the <IP, MAC> entry from the SARPI
                 * cache queue structure (POLICY: UPDATE).
                 */
                arpca_overwrite(&cur->mac, &cur->ip, ARPCA_PERMANENT);

                /* Print the UPDATE policy info message. */
                ISPN_UPDATE(sip, smac);
            }
        } else {
            /* Empty SARPI cache queue structure. */
            MSG_DEBUG("No update of the static entries from the SARPI cache");
        }

        /*
         * Suspend the execution of the calling thread until the
         * SARPI timeout of the SARPI cache expires (600 seconds).
         */
        thd_suspend(SARPICA_LOOPTIMEOUT);
    }

    /* Never reaches here. */
    return NULL;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
