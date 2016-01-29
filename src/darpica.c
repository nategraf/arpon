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
 * $ArpON: darpica.c,v 3.0-ng 01/29/2016 03:08:04 spikey Exp $
 */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "darpica.h"
#include "exit.h"
#include "msg.h"
#include "queue.h"
#include "rt.h"
#include "thd.h"
#include "unused.h"

/*
 * DARPI timeout of the DARPI cache
 * (Expiry for each IP entry of the DARPI cache).
 */
#define DARPICA_TIMEOUT         1.0     /* 1 second. */

/*
 * Timeout of the DARPI cache
 * (Expiry for each loop of the DARPI cache handler).
 */
#define DARPICA_LOOPTIMEOUT     1       /* 1 second. */

/*
 * DARPI cache queue structure definition.
 */
typedef struct dca_queue {
    double time;                        /* DARPI cache local time entry. */
    struct in_addr ip;                  /* DARPI cache IP addr entry. */

    TAILQ_ENTRY(dca_queue) next;        /* Next DARPI cache queue element. */
} dca_t;

/*
 * Function prototypes not exported.
 */
static void  darpica_init(void);
static void  darpica_destroy(void);
static void  darpica_dequeuetop(void);
static void *darpica_handler(void *arg);

/*
 * Initialize the DARPI cache queue structure.
 */
static TAILQ_HEAD(dca, dca_queue) dca_head = TAILQ_HEAD_INITIALIZER(dca_head);

/*
 * Initialize the DARPI cache mutex.
 */
static pthread_mutex_t darpica_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * Configure the DARPI cache.
 */
void
darpica_configure(void)
{

    MSG_DEBUG("Start DARPI cache configure");

    /* Initialize the DARPI cache queue structure. */
    darpica_init();

    /* Register the DARPI cache handler thread. */
    thd_register(darpica_handler, NULL, "darpica_handler");

    MSG_DEBUG("End DARPI cache configure");
}

/*
 * Initialize the DARPI cache queue structure.
 */
static void
darpica_init(void)
{

    /* Set the DARPI cache queue structure to NULL. */
    TAILQ_INIT(&dca_head);
    MSG_DEBUG("Initialize DARPI cache queue successful");

    /* Push darpica_destroy() to be called on exit_clean(). */
    exit_push(darpica_destroy, "darpica_destroy");
}

/*
 * Destroy the DARPI cache queue structure.
 */
static void
darpica_destroy(void)
{

    /* Unlock the mutex of the DARPI cache before the destruction. */
    if (pthread_mutex_unlock(&darpica_mtx) != 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* No empty DARPI cache queue structure? */
    if (TAILQ_EMPTY(&dca_head) == 0) {
        /* Loop until the DARPI cache queue structure is empty. */
        do {
            /* Dequeue the DARPI cache entry. */
            darpica_dequeuetop();
        } while (TAILQ_EMPTY(&dca_head) == 0);

        /* Re-initialize the DARPI cache queue structure to NULL. */
        TAILQ_INIT(&dca_head);
    }

    MSG_DEBUG("Destroy DARPI cache queue successful");
}

/*
 * Dequeue the DARPI cache queue element from the DARPI cache queue structure.
 */
static void
darpica_dequeuetop(void)
{
    dca_t *cur = NULL;
    double UNUSED(stime);
    char UNUSED(*sip) = NULL;

    /* Get the first DARPI cache queue element. */
    cur = TAILQ_FIRST(&dca_head);

    /* Dequeue the first DARPI cache queue element. */
    TAILQ_REMOVE(&dca_head, cur, next);

#ifndef NDEBUG
    /* Get the DARPI cache local time entry. */
    stime = cur->time;
#endif  /* !NDEBUG */

    MSG_DEBUG("cur->time = %lf", stime);

#ifndef NDEBUG
    /* Get the DARPI cache IP addr entry. */
    sip = inet_ntoa(cur->ip);
#endif  /* !NDEBUG */

    MSG_DEBUG("cur->ip = %s", sip);

    /* Deallocate the DARPI cache queue element. */
    free(cur);

    MSG_DEBUG("dca_t *cur deallocate from the memory");
    MSG_DEBUG("Dequeue <%lf, %s> DARPI cache entry successful", stime, sip);
}

/*
 * Enqueue the DARPI cache queue element in the DARPI cache queue structure.
 */
void
darpica_enqueue(struct in_addr *ip)
{

    do {
        dca_t *new = NULL;
        double UNUSED(stime);
        char UNUSED(*sip) = NULL;

        /* Lock the mutex of the DARPI cache. */
        if (pthread_mutex_lock(&darpica_mtx) != 0)
            break;

        /* Allocate the DARPI cache queue element. */
        if ((new = (dca_t *)malloc(sizeof(dca_t))) == NULL)
            break;

        MSG_DEBUG("dca_t *new allocate in the memory");

        /* Initialize the DARPI cache local time entry. */
        new->time = rt_getlocaltime();

#ifndef NDEBUG
        /* Current local time. */
        stime = new->time;
#endif  /* !NDEBUG */

        MSG_DEBUG("new->time = %lf", stime);

        /* Initialize the DARPI cache IP addr entry. */
        new->ip = *ip;

#ifndef NDEBUG
        /* IP addr network byte order to string. */
        sip = inet_ntoa(new->ip);
#endif  /* !NDEBUG */

        MSG_DEBUG("cur->ip = %s", sip);

        /* Empty DARPI cache queue structure? */
        if (TAILQ_EMPTY(&dca_head) != 0) {
            /* Enqueue the DARPI cache queue element in the head. */
            TAILQ_INSERT_HEAD(&dca_head, new, next);
            MSG_DEBUG("H-Enqueue <%lf, %s> DARPI cache entry successful",
                stime, sip);
        } else {
            /* Enqueue the DARPI cache queue element in the tail. */
            TAILQ_INSERT_TAIL(&dca_head, new, next);
            MSG_DEBUG("T-Enqueue <%lf, %s> DARPI cache entry successful",
                stime, sip);
        }

        /* Unlock the mutex of the DARPI cache. */
        if (pthread_mutex_unlock(&darpica_mtx) != 0)
            break;

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Find a DARPI cache queue element in the DARPI cache queue structure.
 */
bool
darpica_ismember(struct in_addr *ip)
{

    do {
        bool ret;
        double UNUSED(stime);
        char UNUSED(*sip) = NULL;

        /* Lock the mutex of the DARPI cache. */
        if (pthread_mutex_lock(&darpica_mtx) != 0)
            break;

        /* Return value to false. */
        ret = false;

        /* No empty DARPI cache queue structure? */
        if (TAILQ_EMPTY(&dca_head) == 0) {
            dca_t *cur = NULL;

            /* Looking the IP addr in the DARPI cache queue structure. */
            TAILQ_FOREACH(cur, &dca_head, next) {
                if (ip->s_addr == cur->ip.s_addr) {
#ifndef NDEBUG
                    /* Local time of the DARPI cache queue element. */
                    stime = cur->time;

                    /*
                     * IP addr network byte order of the
                     * DARPI cache queue element to string.
                     */
                    sip = inet_ntoa(cur->ip);
#endif  /* !NDEBUG */

                    /* IP addr found, it is a DARPI cache queue element. */
                    MSG_DEBUG("<%lf, %s> DARPI cache entry found", stime, sip);

                    /* Return value to true. */
                    ret = true;

                    /* Therefore break. */
                    break;
                }
            }
        }

        /* IP addr not found? It is not a DARPI cache queue element? */
        if (ret == false) {
#ifndef NDEBUG
            /* IP addr network byte order to string. */
            sip = inet_ntoa(*ip);
#endif  /* !NDEBUG */

            /* IP addr not found, it is not a DARPI cache queue element. */
            MSG_DEBUG("<%s> DARPI cache entry not found", sip);
        }

        /* Unlock the mutex of the DARPI cache. */
        if (pthread_mutex_unlock(&darpica_mtx) != 0)
            break;

        return ret;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Dequeue the DARPI cache queue element from the DARPI cache queue structure.
 */
void
darpica_dequeue(struct in_addr *ip)
{

    do {
        dca_t *elm = NULL, *cur = NULL;
        double UNUSED(stime);
        char UNUSED(*sip) = NULL;

        /* Lock the mutex of the DARPI cache. */
        if (pthread_mutex_lock(&darpica_mtx) != 0)
            break;

        /* Looking the IP addr in the DARPI cache queue structure. */
        TAILQ_FOREACH(elm, &dca_head, next) {
            if (ip->s_addr == elm->ip.s_addr) {
                /* Get the specified DARPI cache queue element. */
                cur = elm;

#ifndef NDEBUG
                /* Get the DARPI cache local time entry. */
                stime = cur->time;

                /* Get the DARPI cache IP addr entry. */
                sip = inet_ntoa(cur->ip);
#endif  /* !NDEBUG */

                /* IP addr found, it is a DARPI cache queue element. */
                MSG_DEBUG("<%lf, %s> DARPI cache entry found", stime, sip);

                /* Therefore break. */
                break;
            }
        }

        /* IP addr not found? It is not a DARPI cache queue element? */
        if (cur == NULL) {
#ifndef NDEBUG
            /* IP addr network byte order to string. */
            sip = inet_ntoa(*ip);
#endif  /* !NDEBUG */

            /* IP addr not found, it is not a DARPI cache queue element. */
            MSG_DEBUG("<%s> DARPI cache entry not found", sip);
        } else {
            /* Dequeue the specified DARPI cache queue element. */
            TAILQ_REMOVE(&dca_head, cur, next);

            MSG_DEBUG("cur->time = %lf", stime);
            MSG_DEBUG("cur->ip = %s", sip);

            /* Deallocate the DARPI cache queue element. */
            free(cur);

            MSG_DEBUG("dca_t *cur deallocate from the memory");
            MSG_DEBUG("Dequeue <%lf, %s> DARPI cache entry successful",
                stime, sip);
        }

        /* Unlock the mutex of the DARPI cache. */
        if (pthread_mutex_unlock(&darpica_mtx) != 0)
            break;

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Delete the <IP, TIME> entries expired from the DARPI cache
 * (difftime(current local time, TIME) >= DARPI timeout of the DARPI cache).
 */
static void *
darpica_handler(UNUSED(void *arg))
{

    /* Initialize the thread. */
    thd_init();

    MSG_DEBUG("Start DARPI cache handler");

    /* Loop each time that the timeout of the DARPI cache expires. */
    while (1) {
        /* Lock the mutex of the DARPI cache. */
        if (pthread_mutex_lock(&darpica_mtx) != 0)
            break;

        /* No empty DARPI cache queue structure? */
        if (TAILQ_EMPTY(&dca_head) == 0) {
            dca_t *cur = NULL, *tmp = NULL;
            double ltime, UNUSED(stime);
            char UNUSED(*sip) = NULL;

            /* Initialize the current local time. */
            ltime = rt_getlocaltime();

            MSG_DEBUG("Delete of the expired entries from the DARPI cache..");

            /*
             * Delete all the <IP, TIME> entries expired
             * from the DARPI cache queue structure.
             */
            for (cur = TAILQ_FIRST(&dca_head); cur != NULL; cur = tmp) {
                /* Get the next DARPI cache queue element. */
                tmp = TAILQ_NEXT(cur, next);

#ifndef NDEBUG
                /* DARPI cache local time entry. */
                stime = cur->time;

                /* DARPI cache IP addr entry network byte order to string. */
                sip = inet_ntoa(cur->ip);
#endif  /* !NDEBUG */

                /*
                 * DARPI cache entry expired? Therefore:
                 *
                 * DARPI cache entry expired =
                 *      difftime(current local time, TIME) >=
                 *      DARPI timeout of the DARPI cache
                 */
                if (rt_difftime(ltime, cur->time) >= DARPICA_TIMEOUT) {
                    /*
                     * Delete the <IP, TIME> entry
                     * expired from the DARPI cache.
                     */
                    MSG_DEBUG("<%lf, %s> DARPI cache entry expired",
                        stime, sip);

                    /* Dequeue the specified DARPI cache queue element. */
                    TAILQ_REMOVE(&dca_head, cur, next);

                    MSG_DEBUG("cur->time = %lf", stime);
                    MSG_DEBUG("cur->ip = %s", sip);

                    /* Deallocate the DARPI cache queue element. */
                    free(cur);

                    MSG_DEBUG("dca_t *cur deallocate from the memory");
                    MSG_DEBUG("Dequeue <%lf, %s> DARPI cache entry successful",
                        stime, sip);
                } else {
                    /*
                     * <IP, TIME> entry not expired, therefore
                     * no delete of it from the DARPI cache.
                     */
                    MSG_DEBUG("<%lf, %s> DARPI cache entry not expired",
                        stime, sip);
                }
            }
        } else {
            /* Empty DARPI cache queue structure. */
            MSG_DEBUG("No delete of the expired entries from the DARPI cache");
        }

        /* Unlock the mutex of the DARPI cache. */
        if (pthread_mutex_unlock(&darpica_mtx) != 0)
            break;

        /*
         * Suspend the execution of the calling thread until
         * the timeout of the DARPI cache expires (1 second).
         */
        thd_suspend(DARPICA_LOOPTIMEOUT);
    }

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);

    /* Never reaches here. */
    return NULL;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
