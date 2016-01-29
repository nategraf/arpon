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
 * $ArpON: thd.c,v 3.0-ng 01/29/2016 03:04:19 spikey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>

#include "msg.h"
#include "queue.h"
#include "thd.h"
#include "unused.h"

/*
 * No nanoseconds.
 */
#define THD_NANOSECS    0

/*
 * Thread context exit status to string.
 */
#define THD_ETOA(x)     x == PTHREAD_CANCELED ? "Cancel" : "Exit"

/*
 * Thread context stack structure definition.
 */
typedef struct thd_stack {
    pthread_t id;                   /* Thread context ID. */
    const char *name;               /* Thread context name. */

    LIST_ENTRY(thd_stack) next;     /* Next thread context stack element. */
} thd_t;

/*
 * Function prototypes not exported.
 */
static void         thd_push(pthread_t id, const char *name);
static pthread_t    thd_pop(const char **name);
static void         thd_unregister(pthread_t id, const char *name);

/*
 * Initialize the thread context stack structure.
 */
static LIST_HEAD(thd, thd_stack) thd_head = LIST_HEAD_INITIALIZER(thd_head);

/*
 * Initialize the thread context mutex initialization.
 */
static pthread_mutex_t thd_mtxinit = PTHREAD_MUTEX_INITIALIZER;

/*
 * Initialize the thread context condition initialization.
 */
static pthread_cond_t thd_condinit = PTHREAD_COND_INITIALIZER;

/*
 * Register the thread context.
 */
void
thd_register(void *(*routine)(void *), void *arg, const char *name)
{

    do {
        /* Register the main thread context? */
        if (routine == NULL && arg == NULL) {
            MSG_DEBUG("Skip create %s() thread context successful", name);

            /* Only push the main thread context. */
            thd_push(pthread_self(), name);
        } else {
            pthread_t id;

            /* Lock the mutex initialization of the thread context. */
            if (pthread_mutex_lock(&thd_mtxinit) != 0)
                break;

            /* Register the thread context calling the routine. */
            if (pthread_create(&id, NULL, routine, arg) != 0)
                break;

            MSG_DEBUG("Create %s() thread context successful", name);

            /* Push the thread context. */
            thd_push(id, name);

            MSG_DEBUG("Wait signal from %s() thread context..", name);

            /* Wait the condition initialization from the thread context. */
            if (pthread_cond_wait(&thd_condinit, &thd_mtxinit) != 0)
                break;

            MSG_DEBUG("%s() thread context ready and initialized", name);

            /* Unlock the mutex initialization of the thread context. */
            if (pthread_mutex_unlock(&thd_mtxinit) != 0)
                break;
        }

        MSG_DEBUG("Register %s() thread context successful", name);

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Push the thread context stack element in the thread stack structure.
 */
static void
thd_push(pthread_t id, const char *name)
{
    thd_t *new = NULL;

    /* Empty thread context stack structure? */
    if (LIST_EMPTY(&thd_head) != 0) {
        /* Set the thread context stack structure to NULL. */
        LIST_INIT(&thd_head);
        MSG_DEBUG("Initialize thread context cleanup successful");
    }

    /* Allocate the thread context stack element. */
    if ((new = (thd_t *)malloc(sizeof(thd_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("thd_t *new allocate in the memory");

    /* Initialize the thread context ID. */
    new->id = id;

    /* pthread_t is an opaque type, therefore check it. */
    assert(sizeof(new->id) == sizeof(unsigned long int));
    MSG_DEBUG("new->id = %lu", new->id);

    /* Initialize the thread context name. */
    new->name = name;
    MSG_DEBUG("new->name = %s", new->name);

    /* Push the thread context stack element. */
    LIST_INSERT_HEAD(&thd_head, new, next);

    MSG_DEBUG("Push %s() thread context successful", name);
}

/*
 * Initialize the calling thread context.
 */
void
thd_init(void)
{

    do {
        thd_t UNUSED(*cur) = NULL;

        /* Lock the mutex initialization of the thread context. */
        if (pthread_mutex_lock(&thd_mtxinit) != 0)
            break;

        /* Enable the cancellation of the calling thread context. */
        if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0)
            break;

        /* Enable asynchronous cancellation of the calling thread context. */
        if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) != 0)
            break;

#ifndef NDEBUG
        /* Looking for the name of the calling thread context. */
        LIST_FOREACH(cur, &thd_head, next) {
            if (pthread_equal(cur->id, pthread_self()) != 0)
                break;
        }
#endif  /* !NDEBUG */

        MSG_DEBUG("%s() sends signal to main thread context..", cur->name);

        /* Send the condition initialization to main thread context. */
        if (pthread_cond_signal(&thd_condinit) != 0)
            break;

        MSG_DEBUG("Initialization %s() thread context successful", cur->name);

        /* Unlock the mutex initialization of the thread context. */
        if (pthread_mutex_unlock(&thd_mtxinit) != 0)
            break;

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Suspend the execution of the caller thread context for specified seconds.
 */
void
thd_suspend(int seconds)
{
    struct timespec tv;
    int ret;

    tv.tv_sec = seconds;        /* Number of seconds. */
    tv.tv_nsec = THD_NANOSECS;  /* No nanoseconds. */

    /* Suspend the execution of the caller thread context (no interruptible). */
    while ((ret = nanosleep(&tv, &tv)) < 0 && errno == EINTR);

    /* Some error? */
    if (ret < 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/*
 * Cleanup all the thread contexts from the thread context
 * stack structure and unregister each thread context found.
 */
void
thd_cleanup(void)
{

    do {
        MSG_DEBUG("Start thread context cleanup");

        /*
         * Send the condition initialization to main thread context
         * before the unregistration of all the threads context.
         */
        if (pthread_cond_signal(&thd_condinit) != 0)
            break;

        /*
         * Unlock the mutex initialization of the thread context
         * before the unregistration of all the threads context.
         */
        if (pthread_mutex_unlock(&thd_mtxinit) != 0)
            break;

        /* No empty thread context stack structure? */
        if (LIST_EMPTY(&thd_head) == 0) {
            /* Loop until the thread context stack structure is empty. */
            do {
                pthread_t id;
                const char *name = NULL;

                /* Pop the thread context ID. */
                id = thd_pop(&name);
                MSG_DEBUG("Start cleanup %s() thread context..", name);

                /* Unregister the thread context. */
                thd_unregister(id, name);
            } while (LIST_EMPTY(&thd_head) == 0);

            /* Re-initialize the thread context stack structure to NULL. */
            LIST_INIT(&thd_head);
        }

        MSG_DEBUG("End thread context cleanup");

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Pop the thread context stack element from the thread context stack structure.
 */
static pthread_t
thd_pop(const char **name)
{
    thd_t *cur = NULL;
    pthread_t id;

    /* Get the first thread context stack element. */
    cur = LIST_FIRST(&thd_head);

    /* Pop the first thread context stack element. */
    LIST_REMOVE(cur, next);

    /* Get the thread context ID. */
    id = cur->id;

    /* pthread_t is an opaque type, therefore check it. */
    assert(sizeof(id) == sizeof(unsigned long int));
    MSG_DEBUG("cur->id = %lu", id);

    /* Get the thread context name. */
    *name = cur->name;
    MSG_DEBUG("cur->name = %s", *name);

    /* Deallocate the thread context stack element. */
    free(cur);

    MSG_DEBUG("thd_t *cur deallocate from the memory");
    MSG_DEBUG("Pop %s() thread context successful", *name);

    return id;
}

/*
 * Unegister the thread context.
 */
static void
thd_unregister(pthread_t id, UNUSED(const char *name))
{

    do {
        void *res = NULL;

        /* Unregister the main thread context? */
        if (pthread_equal(id, pthread_self()) != 0) {
            MSG_DEBUG("Skip cancel %s() thread context successful", name);
        } else {
            /* Unregister the thread context. */
            if (pthread_cancel(id) != 0)
                break;

            /* Join with the thread context to see the exit status. */
            if (pthread_join(id, &res) != 0)
                break;

            MSG_DEBUG("%s %s() thread context successful", THD_ETOA(res), name);
        }

        MSG_DEBUG("Unregister %s() thread context successful", name);

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
