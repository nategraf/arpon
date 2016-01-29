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
 * $ArpON: exit.c,v 3.0-ng 01/29/2016 03:04:38 spikey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "exit.h"
#include "msg.h"
#include "queue.h"
#include "thd.h"

/*
 * Exit callback stack structure definition.
 */
typedef struct exit_stack {
    void (*callback)(void);         /* Exit callback routine. */
    const char *name;               /* Exit callback name. */

    LIST_ENTRY(exit_stack) next;    /* Next exit callback stack element. */
} exit_t;

/*
 * Function prototype not exported.
 */
static void (*exit_pop(const char **name))(void);

/*
 * Initialize the exit callback stack structure.
 */
static LIST_HEAD(exit, exit_stack) exit_head = LIST_HEAD_INITIALIZER(exit_head);

/*
 * Push the exit callback stack element in the exit callback stack structure.
 */
void
exit_push(void (*callback)(void), const char *name)
{
    exit_t *new = NULL, *cur = NULL;

    /* Empty exit callback stack structure? */
    if (LIST_EMPTY(&exit_head) != 0) {
        /* Set the exit callback stack structure to NULL. */
        LIST_INIT(&exit_head);
        MSG_DEBUG("Initialize exit callback cleanup successful");
    } else {
        /* Exit callback already previously pushed? */
        LIST_FOREACH(cur, &exit_head, next) {
            if (strcmp(cur->name, name) == 0) {
                /* Exit callback already pushed, therefore do nothing. */
                MSG_DEBUG("%s() exit callback already pushed", name);
                return;
            }
        }
    }

    /* Allocate the exit callback stack element. */
    if ((new = (exit_t *)malloc(sizeof(exit_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("exit_t *new allocate in the memory");

    /* Initialize the exit callback routine. */
    new->callback = callback;
    MSG_DEBUG("new->callback = %p", (void *)*new->callback);

    /* Initialize the exit callback name. */
    new->name = name;
    MSG_DEBUG("new->name = %s", new->name);

    /* Push the exit callback stack element. */
    LIST_INSERT_HEAD(&exit_head, new, next);

    MSG_DEBUG("Push %s() exit callback successful", name);
}

/*
 * Cleanup all the exit callbacks from the exit callback
 * stack structure and run each exit callback routine found.
 */
void
exit_cleanup(bool callexit)
{

    MSG_DEBUG("Start exit callback cleanup");

    /* Cleanup all the thread contexts. */
    thd_cleanup();

    /* No empty exit callback stack structure? */
    if (LIST_EMPTY(&exit_head) == 0) {
        /* Loop until the exit callback stack structure is empty. */
        do {
            void (*callback)(void) = NULL;
            const char *name = NULL;

            /* Pop the exit callback routine. */
            callback = exit_pop(&name);
            MSG_DEBUG("Start cleanup %s() exit callback..", name);

            /* Run the exit callback routine. */
            callback();
        } while (LIST_EMPTY(&exit_head) == 0);

        /* Re-initialize the exit callback stack structure to NULL. */
        LIST_INIT(&exit_head);
    }

    /* Need call exit()? */
    if (callexit == true) {
        /*
         * Call _exit() instead of exit() to no call
         * any functions registered with atexit().
         */
        _exit(EXIT_SUCCESS);
    }
}

/*
 * Pop the exit callback stack element from the exit callback stack structure.
 */
static void
(*exit_pop(const char **name))(void)
{
    exit_t *cur = NULL;
    void (*callback)(void) = NULL;

    /* Get the first exit callback stack element. */
    cur = LIST_FIRST(&exit_head);

    /* Pop the first exit callback stack element. */
    LIST_REMOVE(cur, next);

    /* Get the exit callback routine. */
    callback = cur->callback;
    MSG_DEBUG("cur->callback = %p", (void *)*callback);

    /* Get the exit callback name. */
    *name = cur->name;
    MSG_DEBUG("cur->name = %s", *name);

    /* Deallocate the exit callback stack element. */
    free(cur);

    MSG_DEBUG("exit_t *cur deallocate from the memory");
    MSG_DEBUG("Pop %s() exit callback successful", *name);

    return callback;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
