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
 * $ArpON: sig.c,v 3.0-ng 01/29/2016 03:06:38 spikey Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include "config.h"
#include "env.h"
#include "exit.h"
#include "msg.h"
#include "sig.h"

/*
 * Integer signal to string.
 */
#define SIG_ITOA(x)     x == SIGINT ? "interrupt signal" :                  \
                        x == SIGTERM ? "termination signal" :               \
                        x == SIGHUP ? "hangup signal" :                     \
                        x == SIGSEGV ? "segmentation fault signal" :        \
                        x == SIGBUS ? "bus error signal" : "unknown signal"

/*
 * Function prototypes not exported.
 */
static void sig_init(void);
static void sig_destroy(void);
static void sig_setblockmask(void);
static void sig_loop(char **argv, char **envp);
static void sig_handleterm(int sig);
static void sig_handlehup(char **argv, char **envp);
static void sig_handlebug(int sig);

/*
 * Initialize the signal mask.
 */
static sigset_t mask = {{0}};

/*
 * Initialize and handle the signal.
 */
void
sig_handle(char **argv, char **envp)
{

    MSG_DEBUG("Start signal handle");

    /* Initialize the signal mask. */
    sig_init();

    /* Set and block the signal mask. */
    sig_setblockmask();

    /* Handle the signal masked. */
    sig_loop(argv, envp);
}

/*
 * Initialize the signal mask.
 */
static void
sig_init(void)
{

    /* Initialize the signal mask. */
    if (sigemptyset(&mask) < 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("Initialize signal mask successful");

    /* Push sig_destroy() to be called on exit_cleanup(). */
    exit_push(sig_destroy, "sig_destroy");
}

/*
 * Destroy and unblock the signal mask.
 */
static void
sig_destroy(void)
{

    do {
        /* Unblock the signal mask. */
        if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0)
            break;

        /* Destroy the signal mask. */
        if (sigemptyset(&mask) < 0)
            break;

        MSG_DEBUG("Unblock signal mask successful");

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Set and block the value of the signal mask.
 */
static void
sig_setblockmask(void)
{

    do {
        /* Add the interrupt signal in the signal mask. */
        if (sigaddset(&mask, SIGINT) < 0)
            break;

        MSG_DEBUG("Add %s to signal mask..", SIG_ITOA(SIGINT));

        /* Add the termination signal in the signal mask. */
        if (sigaddset(&mask, SIGTERM) < 0)
            break;

        MSG_DEBUG("Add %s to signal mask..", SIG_ITOA(SIGTERM));

        /* Add the hangup signal in the signal mask. */
        if (sigaddset(&mask, SIGHUP) < 0)
            break;

        MSG_DEBUG("Add %s to signal mask..", SIG_ITOA(SIGHUP));

        /* Add the segmentation fault signal in the signal mask. */
        if (sigaddset(&mask, SIGSEGV) < 0)
            break;

        MSG_DEBUG("Add %s to signal mask..", SIG_ITOA(SIGSEGV));

        /* Add the bus error signal in the signal mask. */
        if (sigaddset(&mask, SIGBUS) < 0)
            break;

        MSG_DEBUG("Add %s to signal mask...", SIG_ITOA(SIGBUS));

        /* Block the signal mask. */
        if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0)
            break;

        MSG_DEBUG("Block signal mask successful");

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Handle the signal masked.
 */
static void
sig_loop(char **argv, char **envp)
{

    /* Loop until a signal is caught. */
    while (1) {
        int sig;

        /* Suspend the execution of the main thread until a signal is caught. */
        if (sigwait(&mask, &sig) != 0) {
            MSG_ERROR("%s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Handle the signal caught of the main thread. */
        switch(sig) {
            case SIGINT:
                /* Remove ^C symbol from the output terminal. */
                printf("\r");

            case SIGTERM:
                MSG_DEBUG("Caught %s (%d)..", SIG_ITOA(sig), sig);

                /* Handle the interrupt or termination signal. */
                sig_handleterm(sig);

                /* Never reaches here. */
                break;

            case SIGHUP:
                MSG_DEBUG("Caught %s (%d)..", SIG_ITOA(sig), sig);

                /* Handle the hangup signal. */
                sig_handlehup(argv, envp);

                /* Never reaches here. */
                break;

            case SIGSEGV:
            case SIGBUS:
                MSG_DEBUG("Caught %s (%d)..", SIG_ITOA(sig), sig);

                /* Handle the segmentation fault or bus error signal. */
                sig_handlebug(sig);

                /* Never reaches here. */
                break;

            default:
                MSG_DEBUG("Caught no valid %s (%d)..", SIG_ITOA(sig), sig);

                /* Ignore the no valid signal. */
                break;
        }
    }
}

/*
 * Handle the interrupt or termination signal.
 */
static void
sig_handleterm(int sig)
{

    MSG_DEBUG("Handle the %s..", SIG_ITOA(sig));

    /* Print the correct termination name. */
    switch (sig) {
        case SIGINT:
            MSG_INFO("Interrupt requested, quitting now.");
            break;

        /* SIGTERM. */
        default:
            MSG_INFO("Termination requested, quitting now.");
            break;
    }

    /* Cleanup and exit. */
    exit_cleanup(true);
}

/*
 * Handle the hangup signal.
 */
static void
sig_handlehup(char **argv, char **envp)
{
    const char *path = NULL;

    MSG_DEBUG("Handle the %s..", SIG_ITOA(SIGHUP));
    MSG_INFO("Hangup requested, rebooting now...");

    /* Get the environment binary path file. */
    path = env_getpath(*(argv + 0));

    MSG_DEBUG("Re-exec the current process from %s binary path file..", path);

    /* Cleanup without exit. */
    exit_cleanup(false);

    /* Re-exec the current process. */
    if (execve(path, argv, envp) < 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/*
 * Handle the segmentation fault or bus error signal.
 */
static void
sig_handlebug(int sig)
{

    MSG_DEBUG("Handle the %s..", SIG_ITOA(sig));

    /* Print the correct bug name. */
    switch (sig) {
        case SIGSEGV:
            MSG_BUG("Ops... SEGMENTATION FAULT!");
            break;

        /* SIGBUS. */
        default:
            MSG_BUG("Ops... BUS ERROR!");
            break;
    }

    MSG_BUG("Please open with a browser web the documentation: %s", DOC_FILE);
    MSG_BUG("Follow the steps explained in the \"Runtime bugs\" section.");
    MSG_BUG("Thank you so much and have a nice day!");

    /* Exit immediately. */
    exit(EXIT_FAILURE);
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
