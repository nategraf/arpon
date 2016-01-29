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
 * $ArpON: msg.c,v 3.0-ng 01/29/2016 03:09:14 spikey Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>

#include "config.h"
#include "exit.h"
#include "msg.h"
#include "unused.h"

/*
 * Max timestamp length.
 */
#define MSG_TIMESTAMPSIZE   16      /* 16 bytes. */

/*
 * Max message length.
 */
#define MSG_MESSAGESIZE     512     /* 512 bytes. */

/*
 * Log file permissions to 640.
 */
#define MSG_LOGPERMS        S_IRUSR | S_IWUSR | S_IRGRP

/*
 * Function prototypes not exported.
 */
static void msg_init(void);
static void msg_destroy(void);
static void msg_gettimestamp(char *ts);
static void msg_putmessage(FILE *stream, const char *msg);

/*
 * Initialize the log file stream.
 */
static FILE *log = NULL;

/*
 * Initialize the message mutex.
 */
static pthread_mutex_t msg_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * Initialize the log file stream and print the message with logging.
 * The syntax of each message is:
 *
 * timestamp1 [log level] message1
 * timestamp2 [log level] message2
 * ...
 * timestampN [log level] messageN
 */
void
msg(FILE *stream, const char *level, const char *fmt, ...)
{

    do {
        char ts[MSG_TIMESTAMPSIZE], msg[MSG_MESSAGESIZE];
        va_list ap;
        int len1, len2, tot_len = MSG_MESSAGESIZE;

        /* Lock the mutex of the message. */
        if (pthread_mutex_lock(&msg_mtx) != 0)
            break;

        /* Log file stream of the messages already initialized and open? */
        if (log == NULL) {
            /* Initialize the log file stream of the messages. */
            msg_init();
        }

        /* Get the timestamp of the message. */
        msg_gettimestamp(ts);

        /* Initialize the message. */
        memset(msg, '\0', (size_t)tot_len);

        /* Write the timestamp with log level in the message. */
        if ((len1 = snprintf(msg, (size_t)tot_len, "%s [%s] ", ts, level)) < 0)
            break;

        /* Update the total length of the message. */
        tot_len -= len1;

        /* No message truncated. */
        assert(tot_len > 0);

        /* Append the rest of the message. */
        va_start(ap, fmt);

        if ((len2 = vsnprintf(&msg[len1], (size_t)tot_len, fmt, ap)) < 0)
            break;

        va_end(ap);

        /* Update the total length of the message. */
        tot_len -= len2;

        /* No message truncated. */
        assert(tot_len > 0);

        /* Print the message in the log file stream and the file stream. */
        msg_putmessage(stream, msg);

        /* Unlock the mutex of the message. */
        if (pthread_mutex_unlock(&msg_mtx) != 0)
            break;

        return;
    } while (0);

    ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Initialize the log file stream of the messages.
 */
static void
msg_init(void)
{

    do {
        struct stat stats;
        bool UNUSED(logcreate) = false;

        /* Check if the log file exist. */
        if (stat(LOG_FILE, &stats) < 0) {
            if (errno == ENOENT) {
                int fd;

                /* Create and open the log file with the 640 perms. */
                if ((fd = open(LOG_FILE, O_CREAT, MSG_LOGPERMS)) < 0)
                    break;

                /* Close the log file descriptor. */
                if (close(fd) < 0)
                    break;

                /* Call again. */
                if (stat(LOG_FILE, &stats) < 0)
                    break;

#ifndef NDEBUG
                /* Log file created. */
                logcreate = true;
#endif  /* !NDEBUG */
            } else {
                break;
            }
        }

        /* Check if the log file is a regular file. */
        if (S_ISREG(stats.st_mode) == 0) {
            ERROR("%s is not a regular file", LOG_FILE);
            exit(EXIT_FAILURE);
        }

        /* Fix the log file perms to 640. */
        if (chmod(LOG_FILE, MSG_LOGPERMS) < 0)
            break;

        /* Open the log file stream to append. */
        if ((log = fopen(LOG_FILE, "a")) == NULL)
            break;

#ifndef NDEBUG
        /* Unlock the mutex of the message. */
        if (pthread_mutex_unlock(&msg_mtx) != 0)
            break;

        /* Log file created? */
        if (logcreate == true)
            MSG_DEBUG("Create %s with 640 perms successful", LOG_FILE);
#endif  /* !NDEBUG */

        MSG_DEBUG("Open %s successful", LOG_FILE);
        MSG_DEBUG("Start logging");

        /* Push msg_destroy() to be called on exit_cleanup(). */
        exit_push(msg_destroy, "msg_destroy");

#ifndef NDEBUG
        /* Lock the mutex of the message. */
        if (pthread_mutex_lock(&msg_mtx) != 0)
            break;
#endif  /* !NDEBUG */

        return;
    } while (0);

    ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Destroy the log file stream of the messages.
 */
static void
msg_destroy(void)
{

    do {
        /* Unlock the mutex of the message before the destruction. */
        if (pthread_mutex_unlock(&msg_mtx) != 0)
            break;

        /* Log file stream of the messages already destroyed and closed? */
        if (log != NULL) {
            MSG_DEBUG("End logging");
            MSG_DEBUG("Close %s successful", LOG_FILE);

            /* Close the log file stream. */
            if (fclose(log) == EOF)
                break;

            /* Set the log file stream to NULL. */
            log = NULL;
        }

        return;
    } while (0);

    ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Get the timestamp of the message.
 */
static void
msg_gettimestamp(char *ts)
{

    do {
        struct tm *tinfo = NULL;
        time_t rtime;
        int len = MSG_TIMESTAMPSIZE;

        /* Initialize the timestamp. */
        memset(ts, '\0', (size_t)len);

        /* Get the current time of the system. */
        if ((rtime = time(NULL)) == (time_t)-1)
            break;

        /* Current time to local time. */
        if ((tinfo = localtime(&rtime)) == NULL)
            break;

        /* Local time to timestamp. */
        if (strftime(ts, (size_t)len, "%b %d %H:%M:%S", tinfo) == 0)
            break;

        return;
    } while (0);

    ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Put the message in the log file stream and the file stream.
 */
static void
msg_putmessage(FILE *stream, const char *msg)
{

    do {
        struct stat stats;

        /* Check if the log file exist. */
        if (stat(LOG_FILE, &stats) < 0) {
            if (errno == ENOENT) {
                /* Close the log file stream. */
                if (fclose(log) == EOF)
                    break;

                /* Set the log file stream to NULL. */
                log = NULL;

                /* Re-initialize the log file stream. */
                msg_init();

                /* Call again. */
                if (stat(LOG_FILE, &stats) < 0)
                    break;
            } else {
                break;
            }
        }

        /* Check if the log file is a regular file. */
        if (S_ISREG(stats.st_mode) == 0) {
            ERROR("%s is not a regular file", LOG_FILE);
            exit(EXIT_FAILURE);
        }

        /* Print the message in the log file stream. */
        fprintf(log, "%s", msg);

        /* Flush the log file stream. */
        if (fflush(log) == EOF)
            break;

        /* Print the message in the file stream. */
        fprintf(stream, "%s", msg);

        /* Flush the file stream. */
        if (fflush(stream) == EOF)
            break;

        return;
    } while (0);

    ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
