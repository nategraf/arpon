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
 * $ArpON: msg.h,v 3.0-ng 01/29/2016 03:02:30 spikey Exp $
 */

#ifndef _MSG_H_
#define _MSG_H_

/*
 * Remove the path from the filename.
 */
#define __SHORT_FILE__                                                  \
    strrchr(__FILE__, '/') != NULL ?                                    \
    strrchr(__FILE__, '/') + 1 : __FILE__

/*
 * Print the info message to standard output.
 */
#define INFO(fmt, ...) do {                                             \
    printf(fmt "\n", ##__VA_ARGS__);                                    \
} while (0);

/*
 * Print the error message to standard error.
 */
#define ERROR(fmt, ...) do {                                            \
    fprintf(stderr, "ERROR: " "%s:%d %s: `" fmt "'.\n",                 \
            __SHORT_FILE__, __LINE__, __func__, ##__VA_ARGS__);         \
} while (0);

/*
 * Print the info message to standard output and log file.
 */
#define MSG_INFO(fmt, ...) do {                                         \
    msg(stdout, "INFO", fmt "\n", ##__VA_ARGS__);                       \
} while (0)

/*
 * If debug enabled, print the info message to standard output and log file.
 */
#ifndef NDEBUG
#define MSG_DEBUG(fmt, ...) do {                                        \
    msg(stdout, "DEBUG", "%s: " fmt ".\n", __func__, ##__VA_ARGS__);    \
} while (0)
#else   /* NDEBUG */
#define MSG_DEBUG(...)      /* Null instruction. */
#endif  /* !NDEBUG */

/*
 * Print the warning message to standard error and log file.
 */
#define MSG_WARN(fmt, ...) do {                                         \
    msg(stderr, "WARN", fmt ".\n", ##__VA_ARGS__);                      \
} while (0)

/*
 * Print the error message to standard error and log file.
 */
#define MSG_ERROR(fmt, ...) do {                                        \
    msg(stderr, "ERROR", "%s:%d %s: `" fmt "'.\n",                      \
        __SHORT_FILE__, __LINE__, __func__, ##__VA_ARGS__);             \
} while (0)

/*
 * Print the bug message to standard error and log file.
 */
#define MSG_BUG(fmt, ...) do {                                          \
    msg(stderr, "BUG", fmt "\n", ##__VA_ARGS__);                        \
} while (0)

/*
 * Function prototype exported.
 */
extern void msg(FILE *stream, const char *level, const char *fmt, ...);

#endif  /* !_MSG_H_ */

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
