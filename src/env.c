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
 * $ArpON: env.c,v 3.0-ng 01/29/2016 02:58:08 spikey Exp $
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "config.h"
#include "env.h"
#include "msg.h"

/*
 * Environment variable of the preload shared objects.
 */
#define ENV_LDPRELOAD   "LD_PRELOAD"

/*
 * Root User ID.
 */
#define ENV_ROOTUID     0

/*
 * Root Group ID.
 */
#define ENV_ROOTGID     0

/*
 * Audit the environment.
 */
void
env_audit(char **argv, char **envp)
{

    do {
        /* Avoid the $LD_PRELOAD attack. */
        if (getenv(ENV_LDPRELOAD) != NULL) {
            /* Unset $LD_PRELOAD environment variable. */
            if (unsetenv(ENV_LDPRELOAD) < 0)
                break;

            /* Re-exec the current process without $LD_PRELOAD. */
            if (execve(env_getpath(*(argv + 0)), argv, envp) < 0)
                break;
        }

        /* Root user? */
        if (getuid() != ENV_ROOTUID || getgid() != ENV_ROOTGID) {
            /* Print the info message and exit. */
            INFO("You don't have permission to run.");
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("Audit environment successful");

        return;
    } while (0);

    ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Get the value of the environment binary path file.
 */
const char *
env_getpath(const char *bin)
{

    /* Local environment binary path file? */
    if (*(bin + 0) == '.' && *(bin + 1) == '/')
        return bin;

    /* Global environment binary path file. */
    return SBIN_FILE;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
