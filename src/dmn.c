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
 * $ArpON: dmn.c,v 3.0-ng 01/29/2016 03:05:59 spikey Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "config.h"
#include "dmn.h"
#include "env.h"
#include "exit.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"

/*
 * Root directory.
 */
#define DMN_ROOTDIR     "/"

/*
 * User file creation mask.
 */
#define DMN_USERMASK    0

/*
 * Null device.
 */
#define DMN_NULLDEV     "/dev/null"

/*
 * Pid file permissions to 644.
 */
#define DMN_PIDPERMS    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

/*
 * Function prototypes not exported.
 */
static void  dmn_forktwice(void);
static void  dmn_setenvironment(char **argv);
static void  dmn_redirectstreams(void);
static FILE *dmn_initpid(void);
static void  dmn_putpid(FILE *pid);
static void  dmn_destroypid(FILE **pid);

/*
 * Daemonize the process.
 */
void
dmn_daemonize(char **argv)
{
    FILE *pid = NULL;

    MSG_DEBUG("Start daemonize process");

    do {
        /* No specified daemonize command option? */
        if (opt_getdaemon() == false) {
            MSG_DEBUG("No daemonize process");
            break;
        }

        /* Call the fork twice. */
        dmn_forktwice();

        /* Set the environment. */
        dmn_setenvironment(argv);

        /* Redirect the standard I/O/E to /dev/null character device. */
        dmn_redirectstreams();
    } while (0);

    /* Initialize the pid file stream. */
    pid = dmn_initpid();

    /* Put the PID in the pid file stream. */
    dmn_putpid(pid);

    /* Destroy the pid file stream. */
    dmn_destroypid(&pid);

    MSG_DEBUG("End daemonize process");
}

/*
 * Fork twice.
 */
static void
dmn_forktwice(void)
{

    do {
        pid_t pid;

        /* Fork off the parent process. */
        if ((pid = fork()) < 0)
            break;

        /* Grandparent process exit. */
        if (pid > 0) {
            MSG_DEBUG("Grandparent PID = %d exit", getpid());

            /* Cleanup and exit. */
            exit_cleanup(true);
        }

        /* On success the parent process becomes the session leader. */
        if (setsid() < 0) {
            break;
        }

        /* Ignore when the controlling terminal is closed. */
        if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
            break;

        /* Fork off the grandchild process. */
        if ((pid = fork()) < 0) {
            break;
        }

        /* Parent process exit allowing the grandparent process to terminate. */
        if (pid > 0) {
            MSG_DEBUG("Parent PID = %d exit", getpid());

            /* Cleanup and exit. */
            exit_cleanup(true);
        }

        /* Get the grandchild process ID. */
        pid = getpid();

        MSG_DEBUG("Grandchild PID = %d is running", pid);
        MSG_INFO("Background process is running (%d).", pid);

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Set the environment.
 */
static void
dmn_setenvironment(char **argv)
{
    const char *path = NULL;

    /* Get the environment binary path file. */
    path = env_getpath(*(argv + 0));

    /* Global or local environment binary path file? */
    if (strcmp(path, SBIN_FILE) == 0) {
        /* Set the current working directory to the root directory. */
        if (chdir(DMN_ROOTDIR) < 0) {
            MSG_ERROR("%s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("cwd = %s", DMN_ROOTDIR);
    } else {
        /* No change the current working directory (local directory). */
        MSG_DEBUG("cwd = %s", path);
    }

    /* Set the user file creation mask to zero. */
    umask(DMN_USERMASK);
    MSG_DEBUG("umask = %d", DMN_USERMASK);
}

/*
 * Redirect the standard input, output and error to /dev/null character device.
 */
static void
dmn_redirectstreams(void)
{

    do {
        int fd;

        /* Open the /dev/null character device. */
        if ((fd = open(DMN_NULLDEV, O_RDWR, 0)) < 0)
            break;

        /* Redirect the standard input to /dev/null character device. */
        if (dup2(fd, STDIN_FILENO) < 0)
            break;

        /* Redirect the standard output to /dev/null character device. */
        if (dup2(fd, STDOUT_FILENO) < 0)
            break;

        /* Redirect the standard error to /dev/null character device. */
        if (dup2(fd, STDERR_FILENO) < 0)
            break;

        /* Close the /dev/null character device. */
        if (fd > 2) {
            if (close(fd) < 0)
                break;
        }

        MSG_DEBUG("Redirect I/O/E streams to /dev/null successful");

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Initialize the pid file stream of the PID.
 */
static FILE *
dmn_initpid(void)
{

    do {
        struct stat stats;
        FILE *pid = NULL;

        /* Check if the pid file exist. */
        if (stat(PID_FILE, &stats) < 0) {
            if (errno == ENOENT) {
                int fd;

                /* Create and open the pid file with the 644 perms. */
                if ((fd = open(PID_FILE, O_CREAT, DMN_PIDPERMS)) < 0)
                    break;

                /* Close the pid file descriptor. */
                if (close(fd) < 0)
                    break;

                /* Call again. */
                if (stat(PID_FILE, &stats) < 0)
                    break;

                MSG_DEBUG("Create %s with 644 perms successful", PID_FILE);
            } else {
                break;
            }
        }

        /* Check if the pid file is a regular file. */
        if (S_ISREG(stats.st_mode) == 0) {
            MSG_WARN("%s is not a regular file", PID_FILE);
            exit(EXIT_FAILURE);
        }

        /* Fix the pid file perms to 644. */
        if (chmod(PID_FILE, DMN_PIDPERMS) < 0)
            break;

        /* Open the pid file stream to write. */
        if ((pid = fopen(PID_FILE, "w")) == NULL)
            break;

        MSG_DEBUG("Open %s successful", PID_FILE);

        return pid;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Put the PID in the pid file stream.
 */
static void
dmn_putpid(FILE *pid)
{
    pid_t id;

    /* Get the Process ID. */
    id = getpid();

    /* Print the PID in the pid file stream. */
    fprintf(pid, "%d", id);

    /* Flush the pid file stream. */
    if (fflush(pid) == EOF) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("Put %d in %s successful", id, PID_FILE);
}

/*
 * Destroy the pid file stream of the PID.
 */
static void
dmn_destroypid(FILE **pid)
{

    /* Close the pid file stream. */
    if (fclose(*pid) == EOF) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Set the pid file stream to NULL. */
    *pid = NULL;

    MSG_DEBUG("Close %s successful", PID_FILE);
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
