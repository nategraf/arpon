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
 * $ArpON: proc.c,v 3.0-ng 01/29/2016 02:57:20 spikey Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "exit.h"
#include "msg.h"
#include "opt.h"
#include "proc.h"
#include "queue.h"

/*
 * Proc root path file.
 */
#define PROC_ROOTPATH           "/proc/sys/net/ipv4/conf/"

/*
 * Proc arp_ignore file.
 */
#define PROC_ARPIGNOREPATH      "/arp_ignore"

/*
 * Proc arp_accept file.
 */
#define PROC_ARPACCEPTPATH      "/arp_accept"

/*
 * New value of proc arp_ignore file to disable, in the specified network
 * interface of the Operating System, the sending of the ARP replies in
 * response to received ARP requests for all local addresses.
 */
#define PROC_ARPIGNOREVALUE     8

/*
 * New value of proc arp_accept file to disable, in the specified network
 * interface of the Operating System, the creating of the new IP entries
 * in the ARP cache triggered by the unsolicited and gratuitous ARP requests
 * and replies.
 */
#define PROC_ARPACCEPTVALUE     0

/*
 * Proc file list structure definition.
 */
typedef struct proc_list {
    char *path;                     /* Proc path file. */
    int value;                      /* Proc value file. */

    LIST_ENTRY(proc_list) next;     /* Next proc file list element. */
} proc_t;

/*
 * Function prototypes not exported.
 */
static void  proc_init(void);
static void  proc_destroy(void);
static char *proc_get(int *value);
static void  proc_setprocfs(char *path, int value, bool ignore);
static void  proc_loadfile(const char *file);
static int   proc_getprocfs(char *path);
static void  proc_put(char *path, int value);
static void  proc_setvalues(void);

/*
 * Initialize the proc file list structure.
 */
static LIST_HEAD(proc, proc_list) proc_head = LIST_HEAD_INITIALIZER(proc_head);

/*
 * Initialize and configure the proc files in the proc file system.
 */
void
proc_configure(void)
{

    MSG_DEBUG("Start configure proc file system files");

    /* Initialize the proc file list structure. */
    proc_init();

    /* Load the proc arp_ignore file in the proc file list structure. */
    proc_loadfile(PROC_ARPIGNOREPATH);

    /* Load the proc arp_accept file in the proc file list structure. */
    proc_loadfile(PROC_ARPACCEPTPATH);

    /* Set the new values of the proc files in the proc file system. */
    proc_setvalues();

    MSG_DEBUG("End configure proc file system files");
}

/*
 * Initialize the proc file list structure.
 */
static void
proc_init(void)
{

    /* Set the proc file list structure to NULL. */
    LIST_INIT(&proc_head);
    MSG_DEBUG("Initialize proc file list successful");

    /*
     * Push proc_destroy() to be called on exit().
     * (In case of error, segmentation fault or bus error).
     */
    if (atexit(proc_destroy) != 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("Push proc_destroy() to be called on exit");

    /* Push proc_destroy() to be called on exit_cleanup(). */
    exit_push(proc_destroy, "proc_destroy");
}

/*
 * Destroy the proc file list structure.
 */
static void
proc_destroy(void)
{

    /* No empty proc file list structure? */
    if (LIST_EMPTY(&proc_head) == 0) {
        /* Loop until the proc file list structure is empty. */
        do {
            char *path = NULL;
            int value;

            /* Get the proc file. */
            if ((path = proc_get(&value)) == NULL) {
                /* Proc path file not previously allocated. */
                continue;
            }

            MSG_DEBUG("Restore %s proc file to %d value..", path, value);

            /*
             * Restore the previously value read of
             * the proc file in the proc file system.
             */
            proc_setprocfs(path, value, true);

            /* Deallocate the proc path file. */
            free(path);
            MSG_DEBUG("*path deallocate from the memory");
        } while (LIST_EMPTY(&proc_head) == 0);

        /* Re-initialize the proc file list structure to NULL. */
        LIST_INIT(&proc_head);
    }

    MSG_DEBUG("Destroy proc file list successful");
}

/*
 * Get the proc file list element from the proc file list structure.
 */
static char *
proc_get(int *value)
{
    proc_t *cur = NULL;
    char *path = NULL;

    /* Get the first proc file list element. */
    cur = LIST_FIRST(&proc_head);

    /* Remove the first proc file list element. */
    LIST_REMOVE(cur, next);

    /* Get the proc path file. */
    path = cur->path;
    MSG_DEBUG("cur->path = %s", path);

    /* Get the proc value file. */
    *value = cur->value;
    MSG_DEBUG("cur->value = %d", *value);

    /* Deallocate the proc file list element. */
    free(cur);

    MSG_DEBUG("proc_t *cur deallocate from the memory");
    MSG_DEBUG("Get %s proc file successful", path);

    return path;
}

/*
 * Set the new value of the specified proc file in the proc file system.
 */
static void
proc_setprocfs(char *path, int value, bool ignore)
{

    do {
        struct stat stats;
        FILE *file = NULL;

        /* Check if the proc path file exist. */
        if (stat(path, &stats) < 0) {
            /*
             * In case that the proc file is not exist, ignore the set of the
             * new value of the specified proc file in the proc file system?
             */
            if (errno == ENOENT) {
                if (ignore == true) {
                    MSG_DEBUG("Skip set %s proc file to %d value", path, value);
                    return;
                }
            }

            /* Else exit on error. */
            break;
        }

        /* Check if the proc path file is a regular file. */
        if (S_ISREG(stats.st_mode) == 0) {
            MSG_WARN("%s is not a regular file", path);
            exit(EXIT_FAILURE);
        }

        /* Open the proc file stream to write. */
        if ((file = fopen(path, "w")) == NULL)
            break;

        /* Set the new value of the proc file in the proc file stream. */
        fprintf(file, "%d", value);

        /* Flush the proc file stream. */
        if (fflush(file) == EOF)
            break;

        /* Close the proc file stream. */
        if (fclose(file) == EOF)
            break;

        MSG_DEBUG("Set %s proc file to %d value successful", path, value);

        return;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Load the specified proc file in the proc file list structure.
 */
static void
proc_loadfile(const char *file)
{
    char *interface = NULL, *path = NULL;
    size_t len1, len2, len3, tot_len;
    int value;

    /* Get the interface command option. */
    interface = opt_getinterface();

    /* Calculate all the proc parts path file lengths. */
    len1 = strlen(PROC_ROOTPATH);
    len2 = strlen(interface);
    len3 = strlen(file);

    /* Calculate the sum of all the proc parts path file lengths. */
    tot_len = len1 + len2 + len3 + 1;

    /* Allocate the proc path file. */
    if ((path = (char *)malloc(tot_len)) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("*path allocate in the memory");

    /* Set the value of the proc root path file. */
    memcpy(path, PROC_ROOTPATH, len1);

    /* Set the value of the proc interface path file. */
    tot_len = len1;
    memcpy(&path[tot_len], interface, len2);

    /* Set the value of the specified proc path file. */
    tot_len += len2;
    memcpy(&path[tot_len], file, len3);

    /* Set the terminator character of the proc path file. */
    tot_len += len3;
    path[tot_len] = '\0';

    MSG_DEBUG("path = %s", path);

    /* Get the value of the specified proc file from the proc file system. */
    value = proc_getprocfs(path);
    MSG_DEBUG("value = %d", value);

    /* Put the proc file list element in the proc file list structure. */
    proc_put(path, value);
}

/*
 * Get the value of the specified proc file from the proc file system.
 */
static int
proc_getprocfs(char *path)
{

    do {
        struct stat stats;
        FILE *file = NULL;
        int value;

        /* Check if the proc path file exist. */
        if (stat(path, &stats) < 0)
            break;

        /* Check if the proc path file is a regular file. */
        if (S_ISREG(stats.st_mode) == 0) {
            MSG_WARN("%s is not a regular file", path);
            exit(EXIT_FAILURE);
        }

        /* Open the proc file stream to read. */
        if ((file = fopen(path, "r")) == NULL)
            break;

        /* Get the value of the proc file from the proc file stream. */
        if (fscanf(file, "%d", &value) == EOF)
            break;

        /* Close the proc file stream. */
        if (fclose(file) == EOF)
            break;

        MSG_DEBUG("Get %d value from %s proc file successful", value, path);

        return value;
    } while (0);

    MSG_ERROR("%s", strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Put the proc file list element in the proc file list structure.
 */
static void
proc_put(char *path, int value)
{
    proc_t *new = NULL;

    /* Allocate the proc file list element. */
    if ((new = (proc_t *)malloc(sizeof(proc_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("proc_t *new allocate in the memory");

    /* Initialize the proc path file entry. */
    new->path = path;
    MSG_DEBUG("new->path = %s", new->path);

    /* Initialize the proc value file entry. */
    new->value = value;
    MSG_DEBUG("new->value = %d", new->value);

    /* Empty proc file list structure? */
    if (LIST_EMPTY(&proc_head) != 0) {
        /* Insert the proc file list element in the head. */
        LIST_INSERT_HEAD(&proc_head, new, next);
        MSG_DEBUG("H-Insert <%s, %d> proc file successful", path, value);
    } else {
        proc_t *first = NULL;

        /* Get the first proc file list element. */
        first = LIST_FIRST(&proc_head);

        /* Insert the proc file list element after the first or head. */
        LIST_INSERT_AFTER(first, new, next);
        MSG_DEBUG("A-Insert <%s, %d> proc file successful", path, value);
    }
}

/*
 * Set the new values of the proc files in the proc file system.
 */
static void
proc_setvalues(void)
{
    proc_t *cur = NULL;

    /* Loop for each proc file element. */
    LIST_FOREACH(cur, &proc_head, next) {
        char *file = NULL;

        /* Get the proc specified proc path file. */
        file = strrchr(cur->path, '/');

        /* arp_ignore or arp_accept proc file? */
        if (strcmp(file, PROC_ARPIGNOREPATH) == 0) {
            /*
             * Set the new value of the arp_ignore
             * proc file in the proc file system.
             */
            proc_setprocfs(cur->path, PROC_ARPIGNOREVALUE, false);
        } else {
            /*
             * Set the new value of the arp_accept
             * proc file in the proc file system.
             */
            proc_setprocfs(cur->path, PROC_ARPACCEPTVALUE, false);
        }
    }

    MSG_DEBUG("Set values of the proc files successful");
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
