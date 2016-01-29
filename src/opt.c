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
 * $ArpON: opt.c,v 3.0-ng 01/29/2016 02:56:20 spikey Exp $
 */

#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "exit.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"
#include "std.h"

/*
 * Boolean to string.
 */
#define OPT_BTOA(x)     x == true ? "true" : "false"

/*
 * Vector characters to string.
 */
#define OPT_VTOA(x)     x[0] == '\0' ? "\\0" : x

/*
 * Command option structure definition.
 */
typedef struct opt_option {
    bool daemon;                    /* Daemonize command option. */
    char interface[IF_NAMESIZE];    /* Interface name command option. */
    int inspection;                 /* ARP Inspection command option. */
} opt_t;

/*
 * Function prototypes not exported.
 */
static void opt_init(void);
static void opt_destroy(void);
static void opt_loop(int argc, char **argv);
static void opt_setdaemon(void);
static void opt_setinterface(char *interface);
static void opt_setinspection(int inspection);

/*
 * Initialize the command option structure.
 */
static opt_t *opt = NULL;

/*
 * Initialize and parse the command option.
 */
void
opt_parse(int argc, char **argv)
{

    MSG_DEBUG("Start command option parse");

    /* No specified command option? */
    if (argc == 1) {
        MSG_DEBUG("No command option parse");

        /* Print the help screen, cleanup and exit. */
        std_help();
        exit_cleanup(true);
    }

    /* Initialize the command option structure. */
    opt_init();

    /* Parse the command option and set the command option structure. */
    opt_loop(argc, argv);

    MSG_DEBUG("End command option parse");
}

/*
 * Initialize the command option structure.
 */
static void
opt_init(void)
{

    /* Allocate the command option structure. */
    if ((opt = (opt_t *)malloc(sizeof(opt_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("opt_t *opt allocate in the memory");

    /* Initialize the daemonize command option. */
    opt->daemon = false;
    MSG_DEBUG("opt->daemon = false");

    /* Initialize the interface name command option. */
    memset(opt->interface, '\0', (size_t)IF_NAMESIZE);
    MSG_DEBUG("opt->interface = \\0");

    /* Initialize the ARP Inspection command option. */
    opt->inspection = ISPN_NONE;
    MSG_DEBUG("opt->inspection = NONE");

    /* Push opt_destroy() to be called on exit_cleanup(). */
    exit_push(opt_destroy, "opt_destroy");
}

/*
 * Destroy the command option structure.
 */
static void
opt_destroy(void)
{

    /* Command option structure previously allocated? */
    if (opt != NULL) {
        /* Deallocate the command option structure. */
        free(opt);

        /* Set the command option structure to NULL. */
        opt = NULL;

        MSG_DEBUG("opt_t *opt deallocate from the memory");
    }
}

/*
 * Parse the command option and set the values in the command option structure.
 */
static void
opt_loop(int argc, char **argv)
{
    const struct option long_opt[] = {
        /* General command options. */
        {"daemon",      no_argument,        0,  'd'},
        {"interface",   required_argument,  0,  'i'},

        /* ARP Inspection command options. */
        {"sarpi",       no_argument,        0,  'S'},
        {"darpi",       no_argument,        0,  'D'},
        {"harpi",       no_argument,        0,  'H'},

        /* Standard command options. */
        {"version",     no_argument,        0,  'v'},
        {"help",        no_argument,        0,  'h'},
        {NULL,          0,                  0,   0}
    };
    const char *short_opt = "di:SDHvh";
    int gopt;

    /* Parse the specified command option from the command line. */
    while ((gopt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
        switch (gopt) {
            case 'd':
                MSG_DEBUG("-d or --daemon command option");

                /* Set the daemonize command option. */
                opt_setdaemon();
                break;

            case 'i':
                MSG_DEBUG("-i or --interface command option");

                /* Set the interface name command option. */
                opt_setinterface(optarg);
                break;

            case 'S':
                MSG_DEBUG("-S or --sarpi command option");

                /* Set the SARPI comman option. */
                opt_setinspection(ISPN_SARPI);
                break;

            case 'D':
                MSG_DEBUG("-D or --darpi command option");

                /* Set the DARPI command option. */
                opt_setinspection(ISPN_DARPI);
                break;

            case 'H':
                MSG_DEBUG("-H or --harpi command option");

                /* Set the HARPI command option. */
                opt_setinspection(ISPN_HARPI);
                break;

            case 'v':
                MSG_DEBUG("-v or --version command option");

                /* Print the version command option, cleanup and exit. */
                std_version();
                exit_cleanup(true);

            case 'h':
                MSG_DEBUG("-h or --help command option");

                /* Print the help screen command option, cleanup and exit. */
                std_help();
                exit_cleanup(true);

            case '?':
            case ':':
            default:
                MSG_DEBUG("No valid command option");

                /* Print the help screen and exit. */
                std_help();
                exit(EXIT_FAILURE);
        }
    }

    MSG_DEBUG("Command option looped");
}

/*
 * Set the value of the daemonize in the command option structure.
 */
static void
opt_setdaemon(void)
{

    /* Set the value of the daemonize command option. */
    opt->daemon = true;
    MSG_DEBUG("opt->daemon = true");
}

/*
 * Get the value of the daemonize from the command option structure.
 */
bool
opt_getdaemon(void)
{

    MSG_DEBUG("opt->daemon = %s", OPT_BTOA(opt->daemon));

    /* Get the value of the daemonize command option. */
    return opt->daemon;
}

/*
 * Set the value of the interface name in the command option structure.
 */
static void
opt_setinterface(char *interface)
{
    size_t len = strlen(interface);

    /* Check the length of the interface name command option. */
    if (len >= IF_NAMESIZE) {
        /* Print the info message and exit. */
        MSG_WARN("No valid specified network interface");
        exit(EXIT_FAILURE);
    }

    /* Re-initialize the interface name command option to no interface? */
    if (opt->interface != '\0')
        memset(opt->interface, '\0', (size_t)IF_NAMESIZE);

    /* Set the value of the interface name command option. */
    memcpy(opt->interface, interface, len);

    MSG_DEBUG("opt->interface = %s", opt->interface);
}

/*
 * Get the value of the interface name from the command option structure.
 */
char *
opt_getinterface(void)
{

    MSG_DEBUG("opt->interface = %s", OPT_VTOA(opt->interface));

    /* Get the value of the interface name command option. */
    return opt->interface;
}

/*
 * Set the value of the ARP Inspection in the command option structure.
 */
static void
opt_setinspection(int inspection)
{

    /* Set the value of the ARP Inspection command option. */
    opt->inspection = inspection;

    MSG_DEBUG("opt->inspection = %s", ISPN_ATOA(opt->inspection));
}

/*
 * Get the value of the ARP Inspection from the command option structure.
 */
int
opt_getinspection(void)
{

    MSG_DEBUG("opt->inspection = %s", ISPN_ATOA(opt->inspection));

    /* Get the value of the ARP Inspection command option. */
    return opt->inspection;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
