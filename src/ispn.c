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
 * $ArpON: ispn.c,v 3.0-ng 01/29/2016 03:05:27 spikey Exp $
 */

#include <netinet/ether.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "arpca.h"
#include "darpica.h"
#include "darpi.h"
#include "harpi.h"
#include "intf.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"
#include "proc.h"
#include "sarpica.h"
#include "sarpi.h"
#include "thd.h"
#include "unused.h"

/*
 * Function prototypes not exported.
 */
static void ispn_handle(int ispn, char *interface);
static void ispn_handlesarpi(char *interface);
static void ispn_handledarpi(char *interface);
static void ispn_handleharpi(char *interface);

/*
 * Initialize and start the ARP Inspection on the interface.
 */
void
ispn_start(void)
{
    int ispn;
    char *interface = NULL;

    MSG_DEBUG("Start ARP Inspection activate");

    /* No specified ARP Inspection command option? */
    if ((ispn = opt_getinspection()) == ISPN_NONE) {
        /* Print the info message and exit. */
        MSG_WARN("No specified ARP Inspection");
        exit(EXIT_FAILURE);
    }

    /* Get the interface command option. */
    interface = opt_getinterface();

    MSG_INFO("Start %s on %s", ISPN_ATOA(ispn), interface);

    /* Configure the proc files in the proc file system. */
    proc_configure();

    /* Cleanup the ARP cache. */
    arpca_cleanup();

    /* Handle the ARP Inspection on the interface name command option. */
    ispn_handle(ispn, interface);

    MSG_DEBUG("End ARP Inspection activate");
}

/*
 * Handle the ARP Inspection on the interface.
 */
static void
ispn_handle(int ispn, char *interface)
{

    /* Handle the ARP Inspection. */
    switch(ispn) {
        case ISPN_SARPI:
            MSG_DEBUG("Run SARPI on %s..", interface);

            /* Handle and activate the SARPI. */
            ispn_handlesarpi(interface);
            break;

        case ISPN_DARPI:
            MSG_DEBUG("Run DARPI on %s..", interface);

            /* Handle and activate the DARPI. */
            ispn_handledarpi(interface);
            break;

        /* ISPN_HARPI. */
        default:
            MSG_DEBUG("Run HARPI on %s..", interface);

            /* Handle and activate the HARPI. */
            ispn_handleharpi(interface);
            break;
    }
}

/*
 * Handle the SARPI on the interface.
 */
static void
ispn_handlesarpi(UNUSED(char *interface))
{

    MSG_DEBUG("Handle the SARPI on %s..", interface);

    /* Configure the SARPI cache and register the SARPI cache handler thread. */
    sarpica_configure();

    MSG_DEBUG("SARPI cache handler ready and running on %s", interface);

    /* Register the SARPI live capture handler thread. */
    thd_register(intf_capture, sarpi_handler, "intf_capture");

    MSG_DEBUG("SARPI live capture handler ready and running on %s", interface);
}

/*
 * Handle the DARPI on the interface.
 */
static void
ispn_handledarpi(UNUSED(char *interface))
{

    MSG_DEBUG("Handle the DARPI on %s..", interface);

    /* Configure the DARPI cache and register the DARPI cache handler thread. */
    darpica_configure();

    MSG_DEBUG("DARPI cache handler ready and running on %s", interface);

    /* Register the DARPI live capture handler thread. */
    thd_register(intf_capture, darpi_handler, "intf_capture");

    MSG_DEBUG("DARPI live capture handler ready and running on %s", interface);
}

/*
 * Handle the HARPI on the interface.
 */
static void
ispn_handleharpi(UNUSED(char *interface))
{

    MSG_DEBUG("Handle the HARPI on %s..", interface);

    /* Configure the SARPI cache and register the SARPI cache handler thread. */
    sarpica_configure();

    MSG_DEBUG("SARPI cache ready and running on %s", interface);

    /* Configure the DARPI cache and register the DARPI cache handler thread. */
    darpica_configure();

    MSG_DEBUG("DARPI cache handler ready and running on %s", interface);

    /* Register the HARPI live capture handler thread. */
    thd_register(intf_capture, harpi_handler, "intf_capture");

    MSG_DEBUG("HARPI live capture handler ready and running on %s", interface);
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
