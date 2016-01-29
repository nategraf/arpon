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
 * $ArpON: main.c,v 3.0-ng 01/29/2016 03:02:46 spikey Exp $
 */

#include <netinet/ether.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdbool.h>

#include "dmn.h"
#include "env.h"
#include "exit.h"
#include "intf.h"
#include "ispn.h"
#include "opt.h"
#include "sig.h"
#include "thd.h"

/*
 * ArpON Main.
 */
int
main(int argc, char **argv, char **envp)
{

    /* Audit the environment. */
    env_audit(argv, envp);

    /* Register the main thread. */
    thd_register(NULL, NULL, "main");

    /* Parse the command options. */
    opt_parse(argc, argv);

    /* Configure the interface. */
    intf_configure();

    /* Daemonize the process. */
    dmn_daemonize(argv);

    /* Start the ARP Inspection on the interface. */
    ispn_start();

    /* Handle the signals. */
    sig_handle(argv, envp);

    /* Never reaches here. */
    return 0;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
