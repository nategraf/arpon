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
 * $ArpON: intf.c,v 3.0-ng 01/29/2016 03:00:44 spikey Exp $
 */

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#include <libnet.h>

#include "exit.h"
#include "intf.h"
#include "ispn.h"
#include "msg.h"
#include "opt.h"
#include "thd.h"
#include "unused.h"

/*
 * Any device.
 */
#define INTF_ANYDEV         "any"

/*
 * Nflog device.
 */
#define INTF_NFLOGDEV       "nflog"

/*
 * Nfqueue device.
 */
#define INTF_NFQUEUEDEV     "nfqueue"

/*
 * Ethernet header (14 bytes) + ARP header (28 bytes) total length.
 */
#define INTF_HDRLEN         sizeof(struct ether_header) +   \
                            sizeof(struct ether_arp)
/*
 * Snapshot capture length.
 */
#define INTF_SNAPLEN        (int)INTF_HDRLEN    /* 14 + 28 = 42 bytes. */

/*
 * Promiscuous mode.
 */
#define INTF_PROMISC        0                   /* Disabled. */

/*
 * Read capture timeout.
 */
#define INTF_READTIMEOUT    1                   /* 1 millisecond. */

/*
 * Buffer capture size.
 */
#define INTF_BUFFERSIZE     16 * 1024 * 1024    /* 16 MiB. */

/*
 * Non-blocking mode.
 */
#define INTF_NONBLOCKING    1                   /* Enabled. */

/*
 * Ethernet datalink.
 */
#define INTF_ETHDATALINK    DLT_EN10MB

/*
 * Loop suspend timeout.
 */
#define INTF_LOOPTIMEOUT    5                   /* 5 seconds. */

/*
 * ARP filter.
 */
#define INTF_ARPFILTER      "arp"

/*
 * No seconds.
 */
#define INTF_SECS           0

/*
 * Milliseconds to microseconds.
 */
#define INTF_MILLI2MICRO(x) x * 1000

/*
 * Live capture counter.
 */
#define INTF_LOOPCOUNT      -1                  /* All ARP packets received. */

/*
 * IP address length.
 */
#define INTF_IP_ALEN        4                   /* 4 bytes. */

/*
 * All IP addresses.
 */
#define INTF_IPZEROSTRADDR  "0.0.0.0"

/*
 * MAC broadcast address.
 */
#define INTF_MACBROSTRADDR  "ff:ff:ff:ff:ff:ff"

/*
 * ARP operation type to string.
 */
#define INTF_ATOA(x)        x == ARPOP_REQUEST ? "ARP request" : "ARP reply"

/*
 * Interface config structure definition.
 */
typedef struct intf_config {
    /* Pcap configuration on the interface. */
    pcap_t *pcap;                           /* Pcap capture handle. */
    char pcap_errbuf[PCAP_ERRBUF_SIZE];     /* Pcap error buffer. */

    /* Libnet configuration on the interface. */
    libnet_t *lnet;                         /* Libnet network handle. */
    char lnet_errbuf[LIBNET_ERRBUF_SIZE];   /* Libnet error buffer. */

    /* Interface configuration. */
    struct ether_addr mac;                  /* Interface MAC addr config. */
    struct in_addr ip;                      /* Interface IP addr config. */
    struct in_addr network;                 /* Interface Net addr config. */
    struct in_addr netmask;                 /* Interface Mask addr config. */
} intf_t;

/*
 * Function prototypes not exported.
 */
static void intf_autoconfinterface(char *interface);
static void intf_init(void);
static void intf_destroy(void);
static int  intf_isvalidinterface(char *interface);
static void intf_setmac(char *interface);
static int  intf_setip(char *interface);
static void intf_setarpfilter(void);
static void intf_decoder(unsigned char *callback,
    const struct pcap_pkthdr *header, const unsigned char *bytes);

/*
 * Initialize the interface config structure.
 */
static intf_t *cfg = NULL;

/*
 * Initialize and configure the interface.
 */
void
intf_configure(void)
{
    char *interface = NULL;

    MSG_DEBUG("Start configure interface");

    /* No specified interface name command option? */
    if (*((interface = opt_getinterface()) + 0) == '\0') {
        /* Print the info message and exit. */
        MSG_WARN("No specified network interface");
        exit(EXIT_FAILURE);
    }

    /* Autoconf the specified interface name. */
    intf_autoconfinterface(interface);

    /* Set the ARP filter on the interface. */
    intf_setarpfilter();

    MSG_DEBUG("End configure interface");
}

/*
 * Autoconf the interface name from the command option structure.
 */
static void
intf_autoconfinterface(char *interface)
{

    MSG_DEBUG("Autoconf %s network interface..", interface);

    /*
     * Loop until the interface is found and MAC addr,
     * IP addr, Net and Mask addrs are available.
     */
    while (1) {
        /* Initialize the interface config structure. */
        intf_init();

        do {
            /* No valid specified interface name? */
            if (intf_isvalidinterface(interface) < 0)
                break;

            /* Set the interface MAC addr config. */
            intf_setmac(interface);

            /* Set the interface IP addrs config. */
            if (intf_setip(interface) < 0)
                break;

            MSG_DEBUG("Autoconf %s network interface successful", interface);

            return;
        } while (0);

        /* Destroy the interface config structure. */
        intf_destroy();

        MSG_WARN("No autoconf %s network interface, retry in 5 seconds..",
            interface);

        /* Suspend the execution of the thread for 5 seconds. */
        thd_suspend(INTF_LOOPTIMEOUT);

        /* Loop again. */
        continue;
    }
}

/*
 * Initialize the interface config structure.
 */
static void
intf_init(void)
{

    /* Allocate the interface config structure. */
    if ((cfg = (intf_t *)malloc(sizeof(intf_t))) == NULL) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("intf_t *cfg allocate in the memory");

    /* Initialize the pcap capture handle. */
    cfg->pcap = NULL;
    MSG_DEBUG("cfg->pcap = NULL");

    /* Initialize the pcap error buffer. */
    memset(&cfg->pcap_errbuf, '\0', (size_t)PCAP_ERRBUF_SIZE);
    MSG_DEBUG("cfg->pcap_errbuf = \\0");

    /* Initialize the libnet network handle. */
    cfg->lnet = NULL;
    MSG_DEBUG("cfg->lnet = NULL");

    /* Initialize the libnet error buffer. */
    memset(&cfg->lnet_errbuf, '\0', (size_t)LIBNET_ERRBUF_SIZE);
    MSG_DEBUG("cfg->lnet_errbuf = \\0");

    /* Initialize the interface MAC addr config. */
    memset(&cfg->mac, 0, sizeof(cfg->mac));
    MSG_DEBUG("cfg->mac = 0:0:0:0:0:0");

    /* Initialize the interface IP addr config. */
    memset(&cfg->ip, 0, sizeof(cfg->ip));
    MSG_DEBUG("cfg->ip = 0.0.0.0");

    /* Initialize the interface Net addr config. */
    memset(&cfg->network, 0, sizeof(cfg->network));
    MSG_DEBUG("cfg->network = 0.0.0.0");

    /* Initialize the interface Mask addr config. */
    memset(&cfg->netmask, 0, sizeof(cfg->netmask));
    MSG_DEBUG("cfg->netmask = 0.0.0.0");

    /* Push intf_destroy() to be called on exit_cleanup(). */
    exit_push(intf_destroy, "intf_destroy");
}

/*
 * Destroy the interface config structure.
 */
static void
intf_destroy(void)
{

    /* Interface config structure previously allocated? */
    if (cfg != NULL) {
        /* Pcap capture handle had never been open? */
        if (cfg->pcap != NULL) {
            struct pcap_stat UNUSED(stat);

#ifndef NDEBUG
            /* Get the captured (and not) packets statistics. */
            if (pcap_stats(cfg->pcap, &stat) < 0) {
                MSG_ERROR("%s", pcap_geterr(cfg->pcap));
                exit(EXIT_FAILURE);
            }
#endif  /* !NDEBUG */

            MSG_DEBUG("Packets received by filter = %u", stat.ps_recv);
            MSG_DEBUG("Packets dropped by kernel = %u", stat.ps_drop);
            MSG_DEBUG("Packets dropped by interface = %u", stat.ps_ifdrop);

            /* Close the pcap capture handle. */
            pcap_close(cfg->pcap);

            /* Set the pcap capture handle to NULL. */
            cfg->pcap = NULL;

            MSG_DEBUG("Close cfg->pcap successful");
        }

        /* Libnet network handle had never been initialized? */
        if (cfg->lnet != NULL) {
            /* Destroy the libnet network handle. */
            libnet_destroy(cfg->lnet);

            /* Set the libnet network handle to NULL. */
            cfg->lnet = NULL;

            MSG_DEBUG("Destroy cfg->lnet successful");
        }

        /* Deallocate the interface config structure. */
        free(cfg);

        /* Set the interface config structure to NULL. */
        cfg = NULL;

        MSG_DEBUG("intf_t *cfg deallocate from the memory");
    }
}

/*
 * Validate the interface name from the command option structure.
 */
static int
intf_isvalidinterface(char *interface)
{

    do {
        pcap_if_t *alldevs = NULL, *dev = NULL;
        int snapshot;
        bool valid = false;

        /* Allocate and set the list of interfaces that can be open by pcap. */
        if (pcap_findalldevs(&alldevs, cfg->pcap_errbuf) < 0)
            break;

        /* No interfaces that can be open by pcap? */
        if (alldevs == NULL) {
            /* Print the info message and exit. */
            MSG_DEBUG("No exist network interface in the system");
            return -1;
        }

        /* Walk through the list of interfaces that can be open by pcap. */
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            /* Skip the pseudo interfaces. */
            if (strcmp(dev->name, INTF_ANYDEV) == 0 ||
                strcmp(dev->name, INTF_NFLOGDEV) == 0 ||
                strcmp(dev->name, INTF_NFQUEUEDEV) == 0) {
                continue;
            }

            /* Skip the loopback interface. */
            if ((dev->flags & PCAP_IF_LOOPBACK) != 0)
                continue;

            /* Valid specified interface name for pcap? */
            if (strncmp(interface, dev->name, (size_t)IF_NAMESIZE) == 0) {
                /* Valid specified interface name for pcap. */
                valid = true;
                break;
            }
        }

        /* No valid specified interface name for pcap?  */
        if (valid == false) {
            MSG_DEBUG("No valid specified network interface");

            /* Deallocate the list of interfaces that can be open by pcap. */
            pcap_freealldevs(alldevs);

            return -1;
        }

        /* Create the pcap capture handle to look at packets on the network. */
        if ((cfg->pcap = pcap_create(interface, cfg->pcap_errbuf)) == NULL)
            break;

        MSG_DEBUG("interface = %s", interface);

        /* Set the snapshot capture length to 42 bytes. */
        if (pcap_set_snaplen(cfg->pcap, INTF_SNAPLEN) < 0) {
            MSG_ERROR("No set snaplen to %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("snaplen = %d", INTF_SNAPLEN);

        /* Disable the promiscuous mode on the interface. */
        if (pcap_set_promisc(cfg->pcap, INTF_PROMISC) < 0) {
            MSG_ERROR("No disable promisc to %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("promisc = %d", INTF_PROMISC);

        /* Set the read capture timeout to 1 millisecond. */
        if (pcap_set_timeout(cfg->pcap, INTF_READTIMEOUT) < 0) {
            MSG_ERROR("No set timeout to %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("read_timeout = %d", INTF_READTIMEOUT);

        /* Set the buffer capture size to 16 MiB. */
        if (pcap_set_buffer_size(cfg->pcap, INTF_BUFFERSIZE) < 0) {
            MSG_ERROR("No set buffer size to %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("buffer_size = %d", INTF_BUFFERSIZE);

        /* Activate the pcap capture handle. */
        if (pcap_activate(cfg->pcap) < 0) {
            MSG_ERROR("No activate %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("Activate cfg->pcap successful");

        /* Get the snapshot capture length. */
        if ((snapshot = pcap_snapshot(cfg->pcap)) < 0) {
            MSG_ERROR("No get snapshot from %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("snapshot = %d", snapshot);

        /* Assigned shapshot is the same of our snapshot? */
        if (snapshot != INTF_SNAPLEN) {
            MSG_ERROR("No assigned snaplen to %s network interface", interface);
            exit(EXIT_FAILURE);
        }

        /* Valid Ethernet link-layer header type for the live capture? */
        if (pcap_datalink(cfg->pcap) != INTF_ETHDATALINK) {
            MSG_WARN("No Ethernet specified network interface");
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("type = Ethernet/Wi-Fi");

        /* Enable the non-blocking mode. */
        if (pcap_setnonblock(cfg->pcap, INTF_NONBLOCKING, cfg->pcap_errbuf) < 0)
            break;

        MSG_DEBUG("non-blocking = %d", INTF_NONBLOCKING);

        /* Deallocate the list of interfaces that can be open by pcap. */
        pcap_freealldevs(alldevs);

        MSG_DEBUG("%s network interface is valid", interface);

        return 0;
    } while (0);

    MSG_ERROR("%s", cfg->pcap_errbuf);
    exit(EXIT_FAILURE);
}

/*
 * Set the value of the interface MAC addr in the interface config structure.
 */
static void
intf_setmac(char *interface)
{
    struct libnet_ether_addr *mac = NULL;

    /* Initialize the libnet network handle. */
    if ((cfg->lnet = libnet_init(
        LIBNET_LINK,        /* Link layer interface. */
        interface,          /* Specified interface. */
        cfg->lnet_errbuf)) == NULL) {
        MSG_ERROR("%s", cfg->lnet_errbuf);
        exit(EXIT_FAILURE);
    }

    MSG_DEBUG("Initialize cfg->lnet successful");

    /* Get the interface MAC addr to libnet. */
    if ((mac = libnet_get_hwaddr(cfg->lnet)) == NULL) {
        MSG_ERROR("%s", libnet_geterror(cfg->lnet));
        exit(EXIT_FAILURE);
    }

    /* MAC addr available. */
    MSG_DEBUG("MAC address available on the network interface");

    /* Set the value of the interface MAC addr config. */
    memcpy(&cfg->mac.ether_addr_octet, mac->ether_addr_octet, (size_t)ETH_ALEN);
    MSG_DEBUG("cfg->mac = %s", ether_ntoa(&cfg->mac));
}

/*
 * Set the value of the interface IP addrs in the interface config structure.
 */
static int
intf_setip(char *interface)
{
    uint32_t ip, network, netmask;

    /* Get the interface IP addr to libnet. */
    if ((ip = libnet_get_ipaddr4(cfg->lnet)) == (uint32_t)-1) {
        /* No IP addr available? */
        if (errno == EADDRNOTAVAIL) {
            MSG_WARN("No IP address available");
            return -1;
        } else {
            MSG_ERROR("%s", libnet_geterror(cfg->lnet));
            exit(EXIT_FAILURE);
        }
    }

    /* IP addr available. */
    MSG_DEBUG("IP address available on the network interface");

    /* Get the interface Net and Mask addrs to pcap. */
    if (pcap_lookupnet(
        interface,          /* Specified interface. */
        &network,           /* Net addr. */
        &netmask,           /* Mask addr. */
        cfg->pcap_errbuf) < 0) {
        /* No Net and Mask addrs available? */
        if (errno == EADDRNOTAVAIL) {
            MSG_WARN("No Net and Mask addresses available");
            return -1;
        } else {
            MSG_ERROR("%s", cfg->pcap_errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* Net and Mask addrs available. */
    MSG_DEBUG("Net and Mask addresses available on the network interface");

    /* Set the value of the interface IP addr config. */
    cfg->ip.s_addr = ip;
    MSG_DEBUG("cfg->ip = %s", inet_ntoa(cfg->ip));

    /* Set the value of the interface Net addr config. */
    cfg->network.s_addr = network;
    MSG_DEBUG("cfg->network = %s", inet_ntoa(cfg->network));

    /* Set the value of the interface Mask addr config. */
    cfg->netmask.s_addr = netmask;
    MSG_DEBUG("cfg->netmask = %s", inet_ntoa(cfg->netmask));

    return 0;
}

/*
 * Get the value of the interface Net addr from the interface config structure.
 */
struct in_addr *
intf_getnetwork(void)
{

    MSG_DEBUG("cfg->network = %s", inet_ntoa(cfg->network));

    /* Get the value of the interface Net addr config. */
    return &cfg->network;
}

/*
 * Get the value of the interface Mask addr from the interface config structure.
 */
struct in_addr *
intf_getnetmask(void)
{

    MSG_DEBUG("cfg->netmask = %s", inet_ntoa(cfg->netmask));

    /* Get the value of the interface Mask addr config. */
    return &cfg->netmask;
}

/*
 * Set the ARP filter on the interface.
 */
static void
intf_setarpfilter(void)
{

    do {
        struct bpf_program bpf;

        /* Compile the ARP string filter and allocate the ARP filter program. */
        if (pcap_compile(
            cfg->pcap,
            &bpf,               /* ARP filter program. */
            INTF_ARPFILTER,     /* ARP string filter. */
            0,                  /* Not optimized. */
            cfg->netmask.s_addr) < 0) {
            break;
        }

        /* Set the compiled ARP filter program on the interface. */
        if (pcap_setfilter(cfg->pcap, &bpf) < 0)
            break;

        /* Deallocate the ARP filter program. */
        pcap_freecode(&bpf);

        MSG_DEBUG("Set ARP filter on the network interface successful");

        return;
    } while (0);

    MSG_ERROR("%s", pcap_geterr(cfg->pcap));
    exit(EXIT_FAILURE);
}

/*
 * Live capture of the I/O ARP packets read from the network traffic
 * of the interface and run the live capture decoder callback routine.
 */
void *
intf_capture(void *callback)
{
    struct timeval timeout;
    int fd;

    /* Initialize the thread. */
    thd_init();

    MSG_DEBUG("Capture on %s..", opt_getinterface());

    /* Get the pcap capture handle file descriptor. */
    if ((fd = pcap_get_selectable_fd(cfg->pcap)) < 0) {
        MSG_ERROR("No selectable file descriptor from pcap");
        exit(EXIT_FAILURE);
    }

    /* Set the read capture timeout to 1 millisecond. */
    timeout.tv_sec = INTF_SECS;     /* No seconds. */
    timeout.tv_usec = INTF_MILLI2MICRO(INTF_READTIMEOUT);

    /*
     * Loop until the network traffic of the interface is up.
     * This loop uses select + pcap in order to process the
     * I/O asynchronous ARP packets read from the buffer.
     */
    while (1) {
        fd_set fdread;

        /* Clear the set. */
        FD_ZERO(&fdread);

        /* Add the pcap capture handle file descriptor to set. */
        FD_SET(fd, &fdread);

        /*
         * Monitor the pcap capture handle file descriptor
         * until it becomes ready for the reading.
         */
        if (select(fd + 1, &fdread, NULL, NULL, &timeout) < 0) {
            /* Interrupt signal? */
            if (errno == EINTR) {
                /* Loop again with the time remaining calculated by select. */
                continue;
            }

            MSG_ERROR("%s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Pcap capture handle file descriptor is ready to reading? */
        if (FD_ISSET(fd, &fdread) != 0) {
            /*
             * Process the live capture from the network traffic (read from
             * the buffer) and run the live capture decoder callback routine.
             */
            if (pcap_dispatch(
                cfg->pcap,
                INTF_LOOPCOUNT,     /* Live capture counter to all the packets
                                     * received into buffer to be processed. */
                intf_decoder,       /* Live capture decoder callback routine. */
                callback) < 0) {    /* ARP Inspection live capture
                                     * handler callback routine. */
                /* Network of the interface down? */
                if (errno == ENETDOWN) {
                    MSG_WARN("Network is down, wait for 5 seconds..");

                    /* Suspend the execution of the thread for 5 seconds. */
                    thd_suspend(INTF_LOOPTIMEOUT);

                    MSG_DEBUG("Send a hangup signal to ourself");

                    /* Request to ourself the reboot of ArpON. */
                    kill(getpid(), SIGHUP);
                } else {
                    MSG_ERROR("%s", pcap_geterr(cfg->pcap));
                    exit(EXIT_FAILURE);
                }
            }
        }

        /* Re-set the read capture timeout to 1 millisecond. */
        timeout.tv_sec = INTF_SECS;     /* No seconds. */
        timeout.tv_usec = INTF_MILLI2MICRO(INTF_READTIMEOUT);
    }

    /* Never reaches here. */
    return NULL;
}

/*
 * Live capture decoder of the I/O ARP packets read from
 * the network traffic of the interface and run the ARP
 * Inspection live capture handler callback routine.
 */
static void
intf_decoder(unsigned char *callback, const struct pcap_pkthdr *header,
    const unsigned char *bytes)
{

    do {
        const struct ether_header *heth = NULL;
        const struct ether_arp *harp = NULL;
        struct ether_addr macsrc, macdst;
        struct in_addr ipzero, ipsrc, ipdst;
        void (*handler)(int, struct ether_addr *, struct in_addr *,
            struct ether_addr *, struct in_addr *) = NULL;
        int op;

        MSG_DEBUG("Start live capture decoder");

        /* Skip the malformed ARP packet read. */
        if (header->caplen > header->len || header->caplen > INTF_SNAPLEN) {
            MSG_DEBUG("Skip the malformed ARP packet read");

            /* Break immediately. */
            break;
        }

        /* Skip the truncated ARP packet read. */
        if (header->caplen < sizeof(*heth) + sizeof(*harp)) {
            MSG_DEBUG("Skip the truncated ARP packet read");

            /* Break immediately. */
            break;
        }

        /* Extract the Etherner header from the bytes. */
        heth = (const struct ether_header *)bytes;

        /* Extract the ARP header and ARP addresses from the bytes. */
        harp = (const struct ether_arp *)(heth + 1);

        /* Skip the ARP packet read that isn't a request or reply. */
        if (ntohs(heth->ether_type) != ETHERTYPE_ARP && /* ARP. */
            ntohs(harp->arp_hrd) != ARPHRD_ETHER &&     /* Eth addr format. */
            ntohs(harp->arp_pro) != ETHERTYPE_IP &&     /* IP addr format. */
            ntohs(harp->arp_hln) != ETH_ALEN &&         /* Eth addr len. */
            ntohs(harp->arp_pln) != INTF_IP_ALEN &&     /* IP addr len. */
            ntohs(harp->arp_op) != ARPOP_REQUEST &&     /* ARP request. */
            ntohs(harp->arp_op) != ARPOP_REPLY) {       /* ARP reply. */
            MSG_DEBUG("Skip the ARP packet read that isn't a request or reply");

            /* Break immediately. */
            break;
        }

        /* All IP addrs to network byte order. */
        if (inet_aton(INTF_IPZEROSTRADDR, &ipzero) == 0) {
            MSG_ERROR("%s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        MSG_DEBUG("ipzero = %s", inet_ntoa(ipzero));

        /* Copy SHA network byte order to MAC src addr network byte order. */
        memcpy(macsrc.ether_addr_octet, harp->arp_sha, ETH_ALEN);
        MSG_DEBUG("macsrc = %s", ether_ntoa(&macsrc));

        /* Copy SPA network byte order to IP src addr network byte order. */
        memcpy(&ipsrc.s_addr, harp->arp_spa, INTF_IP_ALEN);
        MSG_DEBUG("ipsrc = %s", inet_ntoa(ipsrc));

        /*
         * IP src addr is not part of the same network of the interface?
         * Therefore:
         *
         * IP src addr is not part of the same network of the interface =
         *      (IP src addr & Interface Mask addr) != Interface Net addr &&
         *      IP src addr != All IP addrs
         */
        if ((ipsrc.s_addr & cfg->netmask.s_addr) != cfg->network.s_addr &&
            memcmp(&ipsrc.s_addr, &ipzero.s_addr, INTF_IP_ALEN) != 0) {
            MSG_DEBUG("Skip the ARP packet read that is not part of network");

            /* Break immediately. */
            break;
        }

        /* Copy THA network byte order to MAC dst addr network byte order. */
        memcpy(macdst.ether_addr_octet, harp->arp_tha, ETH_ALEN);
        MSG_DEBUG("macdst = %s", ether_ntoa(&macdst));

        /* Copy TPA network byte order to IP dst addr network byte order. */
        memcpy(&ipdst.s_addr, harp->arp_tpa, INTF_IP_ALEN);
        MSG_DEBUG("ipdst = %s", inet_ntoa(ipdst));

        /*
         * IP dst addr is not part of the same network of the interface?
         * Therefore:
         *
         * IP dst addr is not part of the same network of the interface =
         *      (IP dst addr & Interface Mask addr) != Interface Net addr &&
         *      IP dst addr != All IP addrs
         */
        if ((ipdst.s_addr & cfg->netmask.s_addr) != cfg->network.s_addr &&
            memcmp(&ipdst.s_addr, &ipzero.s_addr, INTF_IP_ALEN) != 0) {
            MSG_DEBUG("Skip the ARP packet read that is not part of network");

            /* Break immediately. */
            break;
        }

        /* Initialize the ARP packet op code. */
        op = INTF_ARPOP_INIT;
        MSG_DEBUG("op = ARP");

        /* Check the type of the ARP packet read. */
        switch (ntohs(harp->arp_op)) {
            case ARPOP_REQUEST:
                /* ARP request packet. */
                op |= INTF_ARPOP_REQUEST;
                MSG_DEBUG("op |= Request");
                break;

            /* ARPOP_REPLY. */
            default:
                /* ARP reply packet. */
                op |= INTF_ARPOP_REPLY;
                MSG_DEBUG("op |= Reply");
                break;
        }

        /*
         * Check if the ARP request/reply packet is a gratuitous ARP request/
         * reply packet, therefore:
         *
         * Gratuitous ARP request/reply packet sent by us or sent to us =
         *      IP src addr == IP dst addr
         */
        if (memcmp(
            &ipsrc.s_addr,                      /* IP src addr. */
            &ipdst.s_addr,                      /* IP dst addr. */
            INTF_IP_ALEN) == 0) {
            /* Gratuitous ARP request/reply packet. */
            op |= INTF_ARPOP_GRATUITOUS;
            MSG_DEBUG("op |= Gratuitous");

            /*
             * Check if the gratuitous ARP request/reply packet is a no valid
             * gratuitous ARP request/reply packet, therefore:
             *
             * Gratuitous ARP request/reply packet no valid =
             *      IP src addr == All IP addrs &&
             *      IP dst addr == All IP addrs
             */
            if (memcmp(
                &ipsrc.s_addr,                  /* IP src addr. */
                &ipzero.s_addr,                 /* All IP addrs. */
                INTF_IP_ALEN) == 0 &&
                memcmp(
                &ipdst.s_addr,                  /* IP dst addr. */
                &ipzero.s_addr,                 /* All IP addrs. */
                INTF_IP_ALEN) == 0) {
                MSG_DEBUG("Skip the ARP packet read that is not valid");

                /* Break immediately. */
                break;
            }

            /*
             * Check the I/O bound direction of the gratuitous ARP request/
             * reply packet read (sent by us or sent to us), therefore:
             *
             * Gratuitous ARP request/reply packet sent by us =
             *      MAC src addr == Interface MAC addr &&
             *      IP src/dst addr == Interface IP addr
             *
             * Gratuitous ARP request/reply packet sent to us =
             *      IP src/dst addr != Interface IP addr
             */
            if (memcmp(
                macsrc.ether_addr_octet,        /* MAC src addr. */
                &cfg->mac.ether_addr_octet,     /* Interface MAC addr. */
                ETH_ALEN) == 0 &&
                memcmp(
                &ipsrc.s_addr,                  /* IP src/dst addr. */
                &cfg->ip.s_addr,                /* Interface IP addr. */
                INTF_IP_ALEN) == 0) {
                /* Gratuitous ARP request/reply packet sent by us. */
                op |= INTF_ARPOP_OUTBOUND;
                MSG_DEBUG("op |= Outbound");
            } else if (
                memcmp(
                &ipsrc.s_addr,                  /* IP src/dst addr. */
                &cfg->ip.s_addr,                /* Interface IP addr. */
                INTF_IP_ALEN) != 0) {
                /* Gratuitous ARP request/reply packet sent to us. */
                op |= INTF_ARPOP_INBOUND;
                MSG_DEBUG("op |= Inbound");
            }
        }

        /*
         * Check if the ARP request/reply packet is a probe ARP request/reply
         * packet, therefore:
         *
         * Probe ARP request/reply packet sent by us or sent to us =
         *      (IP src addr == All IP addrs &&
         *       IP dst addr == Interface IP addr) ||
         *      (IP src addr == Interface IP addr &&
         *       IP dst addr == All IP addrs)
         */
        if ((memcmp(
            &ipsrc.s_addr,                      /* IP src addr. */
            &ipzero.s_addr,                     /* All IP addrs. */
            INTF_IP_ALEN) == 0 &&
            memcmp(
            &ipdst.s_addr,                      /* IP dst addr. */
            &cfg->ip.s_addr,                    /* Interface IP addr. */
            INTF_IP_ALEN) == 0) ||
            (memcmp(
            &ipsrc.s_addr,                      /* IP src addr. */
            &cfg->ip.s_addr,                    /* Interface IP addr. */
            INTF_IP_ALEN) == 0 &&
            memcmp(
            &ipdst.s_addr,                      /* IP dst addr. */
            &ipzero.s_addr,                     /* All IP addrs. */
            INTF_IP_ALEN) == 0)) {
            /* Probe ARP request/reply packet. */
            op |= INTF_ARPOP_PROBE;
            MSG_DEBUG("op |= Probe");

            /*
             * Check the I/O bound direction of the probe ARP request/reply
             * packet read (sent by us or sent to us), therefore:
             *
             * Probe ARP request/reply packet sent by us =
             *      MAC src addr == Interface MAC addr
             *
             * Probe ARP request packet sent to us =
             *      MAC src addr != Interface MAC addr
             */
            if (memcmp(
                macsrc.ether_addr_octet,        /* MAC src addr. */
                &cfg->mac.ether_addr_octet,     /* Interface MAC addr. */
                ETH_ALEN) == 0) {
                /* Probe ARP request/reply sent by us. */
                op |= INTF_ARPOP_OUTBOUND;
                MSG_DEBUG("op |= Outbound");
            } else {
                /* Probe ARP request/reply sent to us. */
                op |= INTF_ARPOP_INBOUND;
                MSG_DEBUG("op |= Inbound");
            }
        }

        /*
         * Check if the ARP request/reply packet is not a gratuitous ARP
         * request/reply packet or a probe ARP request/reply packet.
         */
        if ((op & INTF_ARPOP_GRATUITOUS) == 0 && /* No gratuitous ARP packet. */
            (op & INTF_ARPOP_PROBE) == 0) {      /* No probe ARP packet. */
            /*
             * Check the I/O bound direction of the ARP request/reply packet
             * read (sent by us or sent to us), therefore:
             *
             * ARP request/reply packet sent by us =
             *      MAC src addr == Interface MAC addr &&
             *      IP src addr == Interface IP addr
             *
             * ARP request/reply packet sent to us =
             *      IP dst addr == Interface IP addr
             */
            if (memcmp(
                macsrc.ether_addr_octet,        /* MAC src addr. */
                &cfg->mac.ether_addr_octet,     /* Interface MAC addr. */
                ETH_ALEN) == 0 &&
                memcmp(
                &ipsrc.s_addr,                  /* IP src addr. */
                &cfg->ip.s_addr,                /* Interface IP addr. */
                INTF_IP_ALEN) == 0) {
                /* ARP request/reply packet sent by us. */
                op |= INTF_ARPOP_OUTBOUND;
                MSG_DEBUG("op |= Outbound");
            } else if (
                memcmp(
                &ipdst.s_addr,                  /* IP dst addr. */
                &cfg->ip.s_addr,                /* Interface IP addr. */
                INTF_IP_ALEN) == 0) {
                /* ARP request/reply packet sent to us. */
                op |= INTF_ARPOP_INBOUND;
                MSG_DEBUG("op |= Inbound");
            }
        }

        /* Skip the ARP packet read that isn't matched by decoder. */
        if ((op & INTF_ARPOP_OUTBOUND) == 0 &&  /* No ARP packet sent by us. */
            (op & INTF_ARPOP_INBOUND) == 0) {   /* No ARP packet sent to us. */
            MSG_DEBUG("Skip the ARP packet read that isn't matched by decoder");

            /* Break immediately. */
            break;
        }

        /* Set the ARP Inspection live capture handler callback routine. */
        handler = (void (*)(int, struct ether_addr *, struct in_addr *,
            struct ether_addr *, struct in_addr *))callback;

        /* Run the ARP Inspection live capture handler callback routine. */
        handler(op, &macsrc, &ipsrc, &macdst, &ipdst);
    } while (0);

    MSG_DEBUG("End live capture decoder");
}

/*
 * Inject an ARP packet in the network traffic of the interface.
 */
void
intf_inject(int op, struct in_addr *ip)
{

    do {
        struct ether_addr *mac = NULL;
        char UNUSED(*smac) = NULL, UNUSED(*sip) = NULL;

        /* MAC broadcast addr string to MAC addr network byte order. */
        if ((mac = ether_aton(INTF_MACBROSTRADDR)) == NULL) {
            MSG_ERROR("%s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Autobuild the ARP header inside the libnet network handle. */
        if (libnet_autobuild_arp(
            (uint16_t)op,               /* ARP operation type. */
            (const uint8_t *)&cfg->mac, /* SHA to interface MAC addr. */
            (const uint8_t *)&cfg->ip,  /* SPA to interface IP addr. */
            (const uint8_t *)mac,       /* THA to mac. */
            (uint8_t *)ip,              /* TPA to ip. */
            cfg->lnet) < 0)
            break;

        /* Autobuild the Ethernet header inside the libnet network handle. */
        if (libnet_autobuild_ethernet(
            (const uint8_t *)mac,       /* Destination address to mac. */
            ETHERTYPE_ARP,              /* Upper ARP layer protocol type. */
            cfg->lnet) < 0)
            break;

        /* Send the ARP packet built inside the libnet network handle. */
        if (libnet_write(cfg->lnet) < 0)
            break;

        /* Clear the ARP packet built inside the libnet network handle. */
        libnet_clear_packet(cfg->lnet);

#ifndef NDEBUG
        /* THA network byte order to string. */
        smac = ether_ntoa(mac);

        /* TPA network byte order to string. */
        sip = inet_ntoa(*ip);
#endif  /* !NDEBUG */

        MSG_DEBUG("Sent %s packet to %s (%s)", INTF_ATOA(op), smac, sip);

        return;
    } while (0);

    MSG_ERROR("%s", libnet_geterror(cfg->lnet));
    exit(EXIT_FAILURE);
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
