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
 * $ArpON: rt.c,v 3.0-ng 01/29/2016 03:01:08 spikey Exp $
 */

#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "msg.h"
#include "rt.h"

/*
 * Nanoseconds to seconds.
 */
#define RT_NANOTOSECS       1000000000.0

/*
 * Microseconds to seconds.
 */
#define RT_MICROTOSECS      1000000.0

/*
 * Retrieve the normalized current local time with max high precision.
 */
double
rt_getlocaltime(void)
{
#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0)
    struct timespec ts;
    double time;
#if defined(CLOCK_MONOTONIC_RAW)
    /*
     * Monotonic time measure with access to a raw hardware-based time.
     *
     * This clock is not affected by discontinuous jumps in the system time
     * (e.g., if the system administrator manually changes the clock) and it
     * is not affected by the incremental adjustments performed by adjtime
     * and NTP.
     */
    const clockid_t id = CLOCK_MONOTONIC_RAW;

    MSG_DEBUG("Retrieve monotonic_raw time measure..");
#elif defined(CLOCK_MONOTONIC)
    /*
     * Monotonic time measure.
     *
     * This clock is not affected by discontinuous jumps in the system time
     * (e.g., if the system administrator manually changes the clock), but
     * is affected by the incremental adjustments performed by adjtime
     * and NTP.
     */
    const clockid_t id = CLOCK_MONOTONIC;

    MSG_DEBUG("Retrieve monotonic time measure..");
#else   /* !CLOCK_* */
    /*
     * System-wide clock that measures the real time.
     *
     * This clock is affected by discontinuous jumps in the system time
     * (e.g., if the system administrator manually changes the clock), and
     * by the incremental adjustments performed by adjtime and NTP.
     */
    const clockid_t id = CLOCK_REALTIME;

    MSG_DEBUG("Retrieve realtime measure with clock_gettime()..");
#endif  /* CLOCK_* */

    /*
     * Retrieve the current local time with
     * the precision of the specified id.
     */
    if (clock_gettime(id, &ts) < 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Normalize the current local time to seconds. */
    time = (double)ts.tv_sec + (double)ts.tv_nsec / RT_NANOTOSECS;
#else   /* !_POSIX_TIMERS */
    struct timeval tm;
    double time;

    /*
     * System-wide clock that measures the real time.
     *
     * This clock is affected by discontinuous jumps in the system time
     * (e.g., if the system administrator manually changes the clock), and
     * by the incremental adjustments performed by adjtime and NTP.
     */
    MSG_DEBUG("Retrieve realtime measure with gettimeofday()..");

    /* Retrieve the current local time with the realtime precision. */
    if (gettimeofday(&tm, NULL) < 0) {
        MSG_ERROR("%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Normalize the current local time to seconds. */
    time = (double)tm.tv_sec + (double)tm.tv_usec / RT_MICROTOSECS;
#endif  /* _POSIX_TIMERS */

    MSG_DEBUG("time = %lf", time);

    return time;
}

/*
 * Measure the elapsed time between two retrieved normalized local times.
 */
double
rt_difftime(double timeend, double timestart)
{
    double timeelapsed;

    MSG_DEBUG("timeend = %lf", timeend);
    MSG_DEBUG("timestart = %lf", timestart);

    /* Measure the elapsed time between two retrieved normalized local times. */
    timeelapsed = timeend - timestart;

    MSG_DEBUG("timeelapsed = %lf", timeelapsed);

    return timeelapsed;
}

/*
 * EOF
 *
 * vim:ts=4:expandtab
 */
