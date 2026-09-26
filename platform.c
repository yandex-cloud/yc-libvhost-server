#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "platform.h"

int init_platform_page_size(void)
{
    if (!platform_page_size) {
        long result = sysconf(_SC_PAGESIZE);
        if (result < 0) {
            return errno;
        }
        platform_page_size = result;
    }

    return 0;
}

/*
 * Tick counter frequency, set once by init_ticks_freq().
 */
static uint64_t ticks_per_sec;

int init_ticks_freq(void)
{
    if (ticks_per_sec) {
        return 0;
    }

#if defined(__aarch64__)
    {
        uint64_t freq;
        __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(freq));
        ticks_per_sec = freq;
    }
#elif defined(__x86_64__)
    {
        /*
         * Calibrate TSC against CLOCK_MONOTONIC.  A 10 ms window gives
         * sub-percent accuracy which is plenty for coalescing periods.
         */
        struct timespec ts1, ts2;
        uint64_t t1, t2;
        uint64_t ns;

        clock_gettime(CLOCK_MONOTONIC, &ts1);
        t1 = vhd_ticks();

        /* Busy-spin for ~10 ms */
        do {
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            ns = (uint64_t)(ts2.tv_sec - ts1.tv_sec) * 1000000000ULL
                 + (uint64_t)(ts2.tv_nsec - ts1.tv_nsec);
        } while (ns < 10000000ULL);

        t2 = vhd_ticks();
        ticks_per_sec = (t2 - t1) * 1000000000ULL / ns;
    }
#else
#   error Unsupported architecture for init_ticks_freq
#endif

    return ticks_per_sec ? 0 : -ENODEV;
}

uint64_t vhd_ns_to_ticks(uint64_t ns)
{
    VHD_ASSERT(ticks_per_sec);
    return ns * ticks_per_sec / 1000000000ULL;
}

