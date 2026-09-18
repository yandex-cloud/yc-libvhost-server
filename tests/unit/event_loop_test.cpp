#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>

#include <thread>

#include <CUnit/Basic.h>

#include "platform.h"
#include "event.h"

static void setup_timeout(int seconds, void(*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigaction(SIGALRM, &sa, 0);

    struct itimerval timer;
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_sec = seconds;
    setitimer(ITIMER_REAL, &timer, 0);
}

static void cancel_timeout()
{
    struct itimerval timer;
    memset(&timer, 0, sizeof(timer));
    setitimer(ITIMER_REAL, &timer, 0);
}

static void run_with_timeout(int seconds, void(*testfunc)(void))
{
    setup_timeout(seconds, [](int sig) {
        CU_ASSERT_FATAL(0);
    });

    testfunc();

    cancel_timeout();
}

static void bh_counter_bh(void *opaque)
{
    int *bh_count = (int *)opaque;
    (*bh_count)++;
}

static void bh_oneshot(void)
{
    run_with_timeout(30, []() {
        const int term_count = 1000;
        const static int bh_count_expected = 2500;
        int bh_count = 0;

        for (int i = 0; i < term_count; ++i) {
            vhd_event_loop *evloop =
                vhd_create_event_loop(VHD_EVENT_LOOP_DEFAULT_MAX_EVENTS);
            CU_ASSERT(evloop != NULL);

            std::thread runner([&]() {
                while (true) {
                    int res = vhd_run_event_loop(evloop, -1);
                    if (res != -EAGAIN) {
                        CU_ASSERT(res == 0);
                        break;
                    }
                }
            });

            for (int j = 0; j < bh_count_expected; j++) {
                vhd_bh_schedule_oneshot(evloop, bh_counter_bh, &bh_count);
            }

            vhd_terminate_event_loop(evloop);
            runner.join();
            vhd_free_event_loop(evloop);

            CU_ASSERT(bh_count == bh_count_expected * (i + 1));
        }
    });
}

int main(void)
{
    int res = 0;
    CU_pSuite suite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    suite = CU_add_suite("event_loop_test", NULL, NULL);
    if (NULL == suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_ADD_TEST(suite, bh_oneshot);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    res = CU_get_error() || CU_get_number_of_tests_failed();
    CU_cleanup_registry();

    return res;
}
