#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VHD_EVENT_LOOP_DEFAULT_MAX_EVENTS 32

/**
 * Event loop instance
 *
 * Each event loop will run in a thread which calls vhd_run_event_loop.
 * Events detected in given event loop iteration will also be handled in this
 * thread.
 *
 * Event loop management operations (add/remove events) are thread-safe,
 * although changes to list of events may not be visible until next
 * vhd_run_event_loop.
 */
struct vhd_event_loop;

/**
 * Create new event loop.
 * @max_events      How many events we can handle in one iteration.
 *                  Events are reported in FIFO order to avoid starvation.
 */
struct vhd_event_loop *vhd_create_event_loop(size_t max_events);

/**
 * Free event loop.
 *
 * May be called when event loop is running,
 * in which case it will be freed when running iteration ends.
 */
void vhd_free_event_loop(struct vhd_event_loop *evloop);

/**
 * Run event loop with timeout in milliseconds
 * @timeout     0 to return immediately, -1 to block indefinitely, milliseconds
 *              value otherwise.
 *
 * @return      Number of events handled in this run or 0 if we have been
 *              interrupted or timed out.
 *              Negative code on error.
 */
int vhd_run_event_loop(struct vhd_event_loop *evloop, int timeout_ms);

/**
 * Kick running event loop out of waiting before timeout expires.
 * Meant to be called in a thread parallel to vhd_run_event_loop.
 */
void vhd_interrupt_event_loop(struct vhd_event_loop *evloop);

/**
 * Abort event loop running in another thread.
 *
 * After calling this function vhd_run_event_loop should (eventually) return and
 * will always immediately return 0 on subsequent run attempts (but it is still
 * safe to attempt to run).
 *
 * vhd_event_loop_terminated will also start to return true.
 * Assumed caller pattern is to poll termination in one thread and terminate
 * from another, i.e.:
 *
 * Thread 1:
 * --------
 * while (!vhd_event_loop_terminated(evloop)) {
 *     vhd_event_loop_run(evloop);
 * }
 *
 * vhd_event_loop_free(evloop);
 *
 * Thread 2:
 * --------
 * vhd_terminate_event_loop(evloop);
 */
void vhd_terminate_event_loop(struct vhd_event_loop *evloop);

/**
 * Tell if vhd_terminate_event_loop has been called
 */
bool vhd_event_loop_terminated(struct vhd_event_loop *evloop);

/**
 * Caller-provided event handler ops
 */
struct vhd_event_ops {
    /** Data is available for reading */
    int (*read)(void *ctx);
};

/**
 * Caller-provided event context
 */
struct vhd_event_ctx {
    void *priv;
    const struct vhd_event_ops *ops;
};

/**
 * Add event to event loop
 * @fd      event fd
 * @ctx     event context description
 */
int vhd_add_event(struct vhd_event_loop *evloop, int fd,
                  struct vhd_event_ctx *ctx);

static inline int vhd_make_event(
    struct vhd_event_loop *evloop,
    int fd,
    void *priv,
    const struct vhd_event_ops *ops,
    struct vhd_event_ctx *ctx)
{
    ctx->priv = priv;
    ctx->ops = ops;
    return vhd_add_event(evloop, fd, ctx);
}

/**
 * Clear eventfd after handling it
 */
void vhd_clear_eventfd(int fd);

/**
 * Trigger eventfd
 */
void vhd_set_eventfd(int fd);

/**
 * Remove event from event loop
 */
int vhd_del_event(struct vhd_event_loop *evloop, int fd);

struct vhd_bh;
typedef void vhd_bh_cb(void *opaque);

struct vhd_bh *vhd_bh_new(struct vhd_event_loop *ctx,
                          vhd_bh_cb *cb, void *opaque);
void vhd_bh_schedule_oneshot(struct vhd_event_loop *ctx,
                             vhd_bh_cb *cb, void *opaque);
void vhd_bh_schedule(struct vhd_bh *bh);
void vhd_bh_cancel(struct vhd_bh *bh);
void vhd_bh_delete(struct vhd_bh *bh);

#ifdef __cplusplus
}
#endif
