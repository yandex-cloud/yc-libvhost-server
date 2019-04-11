#pragma once

#include "vhost-server/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Caller-provided event handler ops
 */
struct vhd_event_ops
{
    /** Event source is closing */
    int (*close)(void* ctx);

    /** Data is available for reading */
    int (*read)(void* ctx);
};

/**
 * Caller-provided event context
 */
struct vhd_event_ctx
{
    void* priv;
    const struct vhd_event_ops* ops;
};

/**
 * Add event to event loop
 * @fd      event fd
 * @ctx     event context description
 */
int vhd_add_event(int fd, struct vhd_event_ctx* ctx);

static inline int vhd_make_event(
    int fd,
    void* priv,
    const struct vhd_event_ops* ops,
    struct vhd_event_ctx* ctx)
{
    VHD_VERIFY(ctx);
    ctx->priv = priv;
    ctx->ops = ops;
    return vhd_add_event(fd, ctx);
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
int vhd_del_event(int fd);

/**
 * Init global default event loop
 */
int vhd_init_event_loop(void);

/**
 * Run a blocking iteration of default event loop in calling thread.
 */
int vhd_run_event_loop(void);

#ifdef __cplusplus
}
#endif
