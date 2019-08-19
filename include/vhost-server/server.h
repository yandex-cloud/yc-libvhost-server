#pragma once

#include "vhost-server/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_event_ops;
struct vhd_event_ctx;

/**
 * Start vhost server
 *
 * Server will spawn one native thread to wait for incoming vhost handshakes.
 * This thread will only handle global vhost protocol communication.
 * Device I/O events are handled separately by plugging into request queues.
 */
int vhd_start_vhost_server(void);

/**
 * Stop vhost server
 *
 * Stop vhost event thread which means no new vhost connections are possible
 */
void vhd_stop_vhost_server(void);

/**
 * Add event source to vhost server event loop
 */
int vhd_add_vhost_event(int fd, void* priv, const struct vhd_event_ops* ops, struct vhd_event_ctx* ctx);

/**
 * Delete event source from vhost server event loop
 */
void vhd_del_vhost_event(int fd);

#ifdef __cplusplus
}
#endif
