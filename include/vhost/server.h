#pragma once

#include <vhost/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_event_ops;
struct vhd_event_ctx;
struct vhd_vdev;
struct vhd_bdev_io;

/**
 * Start vhost server
 *
 * Server will spawn one native thread to wait for incoming vhost handshakes.
 * This thread will only handle global vhost protocol communication.
 * Device I/O events are handled separately by plugging into request queues.
 *
 * Return 0 on success or negative error code.
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
 *
 * Return 0 on success or negative error code.
 */
int vhd_add_vhost_event(int fd, void* priv, const struct vhd_event_ops* ops, struct vhd_event_ctx* ctx);

/**
 * Delete event source from vhost server event loop
 */
void vhd_del_vhost_event(int fd);

/**
 * Request instance stored in request queue
 */
struct vhd_request
{
    /* Device that generated this request */
    struct vhd_vdev* vdev;

    /* TODO: this should be device type-specific */
    struct vhd_bdev_io* bio;
};

/**
 * Server request queue
 *
 * Request queues are created by client and attached to vhost device(s).
 * Each device will then send its events to its attched queue.
 * This way request queues serve as a unit of load balancing.
 */
struct vhd_request_queue;

/**
 * Create new request queue
 */
struct vhd_request_queue* vhd_create_request_queue(void);

/**
 * Destroy request queue.
 * Don't call this until there are devices attached to this queue.
 */
void vhd_release_request_queue(struct vhd_request_queue* rq);

/**
 * Attach event to request queue event loop
 */
int vhd_attach_event(struct vhd_request_queue* rq, int fd, struct vhd_event_ctx* ev);
void vhd_detach_event(struct vhd_request_queue* rq, int fd);

/**
 * Run queue in calling thread.
 * Will block until any of the devices enqueue requests.
 */
int vhd_run_queue(struct vhd_request_queue* rq);

/**
 * Unblock running request queue.
 * After calling this vhd_run_queue will eventually return and can the be reeintered.
 */
void vhd_stop_queue(struct vhd_request_queue* rq);

/**
 * Dequeue next request.
 */
bool vhd_dequeue_request(struct vhd_request_queue* rq, struct vhd_request* out_req);

/**
 * Enqueue block IO request
 */
int vhd_enqueue_block_request(struct vhd_request_queue* rq, struct vhd_vdev* vdev, struct vhd_bdev_io* bio);

#ifdef __cplusplus
}
#endif
