#pragma once

#include "vhost/server.h"

struct vhd_event_ops;
struct vhd_event_ctx;

/**
 * Add event source to vhost server event loop
 *
 * Return 0 on success or negative error code.
 */
int vhd_add_vhost_event(int fd, void *priv, const struct vhd_event_ops *ops,
                        struct vhd_event_ctx *ctx);

/**
 * Delete event source from vhost server event loop
 */
void vhd_del_vhost_event(int fd);

/**
 * Attach event to request queue event loop
 */
int vhd_attach_event(struct vhd_request_queue *rq, int fd,
                     struct vhd_event_ctx *ev);
void vhd_detach_event(struct vhd_request_queue *rq, int fd);

struct vhd_vdev;
struct vhd_bio;

/**
 * Enqueue block IO request
 */
int vhd_enqueue_block_request(struct vhd_request_queue *rq,
                              struct vhd_bio *bio);

/**
 * Run callback in request queue
 */
void vhd_run_in_rq(struct vhd_request_queue *rq, void (*cb)(void *),
                   void *opaque);

/*
 * Run callback in vhost control event loop
 */
void vhd_run_in_ctl(void (*cb)(void *), void *opaque);

/*
 * Submit a work item onto vhost control event loop and wait till it's
 * finished.
 */
struct vhd_work;
int vhd_submit_ctl_work_and_wait(void (*func)(struct vhd_work *, void *),
                                 void *opaque);
