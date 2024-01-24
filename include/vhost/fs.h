#pragma once

#include "vhost/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_vdev;
struct vhd_request_queue;

/**
 * Client-supplied file system definition.
 */
struct vhd_fsdev_info {
    /* Path to create listen sockets */
    const char *socket_path;

    /* Device tag (file system name visible to the guest) */
    const char *tag;

    /* Total number of backend queues this device supports */
    uint32_t num_queues;
};

/**
 * Register vhost file system.
 *
 * After registering device will be accessible through vhost socket to client.
 * All requests are submitted to attacher request queue for caller to process.
 *
 * @fsdev       Caller file system device info.
 * @rq          Request queue to use for dispatch device I/O requests.
 * @priv        Caller private data to associate with resulting vdev.
 */
struct vhd_vdev *vhd_register_fs(struct vhd_fsdev_info *fsdev,
                                 struct vhd_request_queue *rq,
                                 void *priv);

/**
 * Unregister vhost file system.
 */
void vhd_unregister_fs(struct vhd_vdev *vdev,
                       void (*unregister_complete)(void *),
                       void *arg);

#ifdef __cplusplus
}
#endif
