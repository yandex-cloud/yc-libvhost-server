#pragma once

#include <stdint.h>

#include "vhost/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_request_queue;
struct vhd_vdev;

/**
 * Block io request type
 */
enum vhd_bdev_io_type {
    VHD_BDEV_READ,
    VHD_BDEV_WRITE
};

/**
 * Block io request result
 */
enum vhd_bdev_io_result {
    VHD_BDEV_SUCCESS = 0,
    VHD_BDEV_IOERR,
};

#define VHD_SECTOR_SHIFT    (9)
#define VHD_SECTOR_SIZE     (1ull << VHD_SECTOR_SHIFT)

/**
 * In-flight blockdev io request
 */
struct vhd_bdev_io {
    enum vhd_bdev_io_type type;

    uint64_t first_sector;
    uint64_t total_sectors;
    struct vhd_sglist sglist;
};

/**
 * Client-supplied block device backend definition
 */
struct vhd_bdev_info {
    /* Blockdev serial */
    const char *serial;

    /* Path to create listen sockets */
    const char *socket_path;

    /* Block size in bytes */
    uint32_t block_size;

    /* Total number of backend queues this device supports */
    uint32_t num_queues;

    /* Device size in blocks */
    uint64_t total_blocks;

    /* Gets called after mapping guest memory region */
    int (*map_cb)(void *addr, size_t len, void *priv);

    /* Gets called before unmapping guest memory region */
    int (*unmap_cb)(void *addr, size_t len, void *priv);
};

/**
 * Register vhost block device.
 *
 * After registering device will be accessible through vhost socket to client.
 * All requests are submitted to attacher request queue for caller to process.
 *
 * @bdev        Caller block device info.
 * @rq          Request queue to use for dispatch device I/O requests.
 * @priv        Caller private data to associate with resulting vdev.
 */
struct vhd_vdev *vhd_register_blockdev(struct vhd_bdev_info *bdev,
                                       struct vhd_request_queue *rq,
                                       void *priv);

/**
 * Unregister vhost block device.
 */
void vhd_unregister_blockdev(struct vhd_vdev *vdev,
                             void (*unregister_complete)(void *), void *arg);

/**
 * Get statistics for device's queue
 */
int vhd_vdev_get_queue_stat(struct vhd_vdev *vdev, uint32_t queue_num,
                            struct vhd_vq_metrics *metrics);

#ifdef __cplusplus
}
#endif
