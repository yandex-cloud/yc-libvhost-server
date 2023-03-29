#pragma once

#include <stdint.h>
#include <stddef.h>
#include "vhost/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_io;
struct vhd_request_queue;
struct vhd_vdev;

#define VHD_SECTOR_SHIFT    (9)
#define VHD_SECTOR_SIZE     (1ull << VHD_SECTOR_SHIFT)

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

    bool readonly;

    /* Gets called after mapping guest memory region */
    int (*map_cb)(void *addr, size_t len, void *priv);

    /* Gets called before unmapping guest memory region */
    int (*unmap_cb)(void *addr, size_t len, void *priv);
};

/**
 * Block io request type
 */
enum vhd_bdev_io_type {
    VHD_BDEV_READ,
    VHD_BDEV_WRITE
};

/**
 * In-flight blockdev io request
 */
struct vhd_bdev_io {
    enum vhd_bdev_io_type type;

    uint64_t first_sector;
    uint64_t total_sectors;
    struct vhd_sglist sglist;
};

struct vhd_bdev_io *vhd_get_bdev_io(struct vhd_io *io);

/**
 * Register a vhost block device.
 *
 * After registering a device, it will be accessible to clients through a vhost
 * socket.
 * All requests are submitted to attacher request queues for caller to process.
 *
 * @bdev        Caller block device info. The structure is used only for
 *              initialization and may be freed by caller after
 *              vhd_register_blockdev() returns.
 * @rqs         An array of request queues to use for dispatching device I/O
 *              requests.
 * @num_rqs     Number of request queues in the @rqs array.
 * @priv        Caller private data to associate with resulting vdev.
 */
struct vhd_vdev *vhd_register_blockdev(const struct vhd_bdev_info *bdev,
                                       struct vhd_request_queue **rqs,
                                       int num_rqs, void *priv);

/**
 * Unregister a vhost block device.
 */
void vhd_unregister_blockdev(struct vhd_vdev *vdev,
                             void (*unregister_complete)(void *), void *arg);

#ifdef __cplusplus
}
#endif
