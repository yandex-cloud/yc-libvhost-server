#pragma once

#include "vhost-server/vdev.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_request_queue;

struct vhd_sglist
{
    uint32_t nbuffers;
    struct vhd_buffer* buffers;
};

/**
 * Block io request type
 */
enum vhd_bdev_io_type
{
    VHD_BDEV_READ,
    VHD_BDEV_WRITE
};

/**
 * Block io request result
 */
enum vhd_bdev_io_result
{
    VHD_BDEV_SUCCESS = 0,
    VHD_BDEV_IOERR,
};

/**
 * In-flight blockdev io request
 */
struct vhd_bdev_io
{
    enum vhd_bdev_io_type type;

    uint64_t first_block;
    uint64_t total_blocks;
    struct vhd_sglist sglist;

    void (*completion_handler) (struct vhd_bdev_io* bio, enum vhd_bdev_io_result res);
};

static inline void vhd_complete_bio(struct vhd_bdev_io* bio, enum vhd_bdev_io_result res)
{
    VHD_VERIFY(bio && bio->completion_handler);
    bio->completion_handler(bio, res);
}

/**
 * Client-supplied block device backend definition
 */
struct vhd_bdev_info
{
    /* Blockdev id, will be used to create listen sockets */
    const char* id;

    /* Block size in bytes */
    uint32_t block_size;

    /* Total number of backend queues this device supports */
    uint32_t num_queues;

    /* Device size in blocks */
    uint64_t total_blocks;
};

/**
 * Register vhost block device.
 *
 * After registering device will be accessible through vhost socket to client.
 * All requests are submitted to attacher request queue for caller to process.
 *
 * @bdev        Caller block device info.
 * @iface       Type of virtualized interface (i.e virtio-blk, ...).
 * @rq          Request queue to use for dispatch device I/O requests.
 */
int vhd_register_blockdev(struct vhd_bdev_info* bdev, struct vhd_request_queue* rq);

#ifdef __cplusplus
}
#endif
