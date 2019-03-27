#pragma once

#include "vhost-server/vdev.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_bdev_queue;

struct vhd_buffer
{
    void* base;
    size_t len;
};

struct vhd_sglist
{
    uint32_t nbuffers;
    struct vhd_buffer* buffers;
};

/**
 * Device guest-facing interface type
 */
enum vhd_bdev_interface_type
{
    VHD_BDEV_IFACE_VIRTIO_BLK = 0,
    VHD_BDEV_IFACE_DEFAULT = VHD_BDEV_IFACE_VIRTIO_BLK,
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
    struct vhd_bdev* bdev;
    struct vhd_bdev_queue* queue;

    enum vhd_bdev_io_type type;

    uint64_t first_block;
    uint64_t total_blocks;
    struct vhd_sglist sglist;

    void (*completion_handler) (struct vhd_bdev_io* bio, enum vhd_bdev_io_result res);
};

/**
 * Client-supplied block device backend definition
 */
struct vhd_bdev
{
    /* Client private data */
    void* priv;

    /* Blockdev id, will be used to create listen sockets */
    const char* id;

    /* Block size in bytes */
    uint32_t block_size;

    /* Device size in blocks */
    uint64_t total_blocks;

    /* Total number of backend queues this device supports */
    uint32_t num_queues;

    /* Start servicing requests on specified queue id (qid is [0; num_queue)) */
    struct vhd_bdev_queue* (*plug_queue) (uint32_t qid);

    /* Submit requests to device queue */
    int (*submit_requests) (struct vhd_bdev_queue* queue, struct vhd_bdev_io* iov, size_t iovsize);
};

/** Global block vdev type description */
extern const struct vhd_vdev_type vhd_block_vdev_type;

int vhd_create_blockdev(struct vhd_bdev* bdev, enum vhd_bdev_interface_type iface);

#ifdef __cplusplus
}
#endif
