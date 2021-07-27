/**
 * Common types' definitions
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_buffer {
    void *base;
    size_t len;

    /* Buffer is write-only if true and read-only if false */
    bool write_only;
};

struct vhd_sglist {
    uint32_t nbuffers;
    struct vhd_buffer *buffers;
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
 *
 * TODO: virtio-fs uses this struct too, that's why we need it in common types
 */
struct vhd_bdev_io {
    enum vhd_bdev_io_type type;

    uint64_t first_sector;
    uint64_t total_sectors;
    struct vhd_sglist sglist;
};

/**
 * virtqueue usage statistics
 */
struct vhd_vq_metrics {
    /* total amount of requests processed */
    uint64_t request_total;

    /* number of times vring was processed */
    uint64_t dispatch_total;

    /* number of times vring was empty on processing */
    uint64_t dispatch_empty;

    /* number of requests was dispatched from vring last time*/
    uint16_t queue_len_last;

    /* max queue len was processed during 60s period */
    uint16_t queue_len_max_60s;
};

#ifdef __cplusplus
}
#endif
