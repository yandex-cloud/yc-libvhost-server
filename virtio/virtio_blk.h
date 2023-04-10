#pragma once

#include "virtio_blk_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VIRTIO_BLK_DEFAULT_FEATURES ((uint64_t)( \
    (1UL << VIRTIO_F_RING_INDIRECT_DESC) | \
    (1UL << VIRTIO_F_RING_EVENT_IDX) | \
    (1UL << VIRTIO_F_VERSION_1) | \
    (1UL << VIRTIO_BLK_F_SEG_MAX) | \
    (1UL << VIRTIO_BLK_F_GEOMETRY) | \
    (1UL << VIRTIO_BLK_F_BLK_SIZE) | \
    (1UL << VIRTIO_BLK_F_TOPOLOGY) | \
    (1UL << VIRTIO_BLK_F_MQ)))

    /*
     * TODO: can implement size_max and seg_max to better control request limits
     * (1UL << VIRTIO_BLK_F_SIZE_MAX) | \
     */

struct vhd_bdev_info;
struct vhd_io;

struct virtio_virtq;
struct virtio_blk_dev;

/**
 * Virtio block I/O dispatch function,
 * can be overriden for testing.
 */
__attribute__((weak))
int virtio_blk_handle_request(struct virtio_virtq *vq,
                              struct vhd_io *io);

/**
 * Virtio block device context
 */
struct virtio_blk_dev {
    struct vhd_bdev_info *bdev;

    /* blk config data generated on init from bdev */
    struct virtio_blk_config config;
};

/**
 * Init virtio blk device context from bdev info
 */
void virtio_blk_init_dev(
    struct virtio_blk_dev *dev,
    struct vhd_bdev_info *bdev);

/**
 * Dispatch requests from device virtq
 */
int virtio_blk_dispatch_requests(struct virtio_blk_dev *dev,
                                 struct virtio_virtq *vq);

/**
 * Get the virtio config
 */
size_t virtio_blk_get_config(struct virtio_blk_dev *dev, void *cfgbuf,
                             size_t bufsize, size_t offset);

/**
 * Get readonly status
 */
bool virtio_blk_is_readonly(struct virtio_blk_dev *dev);

#ifdef __cplusplus
}
#endif
