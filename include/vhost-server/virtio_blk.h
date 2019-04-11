#pragma once

#include "virtio/virtio_blk10.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VIRTIO_BLK_DEFAULT_FEATURES ((uint64_t)( \
    (1UL << VIRTIO_F_RING_INDIRECT_DESC) | \
    (1UL << VIRTIO_F_VERSION_1) | \
    (1UL << VIRTIO_BLK_F_SIZE_MAX) | \
    (1UL << VIRTIO_BLK_F_SEG_MAX) | \
    (1UL << VIRTIO_BLK_F_BLK_SIZE) | \
    (1UL << VIRTIO_BLK_F_TOPOLOGY) | \
    (1UL << VIRTIO_BLK_F_MQ)))

struct vhd_bdev;
struct virtio_mm_ctx;
struct virtio_virtq;

struct virtio_blk_dev
{
    struct vhd_bdev* bdev;

    /* blk config data generated on init from bdev */
    struct virtio_blk_config config;

    /* 512 << block_shift == bdev->block_size */
    uint8_t block_shift;
};

int virtio_blk_init_dev(struct virtio_blk_dev* dev, struct vhd_bdev* bdev);
int virtio_blk_handle_requests(struct virtio_blk_dev* dev, struct virtio_virtq* vq, struct virtio_mm_ctx* mm);

#ifdef __cplusplus
}
#endif
