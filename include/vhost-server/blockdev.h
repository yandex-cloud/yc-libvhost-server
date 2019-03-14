#pragma once

#include "vhost-server/vdev.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Global block vdev type description */
extern const struct vhd_vdev_type vhd_block_vdev_type;

struct vhd_blockdev
{
    struct vhd_vdev vdev;

    uint8_t block_size_log2;
    uint64_t total_blocks;
};

#define VHD_BLOCKDEV_FROM_VDEV(pvdev) containerof((pvdev), struct vhd_blockdev, vdev)

int vhd_create_blockdev(const char* id, uint32_t block_size, uint64_t total_blocks, struct vhd_blockdev* bdev);

#ifdef __cplusplus
}
#endif
