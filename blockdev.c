#include "vhost-server/platform.h"
#include "vhost-server/blockdev.h"
#include "vhost-server/virtio_blk.h"

#include "virtio/virtio_blk10.h"

#define VBLK_DEFAULT_FEATURES ((uint64_t)( \
    (1UL << VIRTIO_F_RING_INDIRECT_DESC) | \
    (1UL << VIRTIO_F_VERSION_1) | \
    (1UL << VIRTIO_BLK_F_SIZE_MAX) | \
    (1UL << VIRTIO_BLK_F_SEG_MAX) | \
    (1UL << VIRTIO_BLK_F_BLK_SIZE) | \
    (1UL << VIRTIO_BLK_F_TOPOLOGY) | \
    (1UL << VIRTIO_BLK_F_MQ)))

static inline uint64_t get_block_size(struct vhd_blockdev* bdev)
{
    return 1ull << bdev->block_size_log2;
}

static uint64_t blk_get_features(struct vhd_vdev* vdev)
{
    return VBLK_DEFAULT_FEATURES;
}

static int blk_set_features(struct vhd_vdev* vdev, uint64_t features)
{
    if (features & ~VBLK_DEFAULT_FEATURES) {
        return EINVAL;
    }

    vdev->negotiated_device_features = features;
    return 0;
}

static size_t blk_get_config(struct vhd_vdev* vdev, void* cfgbuf, size_t bufsize)
{
    VHD_ASSERT(bufsize == sizeof(struct virtio_blk_config));

    struct vhd_blockdev* bdev = VHD_BLOCKDEV_FROM_VDEV(vdev);
    struct virtio_blk_config* blk_config = (struct virtio_blk_config*)cfgbuf;

    blk_config->capacity = bdev->total_blocks;
    blk_config->size_max = bdev->total_blocks;
    blk_config->blk_size = get_block_size(bdev);
    blk_config->numqueues = vdev->max_queues;

    return sizeof(*blk_config);
}

const struct vhd_vdev_type vhd_block_vdev_type = 
{
    .desc = "virtio-blk",
    .get_features = blk_get_features,
    .set_features = blk_set_features,
    .get_config = blk_get_config,
};

int vhd_create_blockdev(const char* id, uint32_t block_size, uint64_t total_blocks, struct vhd_blockdev* bdev)
{
    int res = 0;

    VHD_VERIFY(id);
    VHD_VERIFY(bdev);

    if (total_blocks == 0) {
        return EINVAL;
    }

    /* Check block size is power-of-2 */
    if (block_size == 0 || (block_size & (block_size - 1))) {
        return EINVAL;
    }

    res = vhd_vdev_init_server(&bdev->vdev, id,  &vhd_block_vdev_type, 1);
    if (res != 0) {
        return res;
    }

    bdev->block_size_log2 = __builtin_ctz(block_size);
    bdev->total_blocks = total_blocks;

    return 0;
}
