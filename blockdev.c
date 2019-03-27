#include "vhost-server/platform.h"
#include "vhost-server/blockdev.h"
#include "vhost-server/intrusive_list.h"
#include "vhost-server/virtio_blk.h"

#include "virtio/virtio_blk10.h"

struct vhd_vhost_bdev
{
    /* Base vdev */
    struct vhd_vdev vdev;

    /* Client backend */
    struct vhd_bdev* bdev;

    /* VM-facing interface type and contexts */
    enum vhd_bdev_interface_type iface_type;
    union {
        struct virtio_blk_dev vblk;
    };

    LIST_ENTRY(vhd_vhost_bdev) blockdevs;
};

LIST_HEAD(, vhd_vhost_bdev) g_bdev_list = LIST_HEAD_INITIALIZER(g_bdev_list);

#define VHD_BLOCKDEV_FROM_VDEV(ptr) containerof(ptr, struct vhd_vhost_bdev, vdev)

#define VBLK_DEFAULT_FEATURES ((uint64_t)( \
    (1UL << VIRTIO_F_RING_INDIRECT_DESC) | \
    (1UL << VIRTIO_F_VERSION_1) | \
    (1UL << VIRTIO_BLK_F_SIZE_MAX) | \
    (1UL << VIRTIO_BLK_F_SEG_MAX) | \
    (1UL << VIRTIO_BLK_F_BLK_SIZE) | \
    (1UL << VIRTIO_BLK_F_TOPOLOGY) | \
    (1UL << VIRTIO_BLK_F_MQ)))

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

    struct vhd_vhost_bdev* dev = VHD_BLOCKDEV_FROM_VDEV(vdev);
    struct virtio_blk_config* blk_config = (struct virtio_blk_config*)cfgbuf;

    blk_config->capacity = dev->bdev->total_blocks;
    blk_config->size_max = dev->bdev->total_blocks;
    blk_config->blk_size = dev->bdev->block_size;
    blk_config->numqueues = dev->bdev->num_queues;

    return sizeof(*blk_config);
}

const struct vhd_vdev_type vhd_block_vdev_type = 
{
    .desc = "virtio-blk",
    .get_features = blk_get_features,
    .set_features = blk_set_features,
    .get_config = blk_get_config,
};

////////////////////////////////////////////////////////////////////////////////

int vhd_create_blockdev(struct vhd_bdev* bdev, enum vhd_bdev_interface_type iface)
{
    int res = 0;

    VHD_VERIFY(bdev);

    if (bdev->total_blocks == 0) {
        return -EINVAL;
    }

    /* Check block size is power-of-2 */
    if (bdev->block_size == 0 || (bdev->block_size & (bdev->block_size - 1))) {
        return EINVAL;
    }

    struct vhd_vhost_bdev* dev = vhd_alloc(sizeof(*dev));
    res = vhd_vdev_init_server(&dev->vdev, bdev->id, &vhd_block_vdev_type, bdev->num_queues);
    if (res != 0) {
        goto error_out;
    }

    dev->bdev = bdev;
    return 0;

error_out:
    vhd_free(dev);
    return res;
}
