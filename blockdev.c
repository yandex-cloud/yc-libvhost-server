#include "vhost-server/platform.h"
#include "vhost-server/blockdev.h"
#include "vhost-server/intrusive_list.h"
#include "vhost-server/virtio_blk.h"
#include "vhost-server/server.h"

struct vhd_vhost_bdev
{
    /* Base vdev */
    struct vhd_vdev vdev;

    /* Client backend */
    struct vhd_bdev_info* bdev;

    /* VM-facing interface type */
    struct virtio_blk_dev vblk;

    LIST_ENTRY(vhd_vhost_bdev) blockdevs;
};

LIST_HEAD(, vhd_vhost_bdev) g_bdev_list = LIST_HEAD_INITIALIZER(g_bdev_list);

#define VHD_BLOCKDEV_FROM_VDEV(ptr) containerof(ptr, struct vhd_vhost_bdev, vdev)
#define VHD_BLOCKDEV_FROM_VBLK(ptr) containerof(ptr, struct vhd_vhost_bdev, vblk)

////////////////////////////////////////////////////////////////////////////////

static uint64_t vblk_get_features(struct vhd_vdev* vdev)
{
    return VIRTIO_BLK_DEFAULT_FEATURES;
}

static int vblk_set_features(struct vhd_vdev* vdev, uint64_t features)
{
    if (features & ~VIRTIO_BLK_DEFAULT_FEATURES) {
        return -EINVAL;
    }

    vdev->negotiated_device_features = features;
    return 0;
}

static size_t vblk_get_config(struct vhd_vdev* vdev, void* cfgbuf, size_t bufsize)
{
    struct vhd_vhost_bdev* dev = VHD_BLOCKDEV_FROM_VDEV(vdev);

    VHD_ASSERT(bufsize >= sizeof(struct virtio_blk_config));
    struct virtio_blk_config* blk_config = (struct virtio_blk_config*)cfgbuf;

    *blk_config = dev->vblk.config;
    return sizeof(*blk_config);
}

static int vblk_dispatch(struct vhd_vdev* vdev, struct vhd_vring* vring, struct vhd_request_queue* rq)
{
    struct vhd_vhost_bdev* dev = VHD_BLOCKDEV_FROM_VDEV(vdev);
    return virtio_blk_dispatch_requests(&dev->vblk, &vring->vq, vhd_vdev_mm_ctx(vdev));
}

const struct vhd_vdev_type g_virtio_blk_vdev_type = {
    .desc               = "virtio-blk",
    .get_features       = vblk_get_features,
    .set_features       = vblk_set_features,
    .get_config         = vblk_get_config,
    .dispatch_requests  = vblk_dispatch,
};

static int vblk_handle_request(struct virtio_blk_dev* vblk, struct vhd_bdev_io* bio)
{
    struct vhd_vhost_bdev* dev = VHD_BLOCKDEV_FROM_VBLK(vblk);
    return vhd_enqueue_block_request(dev->vdev.rq, dev->bdev, bio);
}

////////////////////////////////////////////////////////////////////////////////

int vhd_register_blockdev(struct vhd_bdev_info* bdev, struct vhd_request_queue* rq)
{
    int res = 0;

    VHD_VERIFY(bdev);
    VHD_VERIFY(rq);

    if (bdev->total_blocks == 0) {
        return -EINVAL;
    }

    /* Check block size is power-of-2 */
    if (bdev->block_size == 0 || (bdev->block_size & (bdev->block_size - 1))) {
        return -EINVAL;
    }

    struct vhd_vhost_bdev* dev = vhd_alloc(sizeof(*dev));

    res = virtio_blk_init_dev(&dev->vblk, bdev, vblk_handle_request);
    if (res != 0) {
        goto error_out;
    }

    res = vhd_vdev_init_server(&dev->vdev, bdev->id, &g_virtio_blk_vdev_type, bdev->num_queues, rq);
    if (res != 0) {
        goto error_out;
    }

    dev->bdev = bdev;
    return 0;

error_out:
    vhd_free(dev);
    return res;
}
