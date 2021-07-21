#include "vhost/blockdev.h"
#include "server_internal.h"
#include "vdev.h"
#include "logging.h"

#include "bio.h"
#include "virtio/virtio_blk.h"

struct vhd_bdev {
    /* Base vdev */
    struct vhd_vdev vdev;

    /* Client backend */
    struct vhd_bdev_info *bdev;

    /* VM-facing interface type */
    struct virtio_blk_dev vblk;

    LIST_ENTRY(vhd_bdev) blockdevs;
};

LIST_HEAD(, vhd_bdev) g_bdev_list = LIST_HEAD_INITIALIZER(g_bdev_list);

#define VHD_BLOCKDEV_FROM_VDEV(ptr) containerof(ptr, struct vhd_bdev, vdev)
#define VHD_VRING_FROM_VQ(ptr) containerof(ptr, struct vhd_vring, vq)

/*////////////////////////////////////////////////////////////////////////////*/

static uint64_t vblk_get_features(struct vhd_vdev *vdev)
{
    VHD_UNUSED(vdev);
    return VIRTIO_BLK_DEFAULT_FEATURES;
}

static int vblk_set_features(struct vhd_vdev *vdev, uint64_t features)
{
    VHD_UNUSED(vdev);
    VHD_UNUSED(features);
    return 0;
}

/* vhost_get_config assumes that config is less than VHOST_USER_CONFIG_SPACE_MAX */
VHD_STATIC_ASSERT(sizeof(struct virtio_blk_config) <= VHOST_USER_CONFIG_SPACE_MAX);

static size_t vblk_get_config(struct vhd_vdev *vdev, void *cfgbuf,
                              size_t bufsize, size_t offset)
{
    struct vhd_bdev *dev = VHD_BLOCKDEV_FROM_VDEV(vdev);

    if (offset >= sizeof(dev->vblk.config)) {
        return 0;
    }

    size_t data_size = MIN(bufsize, sizeof(dev->vblk.config) - offset);

    memcpy(cfgbuf, (char *)(&dev->vblk.config) + offset, data_size);

    return data_size;
}

static int vblk_dispatch(struct vhd_vdev *vdev, struct vhd_vring *vring,
                         struct vhd_request_queue *rq)
{
    VHD_UNUSED(rq);

    struct vhd_bdev *dev = VHD_BLOCKDEV_FROM_VDEV(vdev);
    return virtio_blk_dispatch_requests(&dev->vblk, &vring->vq);
}

static void vblk_free(struct vhd_vdev *vdev)
{
    struct vhd_bdev *bdev = VHD_BLOCKDEV_FROM_VDEV(vdev);

    LIST_REMOVE(bdev, blockdevs);
    vhd_free(bdev);
}

const struct vhd_vdev_type g_virtio_blk_vdev_type = {
    .desc               = "virtio-blk",
    .get_features       = vblk_get_features,
    .set_features       = vblk_set_features,
    .get_config         = vblk_get_config,
    .dispatch_requests  = vblk_dispatch,
    .free               = vblk_free,
};

static int vblk_handle_request(struct virtio_virtq *vq, struct vhd_bio *bio)
{
    bio->vring = VHD_VRING_FROM_VQ(vq);
    return vhd_enqueue_block_request(bio->vring->vdev->rq, bio);
}

struct vhd_vdev *vhd_register_blockdev(struct vhd_bdev_info *bdev,
                                       struct vhd_request_queue *rq, void *priv)
{
    int res = 0;

    if (bdev->total_blocks == 0) {
        return NULL;
    }

    /* Check block size is power-of-2 */
    if (bdev->block_size == 0 || (bdev->block_size & (bdev->block_size - 1))) {
        return NULL;
    }

    struct vhd_bdev *dev = vhd_zalloc(sizeof(*dev));

    res = virtio_blk_init_dev(&dev->vblk, bdev, vblk_handle_request);
    if (res != 0) {
        goto error_out;
    }

    res = vhd_vdev_init_server(&dev->vdev, bdev->socket_path, &g_virtio_blk_vdev_type,
                               bdev->num_queues, rq, priv, bdev->map_cb,
                               bdev->unmap_cb);
    if (res != 0) {
        goto error_out;
    }

    dev->bdev = bdev;

    LIST_INSERT_HEAD(&g_bdev_list, dev, blockdevs);
    return &dev->vdev;

error_out:
    vhd_free(dev);
    return NULL;
}

void vhd_unregister_blockdev(struct vhd_vdev *vdev,
                             void (*unregister_complete)(void *), void *arg)
{
    vhd_vdev_stop_server(vdev, unregister_complete, arg);
}
