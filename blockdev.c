#include "vhost/blockdev.h"
#include "server_internal.h"
#include "vdev.h"
#include "logging.h"

#include "virtio/virtio_blk.h"

struct vhd_bdev
{
    /* Base vdev */
    struct vhd_vdev vdev;

    /* Client backend */
    struct vhd_bdev_info* bdev;

    /* VM-facing interface type */
    struct virtio_blk_dev vblk;

    LIST_ENTRY(vhd_bdev) blockdevs;
};

LIST_HEAD(, vhd_bdev) g_bdev_list = LIST_HEAD_INITIALIZER(g_bdev_list);

#define VHD_BLOCKDEV_FROM_VDEV(ptr) containerof(ptr, struct vhd_bdev, vdev)
#define VHD_BLOCKDEV_FROM_VBLK(ptr) containerof(ptr, struct vhd_bdev, vblk)

////////////////////////////////////////////////////////////////////////////////

static uint64_t vblk_get_features(struct vhd_vdev* vdev)
{
    VHD_UNUSED(vdev);
    return VIRTIO_BLK_DEFAULT_FEATURES;
}

static int vblk_set_features(struct vhd_vdev* vdev, uint64_t features)
{
    VHD_UNUSED(vdev);
    VHD_UNUSED(features);
    return 0;
}

static size_t vblk_get_config(struct vhd_vdev* vdev, void* cfgbuf, size_t bufsize)
{
    struct vhd_bdev* dev = VHD_BLOCKDEV_FROM_VDEV(vdev);
    struct virtio_blk_config* blk_config = (struct virtio_blk_config*)cfgbuf;

    if (bufsize < sizeof(struct virtio_blk_config)) {
        return 0;
    }

    *blk_config = dev->vblk.config;
    return sizeof(*blk_config);
}

static int vblk_dispatch(struct vhd_vdev* vdev, struct vhd_vring* vring, struct vhd_request_queue* rq)
{
    VHD_UNUSED(rq);

    struct vhd_bdev* dev = VHD_BLOCKDEV_FROM_VDEV(vdev);
    return virtio_blk_dispatch_requests(&dev->vblk, &vring->vq, vhd_vdev_mm_ctx(vdev));
}

const struct vhd_vdev_type g_virtio_blk_vdev_type = {
    .desc               = "virtio-blk",
    .get_features       = vblk_get_features,
    .set_features       = vblk_set_features,
    .get_config         = vblk_get_config,
    .dispatch_requests  = vblk_dispatch,
};

////////////////////////////////////////////////////////////////////////////////

//
// Amplified reads handling
//

struct bdev_aligned_req
{
    struct vhd_buffer aligned_buf;
    struct vhd_bdev_io aligned_bio;
    struct vhd_bdev_io* unaligned_bio;
    struct vhd_bdev* dev;
};

static void aligned_write_completion(struct vhd_bdev_io* bio, enum vhd_bdev_io_result iores)
{
    struct bdev_aligned_req* req = containerof(bio, struct bdev_aligned_req, aligned_bio);
    struct vhd_bdev_io* unaligned_bio = req->unaligned_bio;

    vhd_free(req->aligned_buf.base);
    vhd_free(req);

    unaligned_bio->completion_handler(unaligned_bio, iores);
}

static void aligned_read_completion(struct vhd_bdev_io* bio, enum vhd_bdev_io_result iores)
{
    struct bdev_aligned_req* req = containerof(bio, struct bdev_aligned_req, aligned_bio);
    if (iores != VHD_BDEV_SUCCESS) {
        goto complete;
    }

    size_t bufnum = 0;
    size_t bytes = req->unaligned_bio->total_sectors << VHD_SECTOR_SHIFT;
    void* pdata = req->aligned_buf.base +
        ((req->unaligned_bio->first_sector - req->aligned_bio.first_sector) << VHD_SECTOR_SHIFT);

    while (bytes > 0) {
        VHD_VERIFY(bufnum < req->unaligned_bio->sglist.nbuffers);
        struct vhd_buffer* pbuf = req->unaligned_bio->sglist.buffers + bufnum;
        size_t to_copy = (bytes > pbuf->len ? pbuf->len : bytes);

        if (req->unaligned_bio->type == VHD_BDEV_READ) {
            memcpy(pbuf->base, pdata, to_copy);
        } else if (req->unaligned_bio->type == VHD_BDEV_WRITE) {
            memcpy(pdata, pbuf->base, to_copy);
        } else {
            VHD_VERIFY(0);
        }

        bytes -= to_copy;
        pdata += to_copy;
        ++bufnum;
    }

    if (req->unaligned_bio->type == VHD_BDEV_WRITE) {
        req->aligned_bio.type = VHD_BDEV_WRITE;
        req->aligned_bio.completion_handler = aligned_write_completion;
        int error = vhd_enqueue_block_request(req->dev->vdev.rq, &req->dev->vdev, &req->aligned_bio);
        if (error) {
            VHD_LOG_ERROR("Failed to enqueue aligned write request: %d", error);
            iores = VHD_BDEV_IOERR;
            goto complete;
        }
        /* interrupt wait after enqueuing new request */
        vhd_stop_queue(req->dev->vdev.rq);

        return;
    }

complete:
    req->unaligned_bio->completion_handler(req->unaligned_bio, iores);
    vhd_free(req->aligned_buf.base);
    vhd_free(req);
}

static int aligned_read(struct vhd_bdev* dev,
                        uint64_t aligned_sector,
                        uint64_t aligned_sectors_count,
                        struct vhd_bdev_io* unaligned_bio)
{
    /* We expect unaligned requests only in rare cases during initial boot.
     * Since our main underlying network storage is high latency\high throughput,
     * we will issue 1 aligned request and copy memory instead of amplified unaligned head and tail requests. */
    struct bdev_aligned_req* req = vhd_alloc(sizeof(*req));
    req->aligned_buf.len = aligned_sectors_count << VHD_SECTOR_SHIFT;
    req->aligned_buf.base = vhd_alloc(req->aligned_buf.len);

    req->aligned_bio.type = VHD_BDEV_READ;
    req->aligned_bio.first_sector = aligned_sector;
    req->aligned_bio.total_sectors = aligned_sectors_count;
    req->aligned_bio.completion_handler = aligned_read_completion;
    req->aligned_bio.sglist.nbuffers = 1;
    req->aligned_bio.sglist.buffers = &req->aligned_buf;

    req->unaligned_bio = unaligned_bio;
    req->dev = dev;

    return vhd_enqueue_block_request(dev->vdev.rq, &dev->vdev, &req->aligned_bio);
}

////////////////////////////////////////////////////////////////////////////////

static int vblk_handle_request(struct virtio_blk_dev* vblk, struct vhd_bdev_io* bio)
{
    struct vhd_bdev* dev = VHD_BLOCKDEV_FROM_VBLK(vblk);

    uint64_t aligned_sector = bio->first_sector << VHD_SECTOR_SHIFT;
    aligned_sector = VHD_ALIGN_DOWN(aligned_sector, dev->bdev->block_size) >> VHD_SECTOR_SHIFT;

    uint64_t aligned_sectors_count = (bio->total_sectors + (bio->first_sector - aligned_sector)) << VHD_SECTOR_SHIFT;
    aligned_sectors_count = VHD_ALIGN_UP(aligned_sectors_count, dev->bdev->block_size) >> VHD_SECTOR_SHIFT;

    if (vblk->bdev->handle_unaligned && (aligned_sector != bio->first_sector || aligned_sectors_count != bio->total_sectors)) {
        return aligned_read(dev, aligned_sector, aligned_sectors_count, bio);
    }

    return vhd_enqueue_block_request(dev->vdev.rq, &dev->vdev, bio);
}

void vhd_complete_bio(struct vhd_bdev_io* bio, enum vhd_bdev_io_result res)
{
    VHD_VERIFY(bio && bio->completion_handler);
    bio->completion_handler(bio, res);
}

struct vhd_vdev* vhd_register_blockdev(struct vhd_bdev_info* bdev, struct vhd_request_queue* rq, void* priv)
{
    int res = 0;

    VHD_VERIFY(bdev);
    VHD_VERIFY(rq);

    if (bdev->total_blocks == 0) {
        return NULL;
    }

    /* Check block size is power-of-2 */
    if (bdev->block_size == 0 || (bdev->block_size & (bdev->block_size - 1))) {
        return NULL;
    }

    struct vhd_bdev* dev = vhd_zalloc(sizeof(*dev));

    res = virtio_blk_init_dev(&dev->vblk, bdev, vblk_handle_request);
    if (res != 0) {
        goto error_out;
    }

    res = vhd_vdev_init_server(&dev->vdev, bdev->id, &g_virtio_blk_vdev_type, bdev->num_queues, rq, priv);
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

void vhd_unregister_blockdev(struct vhd_vdev* vdev, void (*unregister_complete)(void*), void* arg)
{
    if (!vdev) {
        return;
    }

    struct vhd_bdev* bdev = VHD_BLOCKDEV_FROM_VDEV(vdev);

    LIST_REMOVE(bdev, blockdevs);
    vhd_vdev_uninit(vdev);
    vhd_free(bdev);

    /* TODO: this will be stored and called after all inflight requests complete */
    if (unregister_complete) {
        unregister_complete(arg);
    }
}
