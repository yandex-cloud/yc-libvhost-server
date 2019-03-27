#include "vhost-server/platform.h"
#include "vhost-server/blockdev.h"
#include "vhost-server/virt_queue.h"
#include "vhost-server/virtio_blk.h"

#include "virtio/virtio_blk10.h"

/* virtio blk data for bdev io */
struct virtio_blk_io
{
    struct virtio_virtq* vq;
    struct virtio_iov* iov;
    struct vhd_bdev_io bdev_io;
};

#define SECTORS_TO_BLOCKS(dev, sectors) ((sectors) >> (dev)->block_shift)
#define BLOCKS_TO_SECTORS(dev, blocks)  ((blocks) << (dev)->block_shift)
#define IS_ALIGNED_TO_SECTOR(val)       (((val) & (VIRTIO_BLK_SECTOR_SIZE - 1)) == 0)

static void set_status(struct virtio_iov* iov, uint8_t status)
{
    *((uint8_t*)iov->buffers[iov->nvecs - 1].start) = status;
}

static void abort_request(struct virtio_virtq* vq, struct virtio_iov* iov)
{
    virtq_commit_buffers(vq, iov);
}

static void complete_io(struct vhd_bdev_io* bdev_io, enum vhd_bdev_io_result res)
{
    VHD_ASSERT(bdev_io);

    struct virtio_blk_io* bio = containerof(bdev_io, struct virtio_blk_io, bdev_io);

    set_status(bio->iov, (res == VHD_BDEV_SUCCESS ? VIRTIO_BLK_S_OK : VIRTIO_BLK_S_IOERR));
    virtq_commit_buffers(bio->vq, bio->iov);
    vhd_free(bio);
}

static int handle_inout(struct virtio_blk_dev* dev,
                         struct virtio_blk_req_hdr* req,
                         struct virtio_virtq* vq,
                         struct virtio_iov* iov)
{
    int res = 0;

    VHD_ASSERT(req->type == VIRTIO_BLK_T_IN || req->type == VIRTIO_BLK_T_OUT);

    /* See comment about message framing in handle_buffers */
    if (iov->nvecs < 3) {
        res = -EINVAL;
        goto abort_request;
    }

    /* Check that status vector has expected size */
    if (iov->buffers[iov->nvecs - 1].len != sizeof(uint8_t)) {
        res = -EINVAL;
        goto abort_request;
    }

    struct virtq_iovec* pdata = &iov->buffers[1];
    size_t ndatabufs = iov->nvecs - 2;

    uint64_t total_sectors = 0;
    for (size_t i = 0; i < ndatabufs; ++i) {
        if (!IS_ALIGNED_TO_SECTOR(pdata[i].len)) {
            res = -EINVAL;
            goto complete_early;
        }

        total_sectors += pdata[i].len / VIRTIO_BLK_SECTOR_SIZE;
    }

    if (total_sectors == 0) {
        res = -EINVAL;
        goto complete_early;
    }

    uint64_t last_sector = req->sector + total_sectors - 1;
    if (last_sector < req->sector /* overflow */ ||
        last_sector >= BLOCKS_TO_SECTORS(dev, dev->bdev->total_blocks)) {
        res = -EINVAL;
        goto complete_early;
    }

    struct virtio_blk_io* bio = vhd_zalloc(sizeof(*bio));
    bio->vq = vq;
    bio->iov = iov;
    bio->bdev_io.bdev = dev->bdev;
    bio->bdev_io.type = (req->type == VIRTIO_BLK_T_IN ? VHD_BDEV_READ : VHD_BDEV_WRITE);
    bio->bdev_io.first_block = SECTORS_TO_BLOCKS(dev, req->sector);
    bio->bdev_io.total_blocks = SECTORS_TO_BLOCKS(dev, total_sectors);
    bio->bdev_io.sglist.nbuffers = ndatabufs;
    bio->bdev_io.sglist.buffers = (struct vhd_buffer*)pdata;
    bio->bdev_io.completion_handler = complete_io;

    res = dev->bdev->submit_requests(NULL, &bio->bdev_io, 1);
    if (res != 0) {
        /* Backend could not submit request, however it is still responsible
         * to complete it with error, so don't do that here */
    }

    return res;

complete_early:
    /* Complete request normally before sending it to backend queue */
    set_status(iov, res);

abort_request:
    /* We didn't like request framing.
     * Release buffer chain, but don't try to set request status on malformed layout. */
    abort_request(vq, iov);
    return res;
}

static void handle_buffers(void* arg, struct virtio_virtq* vq, struct virtio_iov* iov)
{
    int res;
    struct virtio_blk_dev* dev = (struct virtio_blk_dev*) arg;

    VHD_ASSERT(iov->nvecs >= 1);

    /* We don't negotiate VIRTIO_F_ANY_LAYOUT, so our message framing should be:
     * - 8 byte header buffer
     * - data buffer for In/Out/GetId requests
     * - 1 byte status buffer for !GetId requests */

    struct virtio_blk_req_hdr* req = (struct virtio_blk_req_hdr*) iov->buffers[0].start;
    if (iov->buffers[0].len != sizeof(*req)) {
        VHD_LOG_ERROR("virtio blk request invalid size %zu", iov->buffers[0].len);
        abort_request(vq, iov);
        return;
    }

    switch (req->type) {
    case VIRTIO_BLK_T_IN:
    case VIRTIO_BLK_T_OUT:
        res = handle_inout(dev, req, vq, iov);
        break;
    default:
        VHD_LOG_WARN("unknown request type %d", req->type);
        res = -ENOTSUP;
        break;
    };

    if (res != 0) {
        VHD_LOG_ERROR("request failed with %d", res);
    }
}

int virtio_blk_handle_requests(struct virtio_blk_dev* dev, struct virtio_virtq* vq)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(vq);

    return virtq_dequeue_many(vq, dev->mm, handle_buffers, dev);
}

int virtio_blk_init_dev(struct virtio_blk_dev* dev, struct vhd_bdev* bdev)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(bdev);

    /* block size should be a multiple of vblk sector size */
    if (!bdev->block_size || (bdev->block_size & (VIRTIO_BLK_SECTOR_SIZE - 1))) {
        VHD_LOG_ERROR("block size %llu should be a multiple of virtio blk sector size (512 bytes)",
                      (unsigned long long)bdev->block_size);
        return -EINVAL;
    }

    dev->bdev = bdev;
    dev->block_shift = __builtin_ctz(bdev->block_size >> VIRTIO_BLK_SECTOR_SHIFT);

    return 0;
}
