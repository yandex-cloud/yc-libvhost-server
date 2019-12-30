#include <string.h>

#include <vhost/platform.h>
#include <vhost/types.h>
#include <vhost/blockdev.h>

#include "virtio_blk.h"
#include "virtio_blk_spec.h"

#include "virt_queue.h"

#define SECTORS_TO_BLOCKS(dev, sectors) ((sectors) >> (dev)->block_shift)
#define BLOCKS_TO_SECTORS(dev, blocks)  ((blocks) << (dev)->block_shift)
#define IS_ALIGNED_TO_SECTOR(val)       (((val) & (VIRTIO_BLK_SECTOR_SIZE - 1)) == 0)

/* virtio blk data for bdev io */
struct virtio_blk_io
{
    struct virtio_virtq* vq;
    struct virtio_iov* iov;
    struct vhd_bdev_io bdev_io;
};

static void set_status(struct virtio_iov* iov, uint8_t status)
{
    *((uint8_t*)iov->buffers[iov->nvecs - 1].base) = status;
}

static void abort_request(struct virtio_virtq* vq, struct virtio_iov* iov)
{
    virtq_commit_buffers(vq, iov);
}

static void fail_request(struct virtio_virtq* vq, struct virtio_iov* iov)
{
    set_status(iov, VIRTIO_BLK_S_IOERR);
    abort_request(vq, iov);
}

static void complete_io(struct vhd_bdev_io* bdev_io, enum vhd_bdev_io_result res)
{
    VHD_ASSERT(bdev_io);

    struct virtio_blk_io* bio = containerof(bdev_io, struct virtio_blk_io, bdev_io);

    set_status(bio->iov, (res == VHD_BDEV_SUCCESS ? VIRTIO_BLK_S_OK : VIRTIO_BLK_S_IOERR));

    virtq_commit_buffers(bio->vq, bio->iov);
    virtq_notify(bio->vq);

    vhd_free(bio);
}

static bool check_status_buffer(struct vhd_buffer* buf)
{
    /* Check that status vector has expected size */
    if (buf->len != sizeof(uint8_t)) {
        return false;
    }

    /* Status buffer should be writable */
    if (!vhd_buffer_can_write(buf)) {
        return false;
    }

    return true;
}

static int handle_inout(struct virtio_blk_dev* dev,
                        struct virtio_blk_req_hdr* req,
                        struct virtio_virtq* vq,
                        struct virtio_iov* iov)
{
    VHD_ASSERT(req->type == VIRTIO_BLK_T_IN || req->type == VIRTIO_BLK_T_OUT);

    /* See comment about message framing in handle_buffers */
    if (iov->nvecs < 3) {
        VHD_LOG_ERROR("Bad number of buffers %d in iov", iov->nvecs);
        abort_request(vq, iov);
        return -EINVAL;
    }

    struct vhd_buffer* status_buf = &iov->buffers[iov->nvecs - 1];
    struct vhd_buffer* pdata = &iov->buffers[1];
    size_t ndatabufs = iov->nvecs - 2;

    if (!check_status_buffer(status_buf)) {
        VHD_LOG_ERROR("Bad status buffer");
        abort_request(vq, iov);
        return -EINVAL;
    }

    uint64_t total_sectors = 0;
    for (size_t i = 0; i < ndatabufs; ++i) {
        if (!IS_ALIGNED_TO_SECTOR(pdata[i].len)) {
            VHD_LOG_ERROR("Data buffer %zu length %zu is not aligned to sector size", i, pdata[i].len);
            fail_request(vq, iov);
            return -EINVAL;
        }
    
        /* Buffer should be write-only if this is a read request */
        if (req->type == VIRTIO_BLK_T_IN && !vhd_buffer_is_write_only(pdata + i)) {
            VHD_LOG_ERROR("Cannot write to data buffer %zu", i);
            fail_request(vq, iov);
            return -EINVAL;
        }

        /* Buffer should be read-only if this is a write request */
        if (req->type == VIRTIO_BLK_T_OUT && !vhd_buffer_is_read_only(pdata + i)) {
            VHD_LOG_ERROR("Cannot read from data buffer %zu", i);
            fail_request(vq, iov);
            return -EINVAL;
        }

        total_sectors += pdata[i].len / VIRTIO_BLK_SECTOR_SIZE;
    }

    if (total_sectors == 0) {
        VHD_LOG_ERROR("0 sectors in I/O request");
        fail_request(vq, iov);
        return -EINVAL;
    }

    uint64_t last_sector = req->sector + total_sectors - 1;
    if (last_sector < req->sector /* overflow */ ||
        last_sector >= dev->config.capacity) {
        VHD_LOG_ERROR("Request out of bdev range, last sector = %llu", (unsigned long long) last_sector);
        fail_request(vq, iov);
        return -EINVAL;
    }

    struct virtio_blk_io* bio = vhd_zalloc(sizeof(*bio));
    bio->vq = vq;
    bio->iov = iov;
    bio->bdev_io.type = (req->type == VIRTIO_BLK_T_IN ? VHD_BDEV_READ : VHD_BDEV_WRITE);
    bio->bdev_io.first_sector = req->sector;
    bio->bdev_io.total_sectors = total_sectors;
    bio->bdev_io.sglist.nbuffers = ndatabufs;
    bio->bdev_io.sglist.buffers = (struct vhd_buffer*)pdata;
    bio->bdev_io.completion_handler = complete_io;

    int res = dev->dispatch(dev, &bio->bdev_io);
    if (res != 0) {
        VHD_LOG_ERROR("bdev request submission failed with %d", res);
        fail_request(vq, iov);
        return res;
    }

    return 0;
}

static int handle_getid(struct virtio_blk_dev* dev,
                        struct virtio_blk_req_hdr* req,
                        struct virtio_virtq* vq,
                        struct virtio_iov* iov)
{
    VHD_ASSERT(req->type == VIRTIO_BLK_T_GET_ID);
    VHD_UNUSED(req);

    if (iov->nvecs != 3) {
        VHD_LOG_ERROR("Bad number of buffers %d in iov", iov->nvecs);
        abort_request(vq, iov);
        return -EINVAL;
    }

    struct vhd_buffer* status_buf = &iov->buffers[2];
    struct vhd_buffer* id_buf = &iov->buffers[1];

    if (!check_status_buffer(status_buf)) {
        VHD_LOG_ERROR("Bad status buffer");
        abort_request(vq, iov);
        return -EINVAL;
    }

    if (id_buf->len != VIRTIO_BLK_DISKID_LENGTH || !vhd_buffer_can_write(id_buf)) {
        VHD_LOG_ERROR("Bad id buffer (len %zu)", id_buf->len);
        fail_request(vq, iov);
        return -EINVAL;
    }

    /* strncpy will not add a null-term if src length is >= desc->len, which is what we need */
    strncpy((char*) id_buf->base, dev->bdev->id, id_buf->len);

    /* Complete request */
    set_status(iov, VIRTIO_BLK_S_OK);
    virtq_commit_buffers(vq, iov);
    virtq_notify(vq);

    return 0;
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

    struct vhd_buffer* req_buf = &iov->buffers[0];
    if (!vhd_buffer_can_read(req_buf)) {
        VHD_LOG_ERROR("Request header is not readable by device");
        abort_request(vq, iov);
        return;
    }

    struct virtio_blk_req_hdr* req = (struct virtio_blk_req_hdr*) req_buf->base;
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
    case VIRTIO_BLK_T_GET_ID:
        res = handle_getid(dev, req, vq, iov);
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

////////////////////////////////////////////////////////////////////////////////

int virtio_blk_dispatch_requests(
    struct virtio_blk_dev* dev,
    struct virtio_virtq* vq,
    struct virtio_mm_ctx* mm)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(vq);

    return virtq_dequeue_many(vq, mm, handle_buffers, dev);
}

int virtio_blk_init_dev(
    struct virtio_blk_dev* dev,
    struct vhd_bdev_info* bdev,
    virtio_blk_io_dispatch* dispatch)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(bdev);

    /* block size should be a multiple of vblk sector size */
    if (!bdev->block_size || (bdev->block_size & (VIRTIO_BLK_SECTOR_SIZE - 1))) {
        VHD_LOG_ERROR("block size %llu should be a multiple of virtio blk sector size (512 bytes)",
                      (unsigned long long)bdev->block_size);
        return -EINVAL;
    }

    dev->block_shift = __builtin_ctz(bdev->block_size >> VIRTIO_BLK_SECTOR_SHIFT);
    dev->dispatch = dispatch;
    dev->bdev = bdev;

    dev->config.capacity = BLOCKS_TO_SECTORS(dev, bdev->total_blocks);
    dev->config.blk_size = VHD_SECTOR_SIZE;
    dev->config.numqueues = bdev->num_queues;

    dev->config.topology.physical_block_exp = dev->block_shift;
    dev->config.topology.alignment_offset = 0;
    /* TODO: can get that from bdev info */
    dev->config.topology.min_io_size = 1;
    dev->config.topology.opt_io_size = 0;

    return 0;
}
