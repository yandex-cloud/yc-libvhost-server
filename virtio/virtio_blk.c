#include <string.h>
#include <inttypes.h>

#include "vhost/blockdev.h"

#include "virtio_blk.h"
#include "virtio_blk_spec.h"

#include "bio.h"
#include "virt_queue.h"
#include "logging.h"

/* virtio blk data for bdev io */
struct virtio_blk_io {
    struct virtio_virtq *vq;
    struct virtio_iov *iov;
    struct vhd_bio bio;
};

static uint8_t translate_status(enum vhd_bdev_io_result status)
{
    switch (status) {
    case VHD_BDEV_SUCCESS:
        return VIRTIO_BLK_S_OK;
    default:
        return VIRTIO_BLK_S_IOERR;
    }
}

static void set_status(struct virtio_iov *iov, uint8_t status)
{
    *((uint8_t *)iov->buffers[iov->nvecs - 1].base) = status;
}

static void abort_request(struct virtio_virtq *vq, struct virtio_iov *iov)
{
    /*
     * FIXME: this is called when the message framing is messed up.  This
     * appears severe enough to just stop processing the virtq and mark it
     * broken
     */
    VHD_LOG_ERROR("no valid virtio-blk request found, aborting queue %p", vq);
    virtq_push(vq, iov, 0);
    virtio_free_iov(iov);
}

static void complete_req(struct virtio_virtq *vq, struct virtio_iov *iov,
                         uint8_t status)
{
    set_status(iov, status);
    /*
     * FIXME: since the last byte in the IN buffer is always written (for
     * status), the total length of the IN buffer should always be passed to
     * virtq_push().  However, it's too awkward to do before proper OUT/IN
     * buffer split is done, and no actual driver cares, so pass 0 for now.
     */
    virtq_push(vq, iov, 0);
    virtio_free_iov(iov);
}

static void complete_io(struct vhd_bio *bio)
{
    struct virtio_blk_io *vbio = containerof(bio, struct virtio_blk_io, bio);

    if (likely(bio->status != VHD_BDEV_CANCELED)) {
        complete_req(vbio->vq, vbio->iov, translate_status(bio->status));
    } else {
        virtio_free_iov(vbio->iov);
    }

    vhd_free(vbio);
}

static inline bool vhd_buffer_is_read_only(const struct vhd_buffer *buf)
{
    return !buf->write_only;
}

static inline bool vhd_buffer_is_write_only(const struct vhd_buffer *buf)
{
    return buf->write_only;
}

static inline bool vhd_buffer_can_read(const struct vhd_buffer *buf)
{
    return vhd_buffer_is_read_only(buf);
}

static inline bool vhd_buffer_can_write(const struct vhd_buffer *buf)
{
    return vhd_buffer_is_write_only(buf);
}

static bool check_status_buffer(struct vhd_buffer *buf)
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

static bool is_valid_req(uint64_t sector, size_t len, uint64_t capacity)
{
    size_t nsectors = len / VIRTIO_BLK_SECTOR_SIZE;

    if (len == 0) {
        VHD_LOG_ERROR("Zero size request");
        return false;
    }
    if (len % VIRTIO_BLK_SECTOR_SIZE) {
        VHD_LOG_ERROR("Request length %zu"
                      " is not a multiple of sector size %u",
                      len, VIRTIO_BLK_SECTOR_SIZE);
        return false;
    }
    if (sector > capacity || sector > capacity - nsectors) {
        VHD_LOG_ERROR("Request (%" PRIu64 "s, +%zus) spans"
                      " beyond device capacity %" PRIu64,
                      sector, nsectors, capacity);
        return false;
    }
    return true;
}

static void handle_inout(struct virtio_blk_dev *dev,
                         struct virtio_blk_req_hdr *req,
                         struct virtio_virtq *vq,
                         struct virtio_iov *iov)
{
    uint8_t status = VIRTIO_BLK_S_IOERR;
    size_t len;
    size_t i;

    VHD_ASSERT(req->type == VIRTIO_BLK_T_IN || req->type == VIRTIO_BLK_T_OUT);

    if (dev->bdev->readonly && req->type == VIRTIO_BLK_T_OUT) {
        VHD_LOG_ERROR("Write request to readonly device");
        goto complete;
    }

    /* See comment about message framing in handle_buffers */
    if (iov->nvecs < 3) {
        VHD_LOG_ERROR("Bad number of buffers %d in iov", iov->nvecs);
        goto complete;
    }

    struct vhd_buffer *pdata = &iov->buffers[1];
    size_t ndatabufs = iov->nvecs - 2;

    for (i = 0, len = 0; i < ndatabufs; ++i) {
        /* Buffer should be write-only if this is a read request */
        if (req->type == VIRTIO_BLK_T_IN &&
            !vhd_buffer_is_write_only(pdata + i)) {
            VHD_LOG_ERROR("Cannot write to data buffer %zu", i);
            goto complete;
        }

        /* Buffer should be read-only if this is a write request */
        if (req->type == VIRTIO_BLK_T_OUT &&
            !vhd_buffer_is_read_only(pdata + i)) {
            VHD_LOG_ERROR("Cannot read from data buffer %zu", i);
            goto complete;
        }

        len += pdata[i].len;
    }

    if (!is_valid_req(req->sector, len, dev->config.capacity)) {
        goto complete;
    }

    struct virtio_blk_io *vbio = vhd_zalloc(sizeof(*vbio));
    vbio->vq = vq;
    vbio->iov = iov;
    vbio->bio.bdev_io.type = req->type == VIRTIO_BLK_T_IN ? VHD_BDEV_READ :
                             VHD_BDEV_WRITE;
    vbio->bio.bdev_io.first_sector = req->sector;
    vbio->bio.bdev_io.total_sectors = len / VIRTIO_BLK_SECTOR_SIZE;
    vbio->bio.bdev_io.sglist.nbuffers = ndatabufs;
    vbio->bio.bdev_io.sglist.buffers = pdata;
    vbio->bio.completion_handler = complete_io;

    int res = dev->dispatch(vbio->vq, &vbio->bio);
    if (res != 0) {
        VHD_LOG_ERROR("bdev request submission failed with %d", res);
        vhd_free(vbio);
        goto complete;
    }

    /* request will be completed asynchronously */
    return;

complete:
    complete_req(vq, iov, status);
}

static uint8_t handle_getid(struct virtio_blk_dev *dev,
                            struct virtio_iov *iov)
{
    if (iov->nvecs != 3) {
        VHD_LOG_ERROR("Bad number of buffers %d in iov", iov->nvecs);
        return VIRTIO_BLK_S_IOERR;
    }

    struct vhd_buffer *id_buf = &iov->buffers[1];

    if (id_buf->len != VIRTIO_BLK_DISKID_LENGTH ||
        !vhd_buffer_can_write(id_buf)) {
        VHD_LOG_ERROR("Bad id buffer (len %zu)", id_buf->len);
        return VIRTIO_BLK_S_IOERR;
    }

    /*
     * strncpy will not add a null-term if src length is >= desc->len, which is
     * what we need
     */
    strncpy((char *) id_buf->base, dev->bdev->serial, id_buf->len);

    return VIRTIO_BLK_S_OK;
}

static void handle_buffers(void *arg, struct virtio_virtq *vq,
                           struct virtio_iov *iov)
{
    uint8_t status;
    struct virtio_blk_dev *dev = arg;

    VHD_ASSERT(iov->nvecs >= 1);
    /*
     * Assume legacy message framing without VIRTIO_F_ANY_LAYOUT:
     * - one 16-byte device-readable segment for header
     * - data segments
     * - one 1-byte device-writable segment for status
     * FIXME: get rid of this assumption and support VIRTIO_F_ANY_LAYOUT
     */

    if (!check_status_buffer(&iov->buffers[iov->nvecs - 1])) {
        VHD_LOG_ERROR("No room for status response in the request");
        abort_request(vq, iov);
        return;
    }

    struct vhd_buffer *req_buf = &iov->buffers[0];
    if (!vhd_buffer_can_read(req_buf)) {
        VHD_LOG_ERROR("Request header is not readable by device");
        abort_request(vq, iov);
        return;
    }

    struct virtio_blk_req_hdr *req = (struct virtio_blk_req_hdr *)req_buf->base;
    if (iov->buffers[0].len != sizeof(*req)) {
        VHD_LOG_ERROR("virtio blk request invalid size %zu",
                      iov->buffers[0].len);
        abort_request(vq, iov);
        return;
    }

    switch (req->type) {
    case VIRTIO_BLK_T_IN:
    case VIRTIO_BLK_T_OUT:
        handle_inout(dev, req, vq, iov);
        return;         /* async completion */
    case VIRTIO_BLK_T_GET_ID:
        status = handle_getid(dev, iov);
        break;
    default:
        VHD_LOG_WARN("unknown request type %d", req->type);
        status = VIRTIO_BLK_S_UNSUPP;
        break;
    };

    complete_req(vq, iov, status);
}

/*////////////////////////////////////////////////////////////////////////////*/

int virtio_blk_dispatch_requests(struct virtio_blk_dev *dev,
                                 struct virtio_virtq *vq)
{
    return virtq_dequeue_many(vq, handle_buffers, dev);
}

int virtio_blk_init_dev(
    struct virtio_blk_dev *dev,
    struct vhd_bdev_info *bdev,
    virtio_blk_io_dispatch *dispatch)
{
    /*
     * Here we use same max values like we did for blockstor-plugin.
     * But it seems that the real world max values are:
     */
    /* 63 for sectors */
    const uint8_t max_sectors = 255;
    /* 16 for heads */
    const uint8_t max_heads = 255;
    /* 16383 for cylinders */
    const uint16_t max_cylinders = 65535;

    uint32_t phys_block_sectors = bdev->block_size >> VHD_SECTOR_SHIFT;
    uint8_t phys_block_exp = vhd_find_first_bit32(phys_block_sectors);

    dev->dispatch = dispatch;
    dev->bdev = bdev;

    /*
     * Both virtio and block backend use the same sector size of 512.  Don't
     * bother converting between the two, just assert they are the same.
     */
    VHD_STATIC_ASSERT(VHD_SECTOR_SIZE == VIRTIO_BLK_SECTOR_SIZE);

    dev->config.capacity = bdev->total_blocks << phys_block_exp;
    dev->config.blk_size = VHD_SECTOR_SIZE;
    dev->config.numqueues = bdev->num_queues;
    dev->config.topology.physical_block_exp = phys_block_exp;
    dev->config.topology.alignment_offset = 0;
    /* TODO: can get that from bdev info */
    dev->config.topology.min_io_size = 1;
    dev->config.topology.opt_io_size = 0;

    /*
     * Hardcode seg_max to 126. The same way like it's done for virtio-blk in
     * qemu 2.12 which is used by blockstor-plugin.
     * Although, this is an error prone approch which leads to the problems
     * when queue size != 128
     * (see https://www.mail-archive.com/qemu-devel@nongnu.org/msg668144.html)
     * we have to use it to provide migration compatibility between virtio-blk
     * and vhost-user-blk in both directions.
     */
    dev->config.seg_max = 128 - 2;

    dev->config.geometry.sectors = MIN(dev->config.capacity, max_sectors);
    dev->config.geometry.heads =
        MIN(1 + (dev->config.capacity - 1) / max_sectors, max_heads);
    dev->config.geometry.cylinders =
        MIN(1 + (dev->config.capacity - 1) / (max_sectors * max_heads),
            max_cylinders);

    return 0;
}
