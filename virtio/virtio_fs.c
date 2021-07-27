#include <string.h>

#include "vhost/fs.h"

#include "virtio_fs.h"
#include "virtio_fs_spec.h"

#include "bio.h"
#include "virt_queue.h"
#include "logging.h"

/******************************************************************************/

struct virtio_fs_io {
    struct virtio_virtq *vq;
    struct virtio_iov *iov;

    /* TODO: this should be device type-specific */
    struct vhd_bio bio;
};

#define VIRTIO_VBIO_FROM_BIO(ptr) containerof(ptr, struct virtio_fs_io, bio)

/******************************************************************************/

static inline bool vhd_buffer_is_read_only(const struct vhd_buffer *buf)
{
    return !buf->write_only;
}

static inline bool vhd_buffer_is_write_only(const struct vhd_buffer *buf)
{
    return buf->write_only;
}

static inline void abort_request(struct virtio_virtq *vq, struct virtio_iov *iov)
{
    virtq_commit_buffers(vq, iov);
}

static void complete_request(struct vhd_bio *bio)
{
    struct virtio_fs_io *vbio = VIRTIO_VBIO_FROM_BIO(bio);

    virtq_commit_buffers(vbio->vq, vbio->iov);
    virtq_notify(vbio->vq);

    vhd_free(vbio);
}

static void handle_buffers(void *arg, struct virtio_virtq *vq, struct virtio_iov *iov)
{
    struct virtio_fs_dev *dev = (struct virtio_fs_dev *) arg;

    /* We do not negotiate VIRTIO_F_ANY_LAYOUT, so our message framing should be:
     * - at least sizeof(virtio_fs_in_header) In buffer
     * - [optional] data buffers for In args
     * - at least sizeof(virtio_fs_out_header) Out buffer
     * - [optional] data buffers for Out args
     *
     * All FUSE requests are two-way except for FUSE_FORGET
     */

    struct vhd_buffer *buf = iov->buffers;
    struct vhd_buffer *buf_end = iov->buffers + iov->nvecs;

    struct virtio_fs_in_header *in = NULL;
    struct virtio_fs_out_header *out = NULL;

    /* parse IN buffers */
    VHD_ASSERT(buf != buf_end);

    if (vhd_buffer_is_write_only(buf)) {
        VHD_LOG_ERROR("request header is not readable by device");
        abort_request(vq, iov);
        return;
    }

    if (buf->len < sizeof(struct virtio_fs_in_header)) {
        VHD_LOG_ERROR("invalid request header size %zu", buf->len);
        abort_request(vq, iov);
        return;
    }

    in = (struct virtio_fs_in_header *) buf->base;

    size_t in_len = 0;
    while (buf != buf_end && vhd_buffer_is_read_only(buf)) {
        in_len += buf->len;
        ++buf;
    }

    if (in->len != in_len) {
        VHD_LOG_ERROR("invalid request size %u", in->len);
        abort_request(vq, iov);
        return;
    }

    /* parse OUT buffers */
    if (buf != buf_end) {
        VHD_ASSERT(vhd_buffer_is_write_only(buf));

        if (buf->len < sizeof(struct virtio_fs_out_header)) {
            VHD_LOG_ERROR("invalid response header size %zu", buf->len);
            abort_request(vq, iov);
            return;
        }

        out = (struct virtio_fs_out_header *) buf->base;

        size_t out_len = 0;
        while (buf != buf_end && vhd_buffer_is_write_only(buf)) {
            out_len += buf->len;
            ++buf;
        }

        if (buf != buf_end) {
            VHD_LOG_ERROR("invalid response buffers layout");
            abort_request(vq, iov);
            return;
        }
    }

    struct virtio_fs_io *vbio = vhd_zalloc(sizeof(*vbio));
    vbio->vq = vq;
    vbio->iov = iov;
    vbio->bio.bdev_io.sglist.nbuffers = iov->nvecs;
    vbio->bio.bdev_io.sglist.buffers = iov->buffers;
    vbio->bio.completion_handler = complete_request;

    int res = dev->dispatch(vbio->vq, &vbio->bio);
    if (res != 0) {
        VHD_LOG_ERROR("request submission failed with %d", res);

        if (out) {
            out->len = sizeof(struct virtio_fs_out_header);
            out->error = res;
            out->unique = in->unique;
        }

        complete_request(&vbio->bio);
        return;
    }
}

/******************************************************************************/

int virtio_fs_init_dev(
    struct virtio_fs_dev *dev,
    struct vhd_fsdev_info *fsdev,
    virtio_fs_io_dispatch *dispatch)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(fsdev);

    dev->dispatch = dispatch;
    dev->fsdev = fsdev;

    if (fsdev->tag) {
        strncpy((char *) dev->config.tag, fsdev->tag, sizeof(dev->config.tag));
    }

    dev->config.num_request_queues = fsdev->num_queues;

    return 0;
}

int virtio_fs_dispatch_requests(struct virtio_fs_dev *dev,
                                struct virtio_virtq *vq)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(vq);

    return virtq_dequeue_many(vq, handle_buffers, dev);
}
