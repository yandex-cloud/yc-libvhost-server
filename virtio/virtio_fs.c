#include <string.h>

#include "vhost/fs.h"

#include "virtio_fs.h"
#include "virtio_fs_spec.h"

#include "bio.h"
#include "virt_queue.h"
#include "logging.h"
#include "server_internal.h"
#include "vdev.h"

/******************************************************************************/

struct virtio_fs_io {
    struct virtio_virtq *vq;
    struct virtio_iov *iov;

    /* TODO: this should be device type-specific */
    struct vhd_bio bio;
};

#define VIRTIO_VBIO_FROM_BIO(ptr) containerof(ptr, struct virtio_fs_io, bio)

/******************************************************************************/

static inline void abort_request(struct virtio_virtq *vq, struct virtio_iov *iov)
{
    virtq_push(vq, iov, 0);
    virtio_free_iov(iov);
}

static void complete_request(struct vhd_bio *bio)
{
    struct virtio_fs_io *vbio = VIRTIO_VBIO_FROM_BIO(bio);
    struct virtio_iov *viov = vbio->iov;
    /* if IN iov has at least one buffer it accomodates fuse_out_header */
    struct virtio_fs_out_header *out =
                        viov->niov_in ? viov->iov_in[0].base : NULL;
    uint32_t len = out ? out->len : 0;

    if (likely(bio->status != VHD_BDEV_CANCELED)) {
        virtq_push(vbio->vq, vbio->iov, len);
    }

    virtio_free_iov(viov);
    vhd_free(vbio);
}

static int virtio_fs_handle_request(struct virtio_virtq *vq,
                                    struct vhd_bio *bio)
{
    bio->vring = VHD_VRING_FROM_VQ(vq);
    return vhd_enqueue_block_request(vhd_get_rq_for_vring(bio->vring), bio);
}

static void handle_buffers(void *arg, struct virtio_virtq *vq, struct virtio_iov *iov)
{
    uint16_t niov = iov->niov_in + iov->niov_out;
    (void)arg;

    /*
     * Assume legacy message framing without VIRTIO_F_ANY_LAYOUT:
     * - virtio IN / FUSE OUT segments, with the first one fully containing
     *   fuse_in_header
     * - virtio OUT / FUSE IN segments, with the first one fully containing
     *   fuse_out_header (except FUSE_FORGET and FUSE_BATCH_FORGET which have
     *   no response part at all)
     */

    struct virtio_fs_in_header *in;
    struct virtio_fs_out_header *out;

    if (iov->niov_in && iov->iov_in[0].len < sizeof(*out)) {
        VHD_LOG_ERROR("No room for response in the request");
        abort_request(vq, iov);
        return;
    }

    if (!iov->niov_out || iov->iov_out[0].len < sizeof(*in)) {
        VHD_LOG_ERROR("Malformed request header");
        abort_request(vq, iov);
        return;
    }

    in = iov->iov_out[0].base;
    out = iov->niov_in ? iov->iov_in[0].base : NULL;

    struct virtio_fs_io *vbio = vhd_zalloc(sizeof(*vbio));
    vbio->vq = vq;
    vbio->iov = iov;
    vbio->bio.bdev_io.sglist.nbuffers = niov;
    vbio->bio.bdev_io.sglist.buffers = iov->buffers;
    vbio->bio.completion_handler = complete_request;

    int res = virtio_fs_handle_request(vbio->vq, &vbio->bio);
    if (res != 0) {
        VHD_LOG_ERROR("request submission failed with %d", res);

        if (out) {
            out->len = sizeof(*out);
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
    struct vhd_fsdev_info *fsdev)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(fsdev);

    dev->fsdev = fsdev;

    dev->config = (struct virtio_fs_config) {
        .num_request_queues = fsdev->num_queues,
    };
    if (fsdev->tag) {
        memcpy(dev->config.tag, fsdev->tag,
               MIN(strlen(fsdev->tag), sizeof(dev->config.tag)));
    }

    return 0;
}

int virtio_fs_dispatch_requests(struct virtio_fs_dev *dev,
                                struct virtio_virtq *vq)
{
    VHD_VERIFY(dev);
    VHD_VERIFY(vq);

    return virtq_dequeue_many(vq, handle_buffers, dev);
}
