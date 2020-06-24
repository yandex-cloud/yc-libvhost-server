/*
 * Internally used represenation of a block io request passed to and returned
 * from the block backend.
 */

#pragma once

#include "queue.h"
#include "vhost/blockdev.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_vdev;

struct vhd_bio {
    struct vhd_bdev_io bdev_io;

    enum vhd_bdev_io_result status;
    struct vhd_vdev *vdev;

    void (*completion_handler)(struct vhd_bio* bio);

    TAILQ_ENTRY(vhd_bio) submission_link;
};

#ifdef __cplusplus
}
#endif
