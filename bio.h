/*
 * Internally used represenation of a block io request passed to and returned
 * from the block backend.
 */

#pragma once

#include "vhost/blockdev.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_bio {
    struct vhd_bdev_io bdev_io;

    enum vhd_bdev_io_result status;

    void (*completion_handler)(struct vhd_bio* bio);
};

#ifdef __cplusplus
}
#endif
