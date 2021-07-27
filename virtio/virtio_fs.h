#pragma once

#include "virtio_fs_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

struct virtio_fs_dev;
struct virtio_virtq;

struct vhd_fsdev_info;
struct vhd_bio;
struct vhd_guest_memory_map;

#define VIRTIO_FS_DEFAULT_FEATURES ((uint64_t)( \
    (1UL << VIRTIO_F_RING_INDIRECT_DESC) | \
    (1UL << VIRTIO_F_VERSION_1)))

/**
 * Virtio file system I/O dispatch context.
 */
typedef int virtio_fs_io_dispatch(struct virtio_virtq *vq,
                                   struct vhd_bio *bio);

/**
 * Virtio file system device context
 */
struct virtio_fs_dev {
    struct vhd_fsdev_info *fsdev;

    /* fs config data generated on init from fsdev */
    struct virtio_fs_config config;

    /* Handler to dispatch I/O to underlying file system backend */
    virtio_fs_io_dispatch *dispatch;
};

/**
 * Init virtio fs device context from fsdev info
 */
int virtio_fs_init_dev(
    struct virtio_fs_dev *dev,
    struct vhd_fsdev_info *fsdev,
    virtio_fs_io_dispatch *dispatch);

/**
 * Dispatch requests from device virtq
 */
int virtio_fs_dispatch_requests(struct virtio_fs_dev *dev,
                                struct virtio_virtq *vq);

#ifdef __cplusplus
}
#endif
