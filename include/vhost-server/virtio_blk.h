#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_bdev;
struct virtio_mm_ctx;
struct virtio_virtq;

struct virtio_blk_dev
{
    struct vhd_bdev* bdev;
    struct virtio_mm_ctx* mm;

    uint8_t block_shift;
};

int virtio_blk_init_dev(struct virtio_blk_dev* dev, struct vhd_bdev* bdev);
int virtio_blk_handle_requests(struct virtio_blk_dev* dev, struct virtio_virtq* vq);

#ifdef __cplusplus
}
#endif
