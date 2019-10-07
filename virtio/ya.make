LIBRARY(virtio)

ADDINCL(
    cloud/contrib/vhost/include
    cloud/contrib/vhost
)

SRCS(
    virt_queue.c
    virtio_blk.c
)

END()
