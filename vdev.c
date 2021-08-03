#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <pthread.h>

#include "vdev.h"
#include "server_internal.h"
#include "logging.h"
#include "memmap.h"
#include "memlog.h"

static LIST_HEAD(, vhd_vdev) g_vdevs = LIST_HEAD_INITIALIZER(g_vdevs);

static uint16_t vring_idx(struct vhd_vring *vring)
{
    return vring->vdev->vrings - vring;
}

/* Return size of per queue inflight buffer. */
static size_t vring_inflight_buf_size(uint16_t num)
{
    return sizeof(struct inflight_split_region) +
        num * sizeof(struct inflight_split_desc);
}

static int vring_kick(void *opaque)
{
    struct vhd_vring *vring = opaque;
    struct vhd_vdev *vdev = vring->vdev;

    if (!vring->is_started) {
        return 0;
    }

    /*
     * Clear vring event now, before processing virtq.
     * Otherwise we might lose events if guest has managed to
     * signal eventfd again while we were processing
     */
    vhd_clear_eventfd(vring->kickfd);
    return vdev->type->dispatch_requests(vdev, vring, vdev->rq);
}

static int vring_update_vq_addrs(struct vhd_vring *vring)
{
    struct vhd_vdev *vdev = vring->vdev;

    vhd_memmap_ref(vdev->memmap);

    void *desc = uva_to_ptr(vdev->memmap, vring->addr_cache.desc);
    void *used = uva_to_ptr(vdev->memmap, vring->addr_cache.used);
    void *avail = uva_to_ptr(vdev->memmap, vring->addr_cache.avail);

    if (!desc || !used || !avail) {
        VHD_LOG_ERROR("invalid vring component address (%p, %p, %p)",
                       desc, used, avail);
        vhd_memmap_unref(vdev->memmap);
        return -EINVAL;
    }

    vring->vq.desc = desc;
    vring->vq.used = used;
    vring->vq.avail = avail;
    if (vring->vq.mm) {
        vhd_memmap_unref(vring->vq.mm);
    }
    vring->vq.mm = vdev->memmap;

    return 0;
}

static void vdev_ref(struct vhd_vdev *vdev);
static void vdev_unref(struct vhd_vdev *vdev);

static int vring_start(struct vhd_vring *vring)
{
    int res;

    if (vring->is_started) {
        VHD_LOG_ERROR("Try to start already started vring: vring %d",
                      vring_idx(vring));
        return 0;
    }

    /*
     * Update vq addresses from cache right before vq init.
     * This guarantees that vq rings addresses are set with
     * actual guest memory mapping.
     */
    res = vring_update_vq_addrs(vring);
    if (res) {
        return res;
    }

    res = virtio_virtq_init(&vring->vq);
    if (res != 0) {
        VHD_LOG_ERROR("virtq init failed: %d", res);
       return res;
    }

    virtq_set_notify_fd(&vring->vq, vring->callfd);

    vring->is_started = true;
    /* pairs with unref in vring_stop_bh() */
    vhd_vring_ref(vring);
    /* pairs with vdev_unref in vring_unref on vring disabling */
    vdev_ref(vring->vdev);
    vring->kick_handler = vhd_add_rq_io_handler(vring->vdev->rq, vring->kickfd,
                                                vring_kick, vring);

    if (!vring->kick_handler) {
        vring->is_started = false;
        vhd_vring_unref(vring);
        vdev_unref(vring->vdev);
        virtio_virtq_release(&vring->vq);
        VHD_LOG_ERROR("Could not create vring event from kickfd");
        return -EIO;
    }

    return 0;
}

static void vring_stop_bh(void *opaque)
{
    struct vhd_vring *vring = (struct vhd_vring *) opaque;
    vhd_del_io_handler(vring->kick_handler);
    vring->is_started = false;
    if (vring->vq.mm) {
        vhd_memmap_unref(vring->vq.mm);
    }
    /* pairs with ref in vring_started() */
    vhd_vring_unref(vring);
}

static void vring_stop(struct vhd_vring *vring)
{
    /* there should be no cases when we stop already stopped vring */
    VHD_ASSERT(vring->is_started);

    vhd_run_in_rq(vring->vdev->rq, vring_stop_bh, vring);
}

static void vhd_vring_stop(struct vhd_vring *vring)
{
    if (!vring || !vring->is_started) {
        return;
    }

    vring_stop(vring);
}
/*
 * Receive and store the message from the socket. Fill in the file
 * descriptor array. Return number of bytes received or
 * negative error code in case of error.
 */
static int net_recv_msg(int fd, struct vhost_user_msg *msg,
                        int *fds, size_t *num_fds)
{
    struct msghdr msgh;
    struct iovec iov;
    int len;
    int payload_len;
    struct cmsghdr *cmsg;
    char control[CMSG_SPACE(sizeof(int) * VHOST_USER_MAX_FDS)];

    /* Receive header for new request. */
    iov.iov_base = msg;
    iov.iov_len = sizeof(msg->hdr);

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);
    len = recvmsg(fd, &msgh, 0);
    if (len == 0) {
        return 0;
    } else if (len < 0) {
        VHD_LOG_ERROR("recvmsg() failed. Error code = %d, %s",
                errno, strerror(errno));
        return -errno;
    } else if (len != sizeof(msg->hdr)) {
        VHD_LOG_ERROR("recvmsg() gets less bytes = %d, than required = %lu",
                len, sizeof(msg->hdr));
        return -EIO;
    } else if (msgh.msg_flags & MSG_CTRUNC) {
        VHD_LOG_ERROR("recvmsg(): file descriptor array truncated");
        return -ENOBUFS;
    } else if (msg->hdr.size > sizeof(msg->payload)) {
        VHD_LOG_ERROR("Payload size = %d exceeds buffer size = %lu",
                msg->hdr.size, sizeof(msg->payload));
        return -EMSGSIZE;
    }

    /* Fill in file descriptors, if any. */
    for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
        if ((cmsg->cmsg_level == SOL_SOCKET) &&
            (cmsg->cmsg_type == SCM_RIGHTS)) {
            size_t fdlen = cmsg->cmsg_len - CMSG_LEN(0);
            if (fdlen / sizeof(int) < *num_fds) {
                *num_fds = fdlen / sizeof(int);
            }
            memcpy(fds, CMSG_DATA(cmsg), *num_fds * sizeof(int));
            break;
        }
    }

    /* Request payload data for the request. */
    payload_len = read(fd, &msg->payload, msg->hdr.size);
    if (payload_len < 0) {
        VHD_LOG_ERROR("Payload read failed. Error code = %d, %s",
                errno, strerror(errno));
        return -errno;
    } else if ((size_t)payload_len != msg->hdr.size) {
        VHD_LOG_ERROR("Read only part of the payload = %d, required = %d",
                payload_len, msg->hdr.size);
        return -EIO;
    }
    len += payload_len;

    return len;
}

/*
 * Send message to master. Return number of bytes sent or negative
 * error code in case of error.
 */
static int net_send_msg(int fd, const struct vhost_user_msg_hdr *hdr,
                        const void *payload, int *fds, size_t num_fds)
{
    int ret;
    struct iovec iov[] = {
        {
            .iov_base = (void *)hdr,
            .iov_len = sizeof(*hdr),
        }, {
            .iov_base = (void *)payload,
            .iov_len = hdr->size,
        }
    };
    struct msghdr msgh = {
        .msg_iov = iov,
        .msg_iovlen = 2,
    };
    union {
        char buf[CMSG_SPACE(sizeof(int) * VHOST_USER_MAX_FDS)];
        struct cmsghdr cmsg_align;
    } control;
    struct cmsghdr *cmsgh;

    if (num_fds > VHOST_USER_MAX_FDS) {
        VHD_LOG_ERROR("too many fds: %zu", num_fds);
        return -EMSGSIZE;
    }

    if (num_fds) {
        size_t fdsize = sizeof(*fds) * num_fds;
        msgh.msg_control = &control;
        msgh.msg_controllen = CMSG_SPACE(fdsize);
        cmsgh = CMSG_FIRSTHDR(&msgh);
        cmsgh->cmsg_len = CMSG_LEN(fdsize);
        cmsgh->cmsg_level = SOL_SOCKET;
        cmsgh->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsgh), fds, fdsize);
    }
    ret = sendmsg(fd, &msgh, 0);
    if (ret < 0) {
        VHD_LOG_ERROR("sendmsg() failed: %d", errno);
        return -errno;
    } else if ((unsigned)ret != (sizeof(*hdr) + hdr->size)) {
        VHD_LOG_ERROR("sendmsg() puts less bytes = %d, than required = %lu",
                ret, sizeof(*hdr) + hdr->size);
        return -EIO;
    }

    return ret;
}

/*
 * Vhost protocol handling
 */

static const uint64_t g_default_features =
    (1UL << VHOST_USER_F_PROTOCOL_FEATURES) |
    (1UL << VHOST_F_LOG_ALL);

static const uint64_t g_default_protocol_features =
    (1UL << VHOST_USER_PROTOCOL_F_MQ) |
    (1UL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |
    (1UL << VHOST_USER_PROTOCOL_F_REPLY_ACK) |
    (1UL << VHOST_USER_PROTOCOL_F_CONFIG) |
    (1UL << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD);

static inline bool has_feature(uint64_t features_qword, size_t feature_bit)
{
    return features_qword & (1ull << feature_bit);
}

static int vhost_send_fds(struct vhd_vdev *vdev,
                          const struct vhost_user_msg_hdr *hdr,
                          const void *payload,
                          int *fds, size_t num_fds)
{
    int len;

    len = net_send_msg(vdev->connfd, hdr, payload, fds, num_fds);
    if (len < 0) {
        return len;
    }

    return 0;
}

static int vhost_reply_fds(struct vhd_vdev *vdev, uint32_t req,
                           const void *payload, uint32_t len,
                           int *fds, size_t num_fds)
{
    struct vhost_user_msg_hdr hdr = {
        .req = req,
        .size = len,
        .flags = VHOST_USER_MSG_FLAGS_REPLY,
    };

    return vhost_send_fds(vdev, &hdr, payload, fds, num_fds);
}

static int vhost_reply(struct vhd_vdev *vdev, uint32_t req,
                       const void *payload, uint32_t len)
{
    return vhost_reply_fds(vdev, req, payload, len, NULL, 0);
}

static int vhost_reply_u64(struct vhd_vdev *vdev, uint32_t req, uint64_t u64)
{
    return vhost_reply(vdev, req, &u64, sizeof(u64));
}

static int vhost_send_reply(struct vhd_vdev *vdev,
                            const struct vhost_user_msg *msgin, uint64_t u64)
{
    return vhost_reply_u64(vdev, msgin->hdr.req, u64);
}

static int vhost_send_vring_base(struct vhd_vring *vring)
{
    struct vhost_user_vring_state vrstate = {
        .index = vring_idx(vring),
        .num = vring->vq.last_avail,
    };

    return vhost_reply(vring->vdev, VHOST_USER_GET_VRING_BASE,
                       &vrstate, sizeof(vrstate));
}

static int vhost_ack_request_if_needed(struct vhd_vdev *vdev,
                                       const struct vhost_user_msg *msg,
                                       int ret)
{
    /*
     * If REPLY_ACK protocol feature was not negotiated
     * then we have nothing to do
     */
    if (!has_feature(vdev->negotiated_protocol_features,
                     VHOST_USER_PROTOCOL_F_REPLY_ACK)) {
        return 0;
    }

    /* We negotiated REPLY_ACK but client does not need it for this message */
    if (!(msg->hdr.flags & VHOST_USER_MSG_FLAGS_REPLY_ACK)) {
        return 0;
    }

    /*
     * We negotiated REPLY_ACK but message already has an explicit reply
     * which was successfully sent
     */
    if (ret == 0) {
        switch (msg->hdr.req) {
        case VHOST_USER_GET_FEATURES:
        case VHOST_USER_GET_PROTOCOL_FEATURES:
        case VHOST_USER_GET_CONFIG:
        case VHOST_USER_GET_QUEUE_NUM:
        case VHOST_USER_GET_VRING_BASE:
            return 0;
        };
    }

    /* Ok, send the reply */
    return vhost_send_reply(vdev, msg, ret);
}

static int vhost_get_protocol_features(struct vhd_vdev *vdev,
                                       struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    return vhost_send_reply(vdev, msg, vdev->supported_protocol_features);
}

static int vhost_set_protocol_features(struct vhd_vdev *vdev,
                                       struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    uint64_t feats = msg->payload.u64;

    if (feats & ~vdev->supported_protocol_features) {
        /*
         * Client ignored what we've sent in get_protocol_features.
         * We don't have a good way to report this to client.
         * Log and drop unsupported
         */
        feats &= vdev->supported_protocol_features;
        VHD_LOG_WARN(
            "Client ignores supported protocol features: set 0x%llx, support 0x%llx",
            (unsigned long long) msg->payload.u64,
            (unsigned long long) vdev->supported_protocol_features);
        VHD_LOG_WARN("Will set only 0x%llx",
            (unsigned long long)feats);
    }

    vdev->negotiated_protocol_features = feats;
    VHD_LOG_DEBUG("Negotiated protocol features 0x%llx",
        (unsigned long long)feats);

    return 0;
}

static int vhost_get_features(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    vdev->supported_features = g_default_features |
                               vdev->type->get_features(vdev);

    return vhost_send_reply(vdev, msg, vdev->supported_features);
}

static void vdev_update_memlog(struct vhd_vdev *vdev)
{
    uint16_t i;
    struct vhd_memory_log *log =
        has_feature(vdev->negotiated_features, VHOST_F_LOG_ALL) ?
        vdev->memlog : NULL;

    for (i = 0; i < vdev->num_queues; i++) {
        vdev->vrings[i].vq.log = log;
    }
}

static int vhost_set_features(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    uint64_t requested_features = msg->payload.u64;

    /*
     * VHOST_USER_F_PROTOCOL_FEATURES normally doesn't need negotiation: it's just
     * offered by the slave, and then the master may use
     * VHOST_USER_[GS]ET_PROTOCOL_FEATURES to negotiate the vhost protocol features
     * without interfering with the guest-visibile virtio features.
     * There's one exception though: the master may use VHOST_USER_SET_VRING_ENABLE
     * only when VHOST_USER_F_PROTOCOL_FEATURES itself is negotiated.  (Presumably
     * that was a design fallout, it should have received its own within the
     * protocol feature mask.)
     * As we don't support VHOST_USER_SET_VRING_ENABLE, reject the master
     * connections that try to negotiate VHOST_USER_F_PROTOCOL_FEATURES, even
     * though offering it.
     */
    if (has_feature(requested_features, VHOST_USER_F_PROTOCOL_FEATURES)) {
        VHD_LOG_ERROR("Vhost doesn't expect VHOST_USER_F_PROTOCOL_FEATURES "
                      "to be negotiated");
        return -EINVAL;
    }

    vdev->negotiated_features = requested_features & vdev->supported_features;

    if (0 != (requested_features & ~vdev->supported_features)) {
        VHD_LOG_WARN("Master attempts to set device features we don't support: "
                     "supported 0x%lx, requested 0x%lx, negotiated 0x%lx",
                     vdev->supported_features,
                     requested_features,
                     vdev->negotiated_features);
    }

    vdev_update_memlog(vdev);

    return 0;
}

static int vhost_set_owner(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();
    return 0;
}

static void vhost_reset_mem_table(struct vhd_vdev *vdev)
{
    if (!vdev->memmap) {
        return;
    }

    vhd_memmap_unref(vdev->memmap);
    vdev->memmap = NULL;
}

struct set_mem_table_data {
    struct vhd_vdev *vdev;
    struct vhost_user_msg *msg;
    int *fds;
    size_t num_fds;
};

static void set_mem_table_bh(void *opaque)
{
    VHD_LOG_TRACE();

    struct set_mem_table_data *data = opaque;

    struct vhd_vdev *vdev = data->vdev;
    struct vhost_user_msg *msg = data->msg;
    int *fds = data->fds;
    size_t num_fds = data->num_fds;

    int ret = 0;
    struct vhost_user_mem_desc *desc;
    struct vhd_memory_map *mm;
    uint32_t i;

    vhd_free(data);

    vhost_reset_mem_table(vdev);

    desc = &msg->payload.mem_desc;
    if (desc->nregions > VHOST_USER_MEM_REGIONS_MAX) {
        VHD_LOG_ERROR("Invalid number of memory regions %d", desc->nregions);
        ret = -EINVAL;
        goto reply;
    }
    if (desc->nregions != num_fds) {
        VHD_LOG_ERROR("#memory regions != #fds: %u != %zu", desc->nregions,
                      num_fds);
        ret = -EINVAL;
        goto reply;
    }

    mm = vhd_memmap_new(vdev->map_cb, vdev->unmap_cb, vdev->priv);

    for (i = 0; i < desc->nregions; i++) {
        struct vhost_user_mem_region *region = &desc->regions[i];
        ret = vhd_memmap_add_slot(mm, region->guest_addr, region->user_addr,
                                  region->size, fds[i], region->mmap_offset);
        if (ret < 0) {
            vhd_memmap_unref(mm);
            goto out;
        }
    }

    vdev->memmap = mm;

    /*
     * update started rings vq-s addresses with new mapping
     */
    for (i = 0; i < vdev->num_queues; i++) {
        struct vhd_vring *vring = vdev->vrings + i;

        if (!vring->is_started) {
            continue;
        }

        ret = vring_update_vq_addrs(vring);
        if (ret) {
            break;
        }
    }
out:
    for (i = 0; i < num_fds; i++) {
        close(fds[i]);
    }
reply:
    vhost_ack_request_if_needed(vdev, msg, ret);
}

static void vhost_set_mem_table(struct vhd_vdev *vdev,
                               struct vhost_user_msg *msg,
                               int *fds, size_t num_fds)
{
    struct set_mem_table_data *data =
                               vhd_alloc(sizeof(struct set_mem_table_data));
    data->vdev = vdev;
    data->msg = msg;
    data->fds = fds;
    data->num_fds = num_fds;

    vhd_run_in_rq(vdev->rq, set_mem_table_bh, data);
}


static int vhost_get_config(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{

    struct vhost_user_config_space *config = &msg->payload.config;

    VHD_LOG_DEBUG("msg->size %d, config->size %d",
                  msg->hdr.size,
                  config->size);

    /* check that msg has enough space for requested buffer */
    if (msg->hdr.size < VHOST_CONFIG_HDR_SIZE + config->size) {
        VHD_LOG_WARN("Message size is not enough for requested data");
        config->size = msg->hdr.size - VHOST_CONFIG_HDR_SIZE;
    }

    config->size = vdev->type->get_config(vdev, config->payload,
                                          config->size, config->offset);

    /* zero-fill leftover space */
    memset(config->payload + config->size,
           0,
           msg->hdr.size - VHOST_CONFIG_HDR_SIZE - config->size);

    return vhost_reply(vdev, VHOST_USER_GET_CONFIG, config, msg->hdr.size);
}

static int vhost_get_queue_num(struct vhd_vdev *vdev,
                               struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    return vhost_send_reply(vdev, msg, vdev->num_queues);
}

static struct vhd_vring *get_vring(struct vhd_vdev *vdev, uint32_t index)
{
    if (index >= vdev->num_queues) {
        VHD_LOG_ERROR("vring index out of bounds (%d >= %d)", index,
                      vdev->num_queues);
        return NULL;
    }

    return vdev->vrings + index;
}

static struct vhd_vring *get_vring_not_started(struct vhd_vdev *vdev, int index)
{
    struct vhd_vring *vring = get_vring(vdev, index);
    if (vring && vring->is_started) {
        VHD_LOG_ERROR("vring %d is started", index);
        return NULL;
    }

    return vring;
}

static struct vhd_vring *msg_get_vring(struct vhd_vdev *vdev,
                                       struct vhost_user_msg *msg)
{
    uint8_t vring_idx = msg->payload.u64 & VHOST_VRING_IDX_MASK;
    return get_vring(vdev, vring_idx);
}

static bool msg_valid_num_fds(struct vhost_user_msg *msg, size_t num_fds)
{
    bool has_fd = !(msg->payload.u64 & VHOST_VRING_INVALID_FD);
    if (num_fds != has_fd) {
        VHD_LOG_ERROR("unexpected #fds: %zu (expected %u)", num_fds, has_fd);
        return false;
    }
    return true;
}

static int vhost_set_vring_call(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    struct vhd_vring *vring = msg_get_vring(vdev, msg);

    if (!vring || !msg_valid_num_fds(msg, num_fds)) {
        return -EINVAL;
    }

    vring->callfd = num_fds > 0 ? fds[0] : -1;
    if (vring->is_started) {
        virtq_set_notify_fd(&vring->vq, vring->callfd);
    }
    return 0;
}

static int vhost_set_vring_kick(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    struct vhd_vring *vring = msg_get_vring(vdev, msg);

    if (!vring || !msg_valid_num_fds(msg, num_fds)) {
        return -EINVAL;
    }
    if (num_fds == 0) {
        VHD_LOG_ERROR("vring polling mode is not supported");
        return -ENOTSUP;
    }

    vring->kickfd = fds[0];
    return vring_start(vring);
}

static int vhost_set_vring_err(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    struct vhd_vring *vring = msg_get_vring(vdev, msg);

    if (!vring || !msg_valid_num_fds(msg, num_fds)) {
        return -EINVAL;
    }

    vring->errfd = num_fds > 0 ? fds[0] : -1;
    return 0;
}

static int vhost_set_vring_num(struct vhd_vdev *vdev,
                               struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state *vrstate = &msg->payload.vring_state;

    struct vhd_vring *vring = get_vring_not_started(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    vring->vq.qsz = vrstate->num;
    return 0;
}

static int vhost_set_vring_base(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state *vrstate = &msg->payload.vring_state;

    struct vhd_vring *vring = get_vring_not_started(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    vring->vq.last_avail = vrstate->num;
    return 0;
}

static void vring_set_on_drain_cb(struct vhd_vring *vring,
                                  int (*on_drain_cb)(struct vhd_vring *))
{
    vring->on_drain_cb = on_drain_cb;
}

static void vring_clear_on_drain_cb(struct vhd_vring *vring)
{
    vring->on_drain_cb = NULL;
}

static int vhost_get_vring_base(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state *vrstate = &msg->payload.vring_state;

    struct vhd_vring *vring = get_vring(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    /*
     * we don't reply to the command at once but send a reply when
     * the vring is drained. qemu won't send another commands until
     * it gets the reply from this one.
     */
    vring_set_on_drain_cb(vring, vhost_send_vring_base);
    /* callback we just set will be cleared when the vring is drained */
    vring_stop(vring);
    return 0;
}

static int vhost_set_vring_addr(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_addr *vraddr = &msg->payload.vring_addr;

    struct vhd_vring *vring = get_vring(vdev, vraddr->index);
    if (!vring) {
        return EINVAL;
    }

    if (!vring->is_started) {
        vring->addr_cache.desc =  vraddr->desc_addr;
        vring->addr_cache.used = vraddr->used_addr;
        vring->addr_cache.avail = vraddr->avail_addr;
        vring->vq.flags = vraddr->flags;
        vring->vq.used_gpa_base = vraddr->used_gpa_base;
    } else {
        if (vring->addr_cache.desc != vraddr->desc_addr ||
            vring->addr_cache.used != vraddr->used_addr ||
            vring->addr_cache.avail != vraddr->avail_addr ||
            vring->vq.used_gpa_base != vraddr->used_gpa_base)
        {
            VHD_LOG_ERROR("Enabled vring %d parameters mismatch "
                          "(0x%ld, 0x%ld, 0x%ld)",
                          vraddr->index, vraddr->desc_addr, vraddr->desc_addr,
                          vraddr->desc_addr);
            return -EINVAL;
        }
        vring->vq.flags = vraddr->flags;
    }

    return 0;
}

static int vhost_set_log_base(struct vhd_vdev *vdev,
                              struct vhost_user_msg *msg,
                              int *fds,
                              size_t num_fds)
{
    struct vhd_memory_log *memlog, *old_memlog = vdev->memlog;

    VHD_LOG_TRACE();

    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return -EINVAL;
    }

    struct vhost_user_log *log = &msg->payload.log;

    memlog = vhd_memlog_new(log->size, fds[0], log->offset);
    close(fds[0]);
    if (!memlog) {
        return -EFAULT;
    }

    vdev->memlog = memlog;
    vdev_update_memlog(vdev);

    if (old_memlog) {
        vhd_memlog_free(old_memlog);
    }

    return vhost_send_reply(vdev, msg, 0);
}

static void inflight_mem_init(void *buf, size_t queue_region_size,
                              uint16_t num_queues, uint16_t queue_size)
{
    uint16_t i;

    memset(buf, 0,  num_queues * queue_region_size);
    for (i = 0; i < num_queues; i++) {
        struct inflight_split_region *region = buf + i * queue_region_size;
        region->version = 1;
        region->desc_num = queue_size;
    }
}

static int inflight_mmap_region(struct vhd_vdev *vdev, int fd,
                                size_t queue_region_size, uint16_t num_queues)
{
    size_t mmap_size = queue_region_size * num_queues;
    int ret;
    void *buf;
    uint16_t i;

    buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        ret = -errno;
        VHD_LOG_ERROR("can't mmap fd = %d, size = %lu", fd, mmap_size);
        return ret;
    }

    if (vdev->num_queues < num_queues) {
        num_queues = vdev->num_queues;
    }

    for (i = 0; i < num_queues; i++) {
        vdev->vrings[i].vq.inflight_region = buf + i * queue_region_size;
    }

    vdev->inflight_mem = buf;
    vdev->inflight_size = mmap_size;

    return 0;
}

static void vhd_vdev_inflight_cleanup(struct vhd_vdev *vdev)
{
    uint16_t i;

    if (!vdev->inflight_mem) {
        /* Nothing to clean up. */
        return;
    }

    munmap(vdev->inflight_mem, vdev->inflight_size);
    vdev->inflight_mem = NULL;

    for (i = 0; i < vdev->num_queues; i++) {
        vdev->vrings[i].vq.inflight_region = NULL;
    }
}

/* memfd_create is only present since glibc-2.27 */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC                0x0001U

static int memfd_create(const char *name, unsigned int flags)
{
    return syscall(__NR_memfd_create, name, flags);
}
#endif

static int vhost_get_inflight_fd(struct vhd_vdev *vdev,
                                 struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_inflight_desc *idesc = &msg->payload.inflight_desc;
    size_t queue_region_size = vring_inflight_buf_size(idesc->queue_size);
    size_t mmap_size = queue_region_size * idesc->num_queues;
    int fd;
    int ret;

    vhd_vdev_inflight_cleanup(vdev);

    fd = memfd_create("vhost_get_inflight_fd", MFD_CLOEXEC);
    if (fd == -1) {
        ret = -errno;
        VHD_LOG_ERROR("can't create memfd object");
        return ret;
    }
    ret = ftruncate(fd, mmap_size);
    if (ret == -1) {
        ret = -errno;
        VHD_LOG_ERROR("can't truncate fd = %d, to size = %lu", fd, mmap_size);
        goto out;
    }
    ret = inflight_mmap_region(vdev, fd, queue_region_size, idesc->num_queues);
    if (ret) {
        goto out;
    }

    inflight_mem_init(vdev->inflight_mem, queue_region_size, idesc->num_queues,
                      idesc->queue_size);

    /* Prepare reply to the master side. */
    idesc->mmap_size = vdev->inflight_size;
    idesc->mmap_offset = 0;

    ret = vhost_reply_fds(vdev, VHOST_USER_GET_INFLIGHT_FD,
                          idesc, msg->hdr.size, &fd, 1);
    if (ret) {
        VHD_LOG_ERROR("can't send reply to get_inflight_fd command");
        vhd_vdev_inflight_cleanup(vdev);
    }

out:
    close(fd);
    return ret;
}

static int vhost_set_inflight_fd(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    VHD_LOG_TRACE();

    struct vhost_user_inflight_desc *idesc = &msg->payload.inflight_desc;
    size_t queue_region_size = vring_inflight_buf_size(idesc->queue_size);
    int ret;

    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return -EINVAL;
    }

    if (idesc->mmap_offset) {
        VHD_LOG_ERROR("non-zero mmap offset: %lx", idesc->mmap_offset);
        return -EINVAL;
    }

    if (idesc->mmap_size != queue_region_size * idesc->num_queues) {
        VHD_LOG_ERROR("invalid inflight region dimensions: %zu != %zu * %u",
                      idesc->mmap_size, queue_region_size, idesc->num_queues);
        return -EINVAL;
    }

    vhd_vdev_inflight_cleanup(vdev);
    ret = inflight_mmap_region(vdev, fds[0], queue_region_size, idesc->num_queues);
    close(fds[0]);

    return ret;
}

/*
 * Return 0 in case of success, otherwise return error code.
 */
static int vhost_handle_request(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    int ret = 0;

    VHD_LOG_DEBUG("Handle command %d, flags 0x%x, size %u",
                  msg->hdr.req, msg->hdr.flags, msg->hdr.size);
    switch (msg->hdr.req) {
    case VHOST_USER_GET_FEATURES:
        ret = vhost_get_features(vdev, msg);
        break;
    case VHOST_USER_SET_FEATURES:
        ret = vhost_set_features(vdev, msg);
        break;
    case VHOST_USER_SET_OWNER:
        ret = vhost_set_owner(vdev, msg);
        break;
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        ret = vhost_get_protocol_features(vdev, msg);
        break;
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        ret = vhost_set_protocol_features(vdev, msg);
        break;
    case VHOST_USER_GET_CONFIG:
        ret = vhost_get_config(vdev, msg);
        break;
    case VHOST_USER_SET_MEM_TABLE:
        vhost_set_mem_table(vdev, msg, fds, num_fds);
        return 0;
    case VHOST_USER_GET_QUEUE_NUM:
        ret = vhost_get_queue_num(vdev, msg);
        break;
    case VHOST_USER_SET_LOG_BASE:
        ret = vhost_set_log_base(vdev, msg, fds, num_fds);
        break;
    case VHOST_USER_SET_VRING_CALL:
        ret = vhost_set_vring_call(vdev, msg, fds, num_fds);
        break;
    case VHOST_USER_SET_VRING_KICK:
        ret = vhost_set_vring_kick(vdev, msg, fds, num_fds);
        break;
    case VHOST_USER_SET_VRING_ERR:
        ret = vhost_set_vring_err(vdev, msg, fds, num_fds);
        break;
    case VHOST_USER_SET_VRING_NUM:
        ret = vhost_set_vring_num(vdev, msg);
        break;
    case VHOST_USER_SET_VRING_BASE:
        ret = vhost_set_vring_base(vdev, msg);
        break;
    case VHOST_USER_GET_VRING_BASE:
        ret = vhost_get_vring_base(vdev, msg);
        break;
    case VHOST_USER_SET_VRING_ADDR:
        ret = vhost_set_vring_addr(vdev, msg);
        break;
    case VHOST_USER_GET_INFLIGHT_FD:
        ret = vhost_get_inflight_fd(vdev, msg);
        break;
    case VHOST_USER_SET_INFLIGHT_FD:
        ret = vhost_set_inflight_fd(vdev, msg, fds, num_fds);
        break;
    default:
        VHD_LOG_WARN("Command = %d, not supported", msg->hdr.req);
        ret = -ENOTSUP;
        break;
    }

    if (ret != 0) {
        VHD_LOG_ERROR("Request %d failed with %d", msg->hdr.req, ret);
    }

    int reply_ret = vhost_ack_request_if_needed(vdev, msg, ret);
    if (reply_ret != 0) {
        /*
         * We've logged failed ret above,
         * so we are probably ok with overriding it if ack now failed as well
         */
        ret = reply_ret;
    }

    return ret;
}

struct vdev_work {
    struct vhd_vdev *vdev;
    void (*func)(struct vhd_vdev *, void *);
    void *opaque;
};

static void vdev_complete_work(struct vhd_vdev *vdev, int ret)
{
    vhd_complete_work(vdev->work, ret);
    vdev->work = NULL;
}

static void vdev_work_fn(struct vhd_work *work, void *opaque)
{
    struct vdev_work *vd_work = opaque;
    struct vhd_vdev *vdev = vd_work->vdev;

    /* allow no concurrent work */
    if (vdev->work != NULL) {
        vhd_complete_work(work, -EBUSY);
        return;
    }

    vdev->work = work;
    vd_work->func(vdev, vd_work->opaque);
}

static int vdev_submit_work_and_wait(struct vhd_vdev *vdev,
                                     void (*func)(struct vhd_vdev *, void *),
                                     void *opaque)
{
    struct vdev_work vd_work = {
        .vdev = vdev,
        .func = func,
        .opaque = opaque,
    };

    return vhd_submit_ctl_work_and_wait(vdev_work_fn, &vd_work);
}

static void vhd_vdev_stop(struct vhd_vdev *vdev)
{
    for (uint32_t i = 0; i < vdev->num_queues; ++i) {
        vhd_vring_stop(vdev->vrings + i);
    }
}

static void vhd_vdev_release(struct vhd_vdev *vdev)
{
    close(vdev->listenfd);
    close(vdev->connfd);

    vhost_reset_mem_table(vdev);
    vhd_vdev_inflight_cleanup(vdev);

    LIST_REMOVE(vdev, vdev_list);
    vhd_free(vdev->vrings);
    vdev->type->free(vdev);
}

static int server_read(void *opaque);
static int conn_read(void *opaque);

static int change_device_state(struct vhd_vdev *vdev,
                               enum vhd_vdev_state new_state)
{
    if (new_state == VDEV_LISTENING) {

        switch (vdev->state) {
        case VDEV_CONNECTED:
            /*
             * We're terminating existing connection
             * and going back to listen mode
             */
            vhd_del_io_handler(vdev->conn_handler);

            vhd_vdev_stop(vdev);

            vhost_reset_mem_table(vdev);
            if (vdev->memlog) {
                vhd_memlog_free(vdev->memlog);
                vdev->memlog = NULL;
            }

            close(vdev->connfd);
            vdev->connfd = -1; /* Not nessesary, just defensive */
            /* Fall thru */

        case VDEV_INITIALIZED:
            /* Normal listening init */
            vdev->listen_handler = vhd_add_vhost_io_handler(vdev->listenfd,
                                                            server_read, vdev);
            if (!vdev->listen_handler) {
                return -EIO;
            }

            break;
        default:
            goto invalid_transition;
        };

    } else if (new_state == VDEV_CONNECTED) {

        switch (vdev->state) {
        case VDEV_LISTENING:
            /* Establish new connection and exiting listen-mode */
            vdev->conn_handler = vhd_add_vhost_io_handler(vdev->connfd,
                                                          conn_read, vdev);
            if (!vdev->conn_handler) {
                return -EIO;
            }

            /*
             * Remove server fd from event loop.
             * We don't want multiple clients
             */
            vhd_del_io_handler(vdev->listen_handler);
            break;
        default:
            goto invalid_transition;
        };

    } else if (new_state == VDEV_TERMINATING) {

        switch (vdev->state) {
        case VDEV_LISTENING:
            vhd_del_io_handler(vdev->listen_handler);
            break;
        case VDEV_CONNECTED:
            vhd_del_io_handler(vdev->conn_handler);
            break;
        case VDEV_INITIALIZED:
            break;
        default:
            goto invalid_transition;
        };

    } else {
        goto invalid_transition;
    }

    VHD_LOG_DEBUG("changing state from %d to %d", vdev->state, new_state);
    vdev->state = new_state;

    return 0;

invalid_transition:
    VHD_LOG_ERROR("invalid state transition from %d to %d",
                  vdev->state, new_state);
    return -EINVAL;
}

/*
 * Accept connection and add the client socket to the IO polling.
 * Will close server socket on first connection since we're only support
 * 1 active master.
 */
static int server_read(void *data)
{
    int flags;
    int connfd;
    struct vhd_vdev *vdev = (struct vhd_vdev *)data;

    connfd = accept(vdev->listenfd, NULL, NULL);
    if (connfd == -1) {
        VHD_LOG_ERROR("accept() failed: %d", errno);
        return 0;
    }

    flags = fcntl(connfd, F_GETFL, 0);
    if (flags < 0) {
        VHD_LOG_ERROR("fcntl on client socket failed: %d", errno);
        goto close_client;
    }

    if (fcntl(connfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        VHD_LOG_ERROR("Can't set O_NONBLOCK mode on the client socket: %d",
                      errno);
        goto close_client;
    }

    vdev->connfd = connfd;
    if (change_device_state(vdev, VDEV_CONNECTED)) {
        goto close_client;
    }

    VHD_LOG_INFO("Connection established, sock = %d", connfd);
    return 0;

close_client:
    close(connfd);
    return 0;
}

static int conn_read(void *data)
{
    struct vhost_user_msg msg;
    int fds[VHOST_USER_MAX_FDS];
    size_t num_fds = VHOST_USER_MAX_FDS;
    struct vhd_vdev *vdev = data;

    if (net_recv_msg(vdev->connfd, &msg, fds, &num_fds) <= 0) {
        goto err_out;
    }

    if (vhost_handle_request(vdev, &msg, fds, num_fds)) {
        goto err_out;
    }

    return 0;
err_out:
    VHD_LOG_DEBUG("Close connection with client, sock = %d",
                  vdev->connfd);

    change_device_state(vdev, VDEV_LISTENING);
    return 0;
}

/*
 * Prepare the sock path for the server. Return 0 if the requested path
 * can be used for the bind() and listen() calls. In case of error, return
 * error code.
 * Note that if the file with such path exists and it is socket, then it
 * will be unlinked.
 */
static int prepare_server_sock_path(const char *path)
{
    struct stat buf;

    if (stat(path, &buf) == -1) {
        if (errno == ENOENT) {
            return 0;
        } else {
            return errno;
        }
    }

    if (!S_ISSOCK(buf.st_mode)) {
        return EINVAL;
    }

    if (unlink(path) == -1) {
        return errno;
    }

    return 0;
}

/* TODO: properly destroy server on close */
static int sock_create_server(const char *path)
{
    int fd;
    int flags;
    int ret;
    struct sockaddr_un sockaddr;

    if (strlen(path) >= sizeof(sockaddr.sun_path)) {
        VHD_LOG_ERROR(
            "Path = %s to socket is too long, it should be less than %lu",
            path, sizeof(sockaddr.sun_path));
        return -1;
    }

    ret = prepare_server_sock_path(path);
    if (ret) {
        VHD_LOG_ERROR(
            "Sock path = %s, is busy or can't be unlinked. Error code = %d, %s",
            path, ret, strerror(ret));
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        VHD_LOG_ERROR("Can't create socket");
        return -1;
    }

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sun_family = AF_UNIX;
    strncpy(sockaddr.sun_path, path, sizeof(sockaddr.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        VHD_LOG_ERROR("Can't bind socket to path = %s", path);
        goto close_fd;
    }

    if (listen(fd, 1) < 0) {
        VHD_LOG_ERROR("Can't listen for the incoming connections");
        goto close_fd;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        VHD_LOG_ERROR("Can't get flags for a file = %s", path);
        goto close_fd;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        VHD_LOG_ERROR("Can't set O_NONBLOCK mode on the server socket");
        goto close_fd;
    }

    return fd;

close_fd:
    close(fd);
    return -1;
}

static void vdev_ref(struct vhd_vdev *vdev)
{
    atomic_inc(&vdev->refcount);
}

static void vdev_unref(struct vhd_vdev *vdev)
{
    unsigned int val = atomic_fetch_dec(&vdev->refcount);
    VHD_ASSERT(val);
    /* check refcount drops to 0 */
    if (val == 1) {
        if (vdev->unregister_cb) {
            vdev->unregister_cb(vdev->unregister_arg);
        }
        vhd_vdev_release(vdev);
    }
}

/*
 * We use two different types of refcounters for device:
 *  - per-vring refcounter
 *  - per-device refcounter
 * Per-vring refcounter counts active requests for its vring, also
 * it does ref vring when it's started and does unref vring when its stoppedd.
 * Vring does ref for each request as soon as it's consumed from
 * virtio vitqueue and unref when the request completion has processed.
 *
 * When per-vring refcounter drops to 0 it calls darin callback if set.
 * The vring refcounter drops to 0 only when there're no active requests and
 *    vring is DISABLED.
 * Another words, to make a vring call the drain callback
 * one needs to stop vring and let it wait for all its active requests
 * send their completions. In this case, after the last completion vring does
 * unref which calls the vring drain callback.
 * Vring draining is based on vring refcounting (see vhost_get_vring_base).
 *
 * Per-device refcounter counts sum of started vrings. It is initialized with 1
 * and does unref on vdev stopping.
 * When per-device refcounter drops to 0 it calls its special callback (if set)
 * This notification may happen:
 *     - on the last device request completion
 *     - on the last vring disabling if there were no in-flight reuests
 *     - on the device unref if there were no started vrings
 * Device stopping is based on vdev refcounting (see vhd_vdev_stop_server)
 */

/* called from vdev's request queue */
void vhd_vring_ref(struct vhd_vring *vring)
{
    vring->refcount++;
}

/* called from vdev's request queue */
void vhd_vring_unref(struct vhd_vring *vring)
{
    vring->refcount--;

    /*
     * vring->refcount == 0 only when we unref-ed vring
     * for disabling
     */
    if (!vring->refcount) {
        if (vring->on_drain_cb) {
            vring->on_drain_cb(vring);
            vring_clear_on_drain_cb(vring);
        }
        virtio_virtq_release(&vring->vq);
        /*
         * unref vdev on vring disabling
         * this pairs with dev_ref in vring_start
         */
        vdev_unref(vring->vdev);
    }
}

static void vdev_unregister_bh(void *opaque)
{
    struct vhd_vdev *vdev = opaque;

    vdev_unref(vdev);
}

int vhd_vdev_init_server(
    struct vhd_vdev *vdev,
    const char *socket_path,
    const struct vhd_vdev_type *type,
    int max_queues,
    struct vhd_request_queue *rq,
    void *priv,
    int (*map_cb)(void *addr, size_t len, void *priv),
    int (*unmap_cb)(void *addr, size_t len, void *priv))
{
    int ret;
    int listenfd;
    uint16_t i;

    /*
     * The spec is unclear about the maximum number of queues allowed, using
     * different types for the vring index in different messages.  The most
     * limiting appear to VHOST_USER_SET_VRING_{CALL,ERR,KICK}, which allow
     * only 8 bits for the vring index.
     */
    if (max_queues > VHOST_VRING_IDX_MASK + 1) {
        VHD_LOG_ERROR("%d queues is too many", max_queues);
        return -1;
    }

    listenfd = sock_create_server(socket_path);
    if (listenfd < 0) {
        return -1;
    }

    *vdev = (struct vhd_vdev) {
        .priv = priv,
        .type = type,
        .listenfd = listenfd,
        .connfd = -1,
        .rq = rq,
        .map_cb = map_cb,
        .unmap_cb = unmap_cb,
        .supported_protocol_features = g_default_protocol_features,
        .num_queues = max_queues,
        .refcount = 1,
        .state = VDEV_INITIALIZED,
    };

    vdev->vrings = vhd_calloc(vdev->num_queues, sizeof(vdev->vrings[0]));
    for (i = 0; i < vdev->num_queues; i++) {
        vdev->vrings[i].vdev = vdev;
    }

    LIST_INSERT_HEAD(&g_vdevs, vdev, vdev_list);

    ret = change_device_state(vdev, VDEV_LISTENING);
    if (ret != 0) {
        vhd_vdev_release(vdev);
    }

    return ret;
}

struct vdev_stop_work {
    void (*cb)(void *);
    void *opaque;
};

static void vdev_stop(struct vhd_vdev *vdev, void *opaque)
{
    struct vdev_stop_work *work = opaque;

    vdev->unregister_cb = work->cb;
    vdev->unregister_arg = work->opaque;

    change_device_state(vdev, VDEV_TERMINATING);
    vhd_vdev_stop(vdev);

    vdev_complete_work(vdev, 0);
    vhd_run_in_rq(vdev->rq, vdev_unregister_bh, vdev);
}

int vhd_vdev_stop_server(struct vhd_vdev *vdev,
                         void (*unregister_complete)(void *), void *arg)
{
    int ret;
    struct vdev_stop_work work = {
        .cb = unregister_complete,
        .opaque = arg
    };

    ret = vdev_submit_work_and_wait(vdev, vdev_stop, &work);
    if (ret < 0) {
        VHD_LOG_ERROR("%s", strerror(-ret));
    }
    return ret;
}

void *vhd_vdev_get_priv(struct vhd_vdev *vdev)
{
    return vdev->priv;
}

/**
 * metrics - output parameter.
 * Returns 0 on success, -errno on failure
 */
int vhd_vdev_get_queue_stat(struct vhd_vdev *vdev, uint32_t queue_num,
                            struct vhd_vq_metrics *metrics)
{
    if (queue_num >= vdev->num_queues) {
        return -EINVAL;
    }

    virtio_virtq_get_stat(&vdev->vrings[queue_num].vq, metrics);

    return 0;
}
