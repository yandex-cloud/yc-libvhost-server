#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdatomic.h>

#include "vhost-server/platform.h"
#include "vhost-server/event.h"
#include "vhost-server/vdev.h"
#include "vhost-server/virt_queue.h"
#include "vhost-server/server.h"

static LIST_HEAD(, vhd_vdev) g_vdevs = LIST_HEAD_INITIALIZER(g_vdevs);

////////////////////////////////////////////////////////////////////////////////

static int server_read(void* sock);
static int server_close(void* sock);

/*
 * Event callbacks for vhost vdev listen socket
 */
static const struct vhd_event_ops g_server_sock_ops = {
    .read = server_read,
    .close = server_close,
};

static int conn_read(void* data);
static int conn_close(void* data);

/*
 * Event callbacks for vhost vdev client connection
 */
static const struct vhd_event_ops g_conn_sock_ops = {
    .read = conn_read,
    .close = conn_close
};

/* Receive and store the message from the socket. Fill in the file
 * descriptor array. Also update the fdn argument with the number
 * of the file descriptors received. Return number of bytes received or
 * negative error code in case of error.
 */
static int net_recv_msg(int fd, struct vhost_user_msg *msg,
        int *fds, int *fdn)
{
    struct msghdr msgh;
    struct iovec iov;
    int len;
    int payload_len;
    int num;
    char control[CMSG_SPACE(sizeof(int) * VHOST_USER_MEM_REGIONS_MAX)];
    struct cmsghdr *cmsg;

    /* Receive header for new request. */
    iov.iov_base = msg;
    iov.iov_len = VHOST_MSG_HDR_SIZE;
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);
    len = recvmsg(fd, &msgh, 0);
    if (len < 0) {
        VHD_LOG_ERROR("recvmsg() failed. Error code = %d, %s",
                errno, strerror(errno));
        return -errno;
    } else if (len != VHOST_MSG_HDR_SIZE) {
        VHD_LOG_ERROR("recvmsg() gets less bytes = %d, than required = %lu",
                len, VHOST_MSG_HDR_SIZE);
        return -EIO;
    }

    /* Fill in file descriptors, if any. */
    *fdn = 0;
    num = msgh.msg_controllen / CMSG_SPACE(sizeof(int));
    cmsg = CMSG_FIRSTHDR(&msgh);
    while (cmsg) {
        if ((cmsg->cmsg_level == SOL_SOCKET) &&
                (cmsg->cmsg_type == SCM_RIGHTS)) {
            memcpy(fds, CMSG_DATA(cmsg), num * sizeof(int));
            *fdn = num;
            break;
        }
    }

    /* Request payload data for the request. */
    payload_len = read(fd, &msg->payload, msg->size);
    if (payload_len < 0) {
        VHD_LOG_ERROR("Payload read failed. Error code = %d, %s",
                errno, strerror(errno));
        return -errno;
    } else if (payload_len != msg->size) {
        VHD_LOG_ERROR("Read only part of the payload = %d, required = %d",
                payload_len, msg->size);
        return -EIO;
    }
    len += payload_len;

    return len;
}

/* Send message to master. Return number of bytes sent or negative
 * error code in case of error.
 */
static int net_send_msg(int fd, const struct vhost_user_msg *msg)
{
    struct msghdr msgh;
    struct iovec iov;
    int len;

    iov.iov_base = (void*)msg;
    iov.iov_len = VHOST_MSG_HDR_SIZE + msg->size;
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = NULL;
    msgh.msg_controllen = 0;
    len = sendmsg(fd, &msgh, 0);
    if (len < 0) {
        VHD_LOG_ERROR("sendmsg() failed: %d", errno);
        return -errno;
    } else if (len != (VHOST_MSG_HDR_SIZE + msg->size)) {
        VHD_LOG_ERROR("sendmsg() puts less bytes = %d, than required = %lu",
                len, VHOST_MSG_HDR_SIZE + msg->size);
        return -EIO;
    }

    return len;
}

////////////////////////////////////////////////////////////////////////////////

/*
 * Memory mappings
 * TODO: Ad-hoc
 */

/* Map guest memory region to the vhost server. Return mapped address
 * in case of success, otherwise return (uint64_t)-1. In case of error
 * the errorCode argument will store the error code.
 */
static int map_guest_region(
    struct vhd_guest_memory_map* memmap,
    int index,
    vhd_paddr_t guest_addr,
    vhd_uaddr_t user_addr,
    uint64_t size,
    uint64_t offset,
    int fd)
{
    struct vhd_guest_memory_region* region;
    void* vaddr;

    VHD_VERIFY(memmap);

    if (index >= VHOST_USER_MEM_REGIONS_MAX) {
        VHD_LOG_ERROR("Memory index = %u, should be between 0 and %d",
                index, VHOST_USER_MEM_REGIONS_MAX);
        return EINVAL;
    }

    if (!VHD_IS_ALIGNED(size, PAGE_SIZE)) {
        return EINVAL;
    }

    if (!VHD_IS_ALIGNED(offset, PAGE_SIZE)) {
        return EINVAL;
    }

    region = &memmap->regions[index];
    if (region->hva != NULL) {
        VHD_LOG_ERROR("Region %d already mapped to %p", index, region->hva);
        return EBUSY;
    }


    vaddr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (vaddr == MAP_FAILED) {
        VHD_LOG_ERROR("Can't mmap guest memory: %d", errno);
        return errno;
    }

    region->fd = fd;
    region->hva = vaddr;
    region->gpa = guest_addr;
    region->uva = user_addr;
    region->pages = size / PAGE_SIZE;

    VHD_LOG_DEBUG("Guest region %d mapped to %p, gpa 0x%llx, pages %lu",
        index, region->hva, (unsigned long long)region->gpa, (unsigned long)region->pages);

    return 0;
}

static bool is_region_mapped(struct vhd_guest_memory_region* reg)
{
    return reg->hva != NULL;
}

static size_t region_size_bytes(struct vhd_guest_memory_region* reg)
{
    return (size_t)reg->pages << PAGE_SHIFT;
}

static void unmap_guest_region(struct vhd_guest_memory_region* reg)
{
    int ret;

    VHD_VERIFY(reg);

    if (!is_region_mapped(reg)) {
        return;
    }

    ret = munmap(reg->hva, reg->pages * PAGE_SIZE);
    if (ret != 0) {
        VHD_LOG_ERROR("failed to unmap guest region at %p\n", reg->hva);
    }

    close(reg->fd);

    memset(reg, 0, sizeof(*reg));
}

void vhd_guest_memory_unmap(struct vhd_guest_memory_map* map, int region_idx)
{
    VHD_VERIFY(map);
    VHD_VERIFY(region_idx < VHOST_USER_MEM_REGIONS_MAX);

    unmap_guest_region(&map->regions[region_idx]);
}

void vhd_guest_memory_unmap_all(struct vhd_guest_memory_map* map)
{
    VHD_VERIFY(map);

    for (int i = 0; i < VHOST_USER_MEM_REGIONS_MAX; ++i) {
        unmap_guest_region(&map->regions[i]);
    }
}

/* Convert host emulator address to the current mmap address.
 * Return mmap address in case of success or NULL.
 */
static void* map_uva(struct vhd_guest_memory_map* map, vhd_uaddr_t uva)
{
    for (int i = 0; i < VHOST_USER_MEM_REGIONS_MAX; i++) {
        struct vhd_guest_memory_region* reg = &map->regions[i];
        if (is_region_mapped(reg)
            && uva >= reg->uva
            && uva - reg->uva < region_size_bytes(reg)) {
            return (void*)((uintptr_t)reg->hva + (uva - reg->uva));
        }
    }

    return NULL;
}

static void* map_gpa_len(struct vhd_guest_memory_map* map, vhd_paddr_t gpa, uint32_t len)
{
    if (len == 0) {
        return NULL;
    }

    /* TODO: sanitize for overflow */
    vhd_paddr_t last_gpa = gpa + len - 1;

    for (int i = 0; i < VHOST_USER_MEM_REGIONS_MAX; i++) {
        struct vhd_guest_memory_region* reg = &map->regions[i];
        if (is_region_mapped(reg)
            && gpa >= reg->gpa
            && gpa - reg->gpa < region_size_bytes(reg))
        {
            /* Check that length fits in a single region.
             *
             * TODO: should we handle gpa areas that cross region boundaries
             *       but are otherwise valid? */
            if (last_gpa - reg->gpa >= region_size_bytes(reg)) {
                return NULL;
            }

            return (void*)((uintptr_t)reg->hva + (gpa - reg->gpa));
        }
    }

    return NULL;
}

void* virtio_map_guest_phys_range(struct virtio_mm_ctx* mm, uint64_t gpa, uint32_t len)
{
    return map_gpa_len((struct vhd_guest_memory_map*)mm, gpa, len);
}

////////////////////////////////////////////////////////////////////////////////

/*
 * Vhost protocol handling
 */

static const uint64_t g_default_device_features = 
    (1UL << VHOST_USER_F_PROTOCOL_FEATURES);

static const uint64_t g_default_protocol_features =
    (1UL << VHOST_USER_PROTOCOL_F_MQ) |
    (1UL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |
    (1UL << VHOST_USER_PROTOCOL_F_REPLY_ACK) |
    (1UL << VHOST_USER_PROTOCOL_F_CONFIG);

static int vring_io_event(void* ctx);
static int vring_close_event(void* ctx);

static int vhost_send(struct vhd_vdev* vdev, const struct vhost_user_msg *msg)
{
    int len = net_send_msg(vdev->connfd, msg);
    if (len < 0) {
        return len;
    } else {
        VHD_ASSERT(len == VHOST_MSG_HDR_SIZE + msg->size);
        return 0;
    }
}

static int vhost_send_reply(struct vhd_vdev* vdev, const struct vhost_user_msg* msgin, uint64_t u64)
{
    struct vhost_user_msg reply;
    reply.req = msgin->req;
    reply.size = sizeof(u64);
    reply.flags = VHOST_USER_MSG_FLAGS_REPLY;
    reply.payload.u64 = u64;

    return vhost_send(vdev, &reply);
}

static int vhost_get_protocol_features(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    return vhost_send_reply(vdev, msg, vdev->supported_protocol_features);
}

static int vhost_set_protocol_features(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    uint64_t feats = msg->payload.u64;

    if (feats & ~vdev->supported_protocol_features) {
        /*
         * Client ignored what we've sent in get_protocol_features.
         * We don't have a good way to report this to client. Log and drop unsupported
         */
        feats &= vdev->supported_protocol_features;
        VHD_LOG_WARN("Client ignores supported protocol features: set 0x%llx, support 0x%llx",
            (unsigned long long) msg->payload.u64,
            (unsigned long long) vdev->supported_protocol_features);
        VHD_LOG_WARN("Will set only 0x%llx",
            (unsigned long long)feats);
    }

    vdev->negotiated_protocol_features = feats;
    VHD_LOG_DEBUG("Negotiated protocol features 0x%llx", (unsigned long long)feats);

    return 0;
}

static int vhost_get_features(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    uint64_t features = g_default_device_features | vhd_vdev_get_features(vdev);
    return vhost_send_reply(vdev, msg, features);
}

static int vhost_set_features(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    if (!(msg->payload.u64 & VHOST_USER_F_PROTOCOL_FEATURES)) {
        VHD_LOG_ERROR("We don't support clients that can't negotiate protocol features");
        return ENOTSUP;
    }

    /* Devices don't know about VHOST_USER_F_PROTOCOL_FEATURES */
    uint64_t feats = msg->payload.u64 & ~VHOST_USER_F_PROTOCOL_FEATURES;
    return vhd_vdev_set_features(vdev, feats);
}

static int vhost_set_owner(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    /* We don't support changing session owner */
    if (vdev->is_owned) {
        VHD_LOG_WARN("Client attempts to set owner a second time, ignoring");
    }

    vdev->is_owned = true;
    return 0;
}

static int vhost_reset_owner(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    /* This is no longer used in vhost-spec spec so we don't support it either */
    return ENOTSUP;
}

static int vhost_set_mem_table(struct vhd_vdev* vdev, struct vhost_user_msg* msg, int* fds, size_t fdn)
{
    VHD_LOG_TRACE();

    int error = 0;
    struct vhost_user_mem_desc *desc;

    desc = &msg->payload.mem_desc;
    if (fdn != desc->nregions || desc->nregions > VHOST_USER_MEM_REGIONS_MAX) {
        VHD_LOG_ERROR("Invalid number if memory regions %d", desc->nregions);
        return EINVAL;
    }

    for (int i = 0; i < desc->nregions; i++) {
        struct vhost_user_mem_region *region = &desc->regions[i];
        error = map_guest_region(
                    &vdev->guest_memmap, i,
                    region->guest_addr, region->user_addr,
                    region->size, region->mmap_offset,
                    fds[i]);
        if (error) {
            /* Close all fds that were left unprocessed.
             * Already mapped will be handled by unmap_all */
            for (; i < fdn; ++i) {
                close(fds[i]);
            }

            goto error_unmap;
        }
    }

    return 0;

error_unmap:
    vhd_guest_memory_unmap_all(&vdev->guest_memmap);
    return error;
}

static int vhost_get_config(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_config_space *config;

    config = &msg->payload.config;
    config->size = vhd_vdev_get_config(vdev, config->payload, config->size);

    msg->flags = VHOST_USER_MSG_FLAGS_REPLY;
    msg->size = sizeof(*config) - sizeof(config->payload) + config->size;
    return vhost_send(vdev, msg);
}

static int vhost_set_config(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    /* TODO */
    return ENOTSUP;
}

static int vhost_get_queue_num(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    return vhost_send_reply(vdev, msg, vdev->max_queues);
}

static struct vhd_vring* get_vring(struct vhd_vdev* vdev, uint32_t index)
{
    if (index >= vdev->num_queues) {
        VHD_LOG_ERROR("vring index out of bounds (%d >= %d)", index, vdev->num_queues);
        return NULL;
    }

    return vdev->vrings + index;
}

static struct vhd_vring* get_vring_not_enabled(struct vhd_vdev* vdev, int index)
{
    struct vhd_vring* vring = get_vring(vdev, index);
    if (vring && vring->is_enabled) {
        VHD_LOG_ERROR("vring %d is enabled", index);
        return NULL;
    }

    return vring;
}

enum vring_desc_type { VRING_KICKFD, VRING_CALLFD, VRING_ERRFD };

static int vhost_set_vring_fd_common(struct vhd_vdev* vdev, struct vhost_user_msg* msg, int* fds, int fdn, enum vring_desc_type type)
{
    VHD_LOG_DEBUG("payload = 0x%llx\n", (unsigned long long) msg->payload.u64);

    uint8_t vring_idx = msg->payload.u64 & VHOST_VRING_IDX_MASK;
    bool has_fd = (msg->payload.u64 & VHOST_VRING_INVALID_FD) == 0;

    if (!has_fd) {
        VHD_LOG_ERROR("vring polling mode is not supported");
        return ENOTSUP;
    }

    if (fdn != 1) {
        VHD_LOG_ERROR("incorrect number of descriptors in auxillary data (%d)", fdn);
        return EINVAL;
    }

    struct vhd_vring* vring = get_vring(vdev, vring_idx);
    if (!vring) {
        return EINVAL;
    }

    switch (type) {
    case VRING_KICKFD: vring->kickfd = fds[0]; break;
    case VRING_CALLFD: vring->callfd = fds[0]; break;
    case VRING_ERRFD:  vring->errfd = fds[0];  break;
    default: VHD_ASSERT(0);
    }

    return 0;
}

static int vhost_set_vring_call(struct vhd_vdev* vdev, struct vhost_user_msg* msg, int* fds, int fdn)
{
    VHD_LOG_DEBUG("payload = 0x%llx", (unsigned long long)msg->payload.u64);
    return vhost_set_vring_fd_common(vdev, msg, fds, fdn, VRING_CALLFD);
}

static int vhost_set_vring_kick(struct vhd_vdev* vdev, struct vhost_user_msg* msg, int* fds, int fdn)
{
    VHD_LOG_DEBUG("payload = 0x%llx", (unsigned long long)msg->payload.u64);
    return vhost_set_vring_fd_common(vdev, msg, fds, fdn, VRING_KICKFD);
}

static int vhost_set_vring_err(struct vhd_vdev* vdev, struct vhost_user_msg* msg, int* fds, int fdn)
{
    VHD_LOG_DEBUG("payload = 0x%llx", (unsigned long long)msg->payload.u64);
    return vhost_set_vring_fd_common(vdev, msg, fds, fdn, VRING_ERRFD);
}

static int vhost_set_vring_num(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state* vrstate = &msg->payload.vring_state;

    struct vhd_vring* vring = get_vring_not_enabled(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    vring->client_info.num = vrstate->num;
    return 0;
}

static int vhost_set_vring_base(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state* vrstate = &msg->payload.vring_state;

    struct vhd_vring* vring = get_vring_not_enabled(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    vring->client_info.base = vrstate->num;
    return 0;
}

static int vhost_get_vring_base(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state* vrstate = &msg->payload.vring_state;

    struct vhd_vring* vring = get_vring(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    return vring->vq.last_avail;
}

static int vhost_set_vring_addr(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_addr* vraddr = &msg->payload.vring_addr;

    struct vhd_vring* vring = get_vring_not_enabled(vdev, vraddr->index);
    if (!vring) {
        return EINVAL;
    }

    /* TODO: we don't have to do full lookup 3 times, we can do it in 1 */
    void* desc_addr = map_uva(&vdev->guest_memmap, vraddr->desc_addr);
    void* used_addr = map_uva(&vdev->guest_memmap, vraddr->used_addr);
    void* avail_addr = map_uva(&vdev->guest_memmap, vraddr->avail_addr);
    /* TODO: log_addr */

    if (!desc_addr || !used_addr || !avail_addr) {
        VHD_LOG_ERROR("invalid vring component address (%p, %p, %p)",
            desc_addr, used_addr, avail_addr);
        return EINVAL;
    }

    vring->client_info.desc_addr = desc_addr;
    vring->client_info.used_addr = used_addr;
    vring->client_info.avail_addr = avail_addr;

    return 0;
}

static int vhost_set_vring_enable(struct vhd_vdev* vdev, struct vhost_user_msg* msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state* vrstate = &msg->payload.vring_state;
    struct vhd_vring* vring = get_vring(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    if (vrstate->num == 1 && !vring->is_enabled) {
        int res = virtio_virtq_attach(&vring->vq,
                                      vring->client_info.desc_addr,
                                      vring->client_info.avail_addr,
                                      vring->client_info.used_addr,
                                      vring->client_info.num,
                                      vring->client_info.base,
                                      vring->callfd);
        if (res != 0) {
            VHD_LOG_ERROR("virtq attach failed: %d", res);
            return res;
        }

        static const struct vhd_event_ops g_vring_ops = {
            .read = vring_io_event,
            .close = vring_close_event,
        };

        vring->kickev.priv = vring;
        vring->kickev.ops = &g_vring_ops;
        res = vhd_attach_event(vdev->rq, vring->kickfd, &vring->kickev);
        if (res != 0) {
            VHD_LOG_ERROR("Could not create vring event from kickfd: %d", res);
            virtio_virtq_release(&vring->vq);
            return res;
        }

        vring->is_enabled = true;
    } else if (vrstate->num == 0 && vring->is_enabled) {
        vhd_detach_event(vdev->rq, vring->kickfd);
        virtio_virtq_release(&vring->vq);
        vring->is_enabled = false;
    } else {
        VHD_LOG_WARN("strange VRING_ENABLE call from client (vring is already %s)",
            vring->is_enabled ? "enabled" : "disabled");
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static int vhost_ack_request_if_needed(struct vhd_vdev* vdev, const struct vhost_user_msg* msg, int ret)
{
    /* If REPLY_ACK protocol feature was not negotiated then we have nothing to do */
    if (!(vdev->negotiated_protocol_features & VHOST_USER_PROTOCOL_F_REPLY_ACK)) {
        return 0;
    }

    /* We negotiated REPLY_ACK but client does not need it for this message */
    if (!(msg->flags & VHOST_USER_MSG_FLAGS_REPLY_ACK)) {
        return 0;
    }

    return vhost_send_reply(vdev, msg, ret);
}

/* 
 * Return 0 in case of success, otherwise return error code.
 */
static int vhost_handle_request(struct vhd_vdev* vdev, struct vhost_user_msg *msg, int *fds, size_t fdn)
{
    int ret;

    VHD_ASSERT(msg);

    ret = 0;
    VHD_LOG_DEBUG("Handle command %d, flags 0x%x, size %u", msg->req, msg->flags, msg->size);
    switch (msg->req) {
        case VHOST_USER_GET_FEATURES:
            ret = vhost_get_features(vdev, msg);
            break;
        case VHOST_USER_SET_FEATURES:
            ret = vhost_set_features(vdev, msg);
            break;
        case VHOST_USER_SET_OWNER:
            ret = vhost_set_owner(vdev, msg);
            break;
        case VHOST_USER_RESET_OWNER:
            ret = vhost_reset_owner(vdev, msg);
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
        case VHOST_USER_SET_CONFIG:
            ret = vhost_set_config(vdev, msg);
            break;
        case VHOST_USER_SET_MEM_TABLE:
            ret = vhost_set_mem_table(vdev, msg, fds, fdn);
            break;
        case VHOST_USER_GET_QUEUE_NUM:
            ret = vhost_get_queue_num(vdev, msg);
            break;

        /*
         * vrings
         */

        case VHOST_USER_SET_VRING_CALL:
            ret = vhost_set_vring_call(vdev, msg, fds, fdn);
            break;
        case VHOST_USER_SET_VRING_KICK:
            ret = vhost_set_vring_kick(vdev, msg, fds, fdn);
            break;
        case VHOST_USER_SET_VRING_ERR:
            ret = vhost_set_vring_err(vdev, msg, fds, fdn);
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
        case VHOST_USER_SET_VRING_ENABLE:
            ret = vhost_set_vring_enable(vdev, msg);
            break;

        /*
         * TODO
         */

        case VHOST_USER_SET_LOG_BASE:
        case VHOST_USER_SET_LOG_FD:
        case VHOST_USER_SEND_RARP:
        case VHOST_USER_NET_SET_MTU:
        case VHOST_USER_SET_SLAVE_REQ_FD:
        case VHOST_USER_IOTLB_MSG:
        case VHOST_USER_SET_VRING_ENDIAN:
        case VHOST_USER_CREATE_CRYPTO_SESSION:
        case VHOST_USER_CLOSE_CRYPTO_SESSION:
        case VHOST_USER_POSTCOPY_ADVISE:
        case VHOST_USER_POSTCOPY_LISTEN:
        case VHOST_USER_POSTCOPY_END:
            ret = vhost_send_reply(vdev, msg, ENOTSUP);
            VHD_LOG_WARN("Command = %d, not supported", msg->req);
            VHD_ASSERT(0);
            break;
        case VHOST_USER_NONE:
        default:
            ret = vhost_send_reply(vdev, msg, EINVAL);
            VHD_LOG_ERROR("Command = %d, not defined", msg->req);
            VHD_ASSERT(0);
            break;
    }

    if (ret != 0) {
        VHD_LOG_ERROR("Request %d failed with %d", msg->req, ret);
    }

    int reply_ret = vhost_ack_request_if_needed(vdev, msg, ret);
    if (reply_ret != 0) {
        /* We've logged failed ret above,
         * so we are probably ok with overriding it if ack now failed as well */
        ret = reply_ret;
    }

    VHD_LOG_DEBUG("Handle command: %d", ret);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////

static int change_device_state(struct vhd_vdev* vdev, enum vhd_vdev_state new_state)
{
    int ret = 0;

    if (new_state == VDEV_LISTENING) {

        switch (vdev->state) {
        case VDEV_CONNECTED:
            /* We're terminating existing connection and going back to listen mode */
            vhd_del_vhost_event(vdev->connfd);
            close(vdev->connfd);
            vdev->connfd = -1; /* Not nessesary, just defensive */
            /* Fall thru */

        case VDEV_INITIALIZED:
            /* Normal listening init */
            ret = vhd_add_vhost_event(vdev->listenfd, vdev, &g_server_sock_ops, &vdev->sock_ev);
            if (ret != 0) {
                return ret;
            }

            break;
        default:
            goto invalid_transition;
        };

    } else if (new_state == VDEV_CONNECTED) {

        switch (vdev->state) {
        case VDEV_LISTENING:
            /* Establish new connection and exiting listen-mode */
            ret = vhd_add_vhost_event(vdev->connfd, vdev, &g_conn_sock_ops, &vdev->sock_ev);
            if (ret != 0) {
                return ret;
            }

            /* Remove server fd from event loop. We don't want multiple clients */
            vhd_del_vhost_event(vdev->listenfd);
            break;
        default:
            goto invalid_transition;
        };

    } else {
        goto invalid_transition;
    }

    VHD_ASSERT(ret == 0);

    VHD_LOG_DEBUG("changing state from %d to %d", vdev->state, new_state);
    vdev->state = new_state;

    return ret;

invalid_transition:
    VHD_LOG_ERROR("invalid state transition from %d to %d", vdev->state, new_state);
    return -EINVAL;
}

/*
 * Accept connection and add the client socket to the IO polling.
 * Will close server socket on first connection since we're only support 1 active master.
 */
static int server_read(void* data)
{
    int ret;
    int flags;
    int connfd;

    struct vhd_vdev* vdev = (struct vhd_vdev*)data;
    VHD_ASSERT(vdev);

    connfd = accept(vdev->listenfd, NULL, NULL);
    if (connfd == -1) {
        VHD_LOG_ERROR("accept() failed: %d", errno);
        return errno;
    }

    flags = fcntl(connfd, F_GETFL, 0);
    if (flags < 0) {
        VHD_LOG_ERROR("fcntl on client socket failed: %d", errno);
        ret = errno;
        goto close_client;
    }

    if (fcntl(connfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        VHD_LOG_ERROR("Can't set O_NONBLOCK mode on the client socket: %d", errno);
        ret = errno;
        goto close_client;
    }

    vdev->connfd = connfd;
    ret = change_device_state(vdev, VDEV_CONNECTED);
    if (ret != 0) {
        goto close_client;
    }

    VHD_LOG_INFO("Connection established, sock = %d", connfd);
    return 0;

close_client:
    close(connfd);
    return ret;
}

static int server_close(void* data)
{
    /* We ignore close on server socket */
    return 0;
}

static int conn_read(void* data)
{
    int len;
    struct vhost_user_msg msg;
    int fds[VHOST_USER_MEM_REGIONS_MAX];
    int fdn = 0;

    struct vhd_vdev* vdev = (struct vhd_vdev*)data;
    VHD_ASSERT(vdev);

    len = net_recv_msg(vdev->connfd, &msg, fds, &fdn);
    if (len < 0) {
        return len;
    }

    return vhost_handle_request(vdev, &msg, fds, fdn);
}

static int conn_close(void* data)
{
    struct vhd_vdev* vdev = (struct vhd_vdev*)data;
    VHD_ASSERT(vdev);

    VHD_LOG_DEBUG("Close connection with client, sock = %d", vdev->connfd);

    return change_device_state(vdev, VDEV_LISTENING);
}

/* Prepare the sock path for the server. Return 0 if the requested path
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

// TODO: properly destroy server on close
int sock_create_server(const char *path)
{
    int fd;
    int flags;
    int ret;
    struct sockaddr_un sockaddr;

    VHD_VERIFY(path);

    if (strlen(path) >= sizeof(sockaddr.sun_path)) {
        VHD_LOG_ERROR("Path = %s to socket is too long, it should be less than %lu",
                path, sizeof(sockaddr.sun_path));
        return -1;
    }

    ret = prepare_server_sock_path(path);
    if (ret) {
        VHD_LOG_ERROR("Sock path = %s, is busy or can't be unlinked. Error code = %d, %s",
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
    if (bind(fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
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

int vhd_vdev_init_server(
    struct vhd_vdev* vdev,
    const char* socket_path,
    const struct vhd_vdev_type* type,
    int max_queues,
    struct vhd_request_queue* rq)
{
    int ret;
    int listenfd;

    VHD_VERIFY(socket_path);
    VHD_VERIFY(type);
    VHD_VERIFY(vdev);
    VHD_VERIFY(max_queues > 0);

    memset(vdev, 0, sizeof(*vdev));

    listenfd = sock_create_server(socket_path);
    if (listenfd < 0) {
        return -1;
    }

    vdev->type = type;
    vdev->listenfd = listenfd;
    vdev->connfd = -1;
    vdev->rq = rq;

    vdev->supported_protocol_features = g_default_protocol_features;
    vdev->max_queues = max_queues;
    vdev->num_queues = max_queues; /* May be overriden later by SET_CONFIG, but should be <= max_queues */
    vdev->vrings = vhd_calloc(max_queues, sizeof(vdev->vrings[0]));
    for (int i = 0; i < max_queues; ++i) {
        vhd_vring_init(vdev->vrings + i, i, vdev);
    }

    LIST_INSERT_HEAD(&g_vdevs, vdev, vdev_list);

    vdev->state = VDEV_INITIALIZED; /* Initial state */

    ret = change_device_state(vdev, VDEV_LISTENING);
    if (ret != 0) {
        vhd_vdev_uninit(vdev);
    }

    return ret;
}

////////////////////////////////////////////////////////////////////////////////

static int vring_io_event(void* ctx)
{
    struct vhd_vring* vring = (struct vhd_vring*) ctx;
    VHD_ASSERT(vring);

    /* TODO: is it possible for client to enqueue a bunch of requests and then disable queue? */
    if (!vring->is_enabled) {
        VHD_LOG_ERROR("Somehow we got an event on disabled vring");
        return -EINVAL;
    }

    int res = vhd_vdev_dispatch_requests(vring->vdev, vring);
    vhd_clear_eventfd(vring->kickfd);

    return res;
}

static int vring_close_event(void* ctx)
{
    /* TODO: not sure how we should react */
    return 0;
}

void vhd_vdev_uninit(struct vhd_vdev* vdev)
{
    if (vdev) {
        LIST_REMOVE(vdev, vdev_list);
        vhd_free(vdev->vrings);
        close(vdev->listenfd);

        /* TODO: we should probably gracefully terminate client connection */
    }
}

void vhd_vring_init(struct vhd_vring* vring, int id, struct vhd_vdev* vdev)
{
    VHD_ASSERT(vring);

    /* According to vhost spec we should check that PROTOCOL_FEATURES
     * have been negotiated with the client here. However we explicitly
     * don't support clients that don't negotiate it, so it makes no difference. */
    vring->is_enabled = false;

    vring->id = id;
    vring->kickfd = -1;
    vring->callfd = -1;
    vring->vdev = vdev;
}
