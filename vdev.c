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
#include <alloca.h>

#include "vdev.h"
#include "server_internal.h"
#include "logging.h"
#include "objref.h"

static LIST_HEAD(, vhd_vdev) g_vdevs = LIST_HEAD_INITIALIZER(g_vdevs);

static void vhd_vdev_inflight_cleanup(struct vhd_vdev *vdev);
static uint64_t vring_inflight_buf_size(int num);
static void vring_inflight_addr_init(struct vhd_vring *vring);

/*////////////////////////////////////////////////////////////////////////////*/

static int server_read(void *sock);

/*
 * Event callbacks for vhost vdev listen socket
 */
static const struct vhd_event_ops g_server_sock_ops = {
    .read = server_read,
};

static int conn_read(void *data);

/*
 * Event callbacks for vhost vdev client connection
 */
static const struct vhd_event_ops g_conn_sock_ops = {
    .read = conn_read,
};

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
    iov.iov_len = VHOST_MSG_HDR_SIZE;

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
    } else if (len != VHOST_MSG_HDR_SIZE) {
        VHD_LOG_ERROR("recvmsg() gets less bytes = %d, than required = %lu",
                len, VHOST_MSG_HDR_SIZE);
        return -EIO;
    } else if (msgh.msg_flags & MSG_CTRUNC) {
        VHD_LOG_ERROR("recvmsg(): file descriptor array truncated");
        return -ENOBUFS;
    } else if (msg->size > sizeof(msg->payload)) {
        VHD_LOG_ERROR("Payload size = %d exceeds buffer size = %lu",
                msg->size, sizeof(msg->payload));
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
    payload_len = read(fd, &msg->payload, msg->size);
    if (payload_len < 0) {
        VHD_LOG_ERROR("Payload read failed. Error code = %d, %s",
                errno, strerror(errno));
        return -errno;
    } else if ((size_t)payload_len != msg->size) {
        VHD_LOG_ERROR("Read only part of the payload = %d, required = %d",
                payload_len, msg->size);
        return -EIO;
    }
    len += payload_len;

    return len;
}

/*
 * Send message to master. Return number of bytes sent or negative
 * error code in case of error.
 */
static int net_send_msg_fds(int fd, const struct vhost_user_msg *msg,
        int *fds, int fdn)
{
    struct msghdr msgh;
    struct iovec iov;
    int len;
    char *control;
    struct cmsghdr *cmsgh;
    int fdsize;

    iov.iov_base = (void *)msg;
    iov.iov_len = VHOST_MSG_HDR_SIZE + msg->size;

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    if (fdn) {
        /* Prepare file descriptors for sending. */
        fdsize = sizeof(*fds) * fdn;
        control = alloca(CMSG_SPACE(fdsize));
        msgh.msg_control = control;
        msgh.msg_controllen = CMSG_SPACE(fdsize);
        cmsgh = CMSG_FIRSTHDR(&msgh);
        cmsgh->cmsg_len = CMSG_LEN(fdsize);
        cmsgh->cmsg_level = SOL_SOCKET;
        cmsgh->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsgh), fds, fdsize);
    }
    len = sendmsg(fd, &msgh, 0);
    if (len < 0) {
        VHD_LOG_ERROR("sendmsg() failed: %d", errno);
        return -errno;
    } else if ((unsigned)len != (VHOST_MSG_HDR_SIZE + msg->size)) {
        VHD_LOG_ERROR("sendmsg() puts less bytes = %d, than required = %lu",
                len, VHOST_MSG_HDR_SIZE + msg->size);
        return -EIO;
    }

    return len;
}

/*////////////////////////////////////////////////////////////////////////////*/

/**
 * TODO: need a separate unit for this
 */
typedef uint64_t vhd_uaddr_t;

struct vhd_guest_memory_region {
    /* Guest physical address */
    vhd_paddr_t gpa;

    /*
     * Userspace virtual address, where this region is mapped
     * in virtio backend on client
     */
    vhd_uaddr_t uva;

    /* Host virtual address, our local mapping */
    void *hva;

    /* Used region size */
    size_t size;
};

/**
 * TODO: need a separate unit for this
 */
struct vhd_guest_memory_map {
    struct objref ref;

    atomic_long *log_addr;
    uint64_t log_size;

    void *priv;
    int (*unmap_cb)(void *addr, size_t len, void *priv);

    uint32_t num;
    struct vhd_guest_memory_region regions[];
};

static void *map_memory(void *addr, size_t len, int fd, off_t offset)
{
    size_t aligned_len = VHD_ALIGN_PTR_UP(len, HUGE_PAGE_SIZE);
    size_t map_len = aligned_len + HUGE_PAGE_SIZE + PAGE_SIZE;

    char *map = mmap(addr, map_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                     0);
    if (map == MAP_FAILED) {
        VHD_LOG_ERROR("unable to map memory: %s", strerror(errno));
        return MAP_FAILED;
    }

    char *aligned_addr = VHD_ALIGN_PTR_UP(map + PAGE_SIZE, HUGE_PAGE_SIZE);
    addr = mmap(aligned_addr, len, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_FIXED, fd, offset);
    if (addr == MAP_FAILED) {
        VHD_LOG_ERROR("unable to remap memory region %p-%p: %s", aligned_addr,
                      aligned_addr + len, strerror(errno));
        munmap(map, map_len);
        return MAP_FAILED;
    }
    aligned_addr = addr;

    size_t tail_len = aligned_len - len;
    if (tail_len) {
        char *tail = aligned_addr + len;
        addr = mmap(tail, tail_len, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (addr == MAP_FAILED) {
            VHD_LOG_ERROR("unable to remap memory region %p-%p: %s", tail,
                          tail + tail_len, strerror(errno));
            munmap(map, map_len);
            return MAP_FAILED;
        }
    }

    char *start = aligned_addr - PAGE_SIZE;
    char *end = aligned_addr + aligned_len + PAGE_SIZE;
    munmap(map, start - map);
    munmap(end, map + map_len - end);

    return aligned_addr;
}

static int unmap_memory(void *addr, size_t len)
{
    size_t map_len = VHD_ALIGN_PTR_UP(len, HUGE_PAGE_SIZE) + PAGE_SIZE * 2;
    char *map = addr - PAGE_SIZE;
    return munmap(map, map_len);
}

/*
 * Map guest memory region to the vhost server.
 */
static int map_guest_region(struct vhd_guest_memory_region *region,
                            vhd_paddr_t guest_addr, vhd_uaddr_t user_addr,
                            uint64_t size, uint64_t offset, int fd,
                            int (*map_cb)(void *addr, size_t len, void *priv),
                            void *priv)
{
    void *vaddr;

    vaddr = map_memory(NULL, size, fd, offset);
    if (vaddr == MAP_FAILED) {
        VHD_LOG_ERROR("Can't mmap guest memory: %s", strerror(errno));
        return -errno;
    }

    if (map_cb) {
        size_t len = VHD_ALIGN_PTR_UP(size, HUGE_PAGE_SIZE);
        int ret = map_cb(vaddr, len, priv);
        if (ret) {
            VHD_LOG_ERROR("map callback failed for region %p-%p: %s",
                          vaddr, vaddr + len, strerror(-ret));
            munmap(vaddr, size);
            return ret;
        }
    }

    /* Mark memory as defined explicitly */
    VHD_MEMCHECK_DEFINED(vaddr, size);

    region->hva = vaddr;
    region->gpa = guest_addr;
    region->uva = user_addr;
    region->size = size;
    return 0;
}

static void unmap_guest_region(struct vhd_guest_memory_region *reg,
    int (*unmap_cb)(void *addr, size_t len, void *priv), void *priv)
{
    int ret;

    if (unmap_cb) {
        size_t len = VHD_ALIGN_PTR_UP(reg->size, HUGE_PAGE_SIZE);
        ret = unmap_cb(reg->hva, len, priv);
        if (ret) {
            VHD_LOG_ERROR("unmap callback failed for region %p-%p: %s",
                          reg->hva, reg->hva + reg->size, strerror(-ret));
        }
    }

    ret = unmap_memory(reg->hva, reg->size);
    if (ret != 0) {
        VHD_LOG_ERROR("failed to unmap guest region at %p", reg->hva);
    }
}

static void memmap_release(struct objref *objref)
{
    struct vhd_guest_memory_map *mm =
        containerof(objref, struct vhd_guest_memory_map, ref);
    uint32_t i;

    for (i = 0; i < mm->num; i++) {
        unmap_guest_region(&mm->regions[i], mm->unmap_cb, mm->priv);
    }

    if (mm->log_addr) {
        int ret = munmap(mm->log_addr, mm->log_size);
        if (ret != 0) {
            VHD_LOG_ERROR("failed to unmap log region at %p", mm->log_addr);
        }
    }

    vhd_free(mm);
}

void vhd_memmap_ref(struct vhd_guest_memory_map *mm) __attribute__ ((weak));
void vhd_memmap_ref(struct vhd_guest_memory_map *mm)
{
    objref_get(&mm->ref);
}

void vhd_memmap_unref(struct vhd_guest_memory_map *mm) __attribute__ ((weak));
void vhd_memmap_unref(struct vhd_guest_memory_map *mm)
{
    objref_put(&mm->ref);
}

/*
 * Convert host emulator address to the current mmap address.
 * Return mmap address in case of success or NULL.
 */
static void *map_uva(struct vhd_guest_memory_map *map, vhd_uaddr_t uva)
{
    uint32_t i;

    for (i = 0; i < map->num; i++) {
        struct vhd_guest_memory_region *reg = &map->regions[i];
        if (uva >= reg->uva && uva - reg->uva < reg->size) {
            return reg->hva + (uva - reg->uva);
        }
    }

    return NULL;
}

#define TRANSLATION_FAILED ((vhd_paddr_t)-1)

static vhd_paddr_t hva2gpa(struct vhd_guest_memory_map *mm, void *hva)
{
    uint32_t i;
    for (i = 0; i < mm->num; ++i) {
        struct vhd_guest_memory_region *reg = &mm->regions[i];
        if (hva >= reg->hva && hva < reg->hva + reg->size) {
            return (hva - reg->hva) + reg->gpa;
        }
    }

    VHD_LOG_WARN("Failed to translate hva %p to gpa", hva);
    return TRANSLATION_FAILED;
}

#define VHOST_LOG_PAGE 0x1000

void vhd_gpa_range_mark_dirty(struct vhd_guest_memory_map *mm,
                              vhd_paddr_t gpa, size_t len)
{
    atomic_long *log_addr = mm->log_addr;
    if (!log_addr) {
        VHD_LOG_WARN("No logging addr set");
        return;
    }

    uint64_t log_size = mm->log_size;

    uint64_t page = gpa / VHOST_LOG_PAGE;
    uint64_t last_page = (gpa + len - 1) / VHOST_LOG_PAGE;

    if (last_page >= log_size * 8) {
        VHD_LOG_ERROR(
            "Write beyond log buffer: gpa = 0x%lx, len = 0x%lx, log_size %zu",
            gpa, len, log_size);
        if (page >= log_size * 8) {
            return;
        }
        last_page = log_size * 8 - 1;
    }

    /*
     * log is always page aligned so we can be sure that its start is aligned
     * to sizeof(long) and also that atomic operations never cross cacheline
     */
    do {
        uint64_t mask = 0UL;
        uint64_t chunk = page / 64;
        for (; page <= last_page && page / 64 == chunk; ++page) {
            mask |= 1LU << (page % 64);
        }
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        mask = __builtin_bswap64(mask);
#endif
        atomic_or(&log_addr[chunk], mask);
    } while (page <= last_page);
}

void vhd_hva_range_mark_dirty(struct vhd_guest_memory_map *mm,
                              void *hva, size_t len)
{
    vhd_paddr_t gpa = hva2gpa(mm, hva);
    if (gpa != TRANSLATION_FAILED) {
        vhd_gpa_range_mark_dirty(mm, gpa, len);
    }
}

static void *map_gpa_len(struct vhd_guest_memory_map *map,
                         vhd_paddr_t gpa, uint32_t len)
{
    uint32_t i;

    if (len == 0) {
        return NULL;
    }

    /* TODO: sanitize for overflow */
    vhd_paddr_t last_gpa = gpa + len - 1;

    for (i = 0; i < map->num; i++) {
        struct vhd_guest_memory_region *reg = &map->regions[i];
        if (gpa >= reg->gpa && gpa - reg->gpa < reg->size) {
            /*
             * Check that length fits in a single region.
             *
             * TODO: should we handle gpa areas that cross region boundaries
             *       but are otherwise valid?
             */
            if (last_gpa - reg->gpa >= reg->size) {
                return NULL;
            }

            return reg->hva + (gpa - reg->gpa);
        }
    }

    return NULL;
}

void *virtio_map_guest_phys_range(struct vhd_guest_memory_map *mm,
                                  uint64_t gpa, uint32_t len)
                                 __attribute__ ((weak));
void *virtio_map_guest_phys_range(struct vhd_guest_memory_map *mm,
                                  uint64_t gpa, uint32_t len)
{
    return map_gpa_len(mm, gpa, len);
}

/*////////////////////////////////////////////////////////////////////////////*/

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

static int vring_io_event(void *ctx);
static int vring_set_enable(struct vhd_vring *vring, bool do_enable);

static inline bool has_feature(uint64_t features_qword, size_t feature_bit)
{
    return features_qword & (1ull << feature_bit);
}

static int vhost_send_fds(struct vhd_vdev *vdev,
                          const struct vhost_user_msg *msg, int *fds, int fdn)
{
    int len;

    len = net_send_msg_fds(vdev->connfd, msg, fds, fdn);
    if (len < 0) {
        return len;
    }

    return 0;
}

static int vhost_send(struct vhd_vdev *vdev, const struct vhost_user_msg *msg)
{
    return vhost_send_fds(vdev, msg, NULL, 0);
}

static int vhost_send_reply(struct vhd_vdev *vdev,
                            const struct vhost_user_msg *msgin, uint64_t u64)
{
    struct vhost_user_msg reply;
    reply.req = msgin->req;
    reply.size = sizeof(u64);
    reply.flags = VHOST_USER_MSG_FLAGS_REPLY;
    reply.payload.u64 = u64;

    return vhost_send(vdev, &reply);
}

static int vhost_send_vring_state(struct vhd_vdev *vdev,
                                  const struct vhost_user_msg *msgin,
                                  int last_avail)
{
    struct vhost_user_msg reply;
    reply.req = msgin->req;
    reply.size = sizeof(reply.payload.vring_state);
    reply.flags = VHOST_USER_MSG_FLAGS_REPLY;
    reply.payload.vring_state.index = msgin->payload.vring_state.index;
    reply.payload.vring_state.num = last_avail;

    return vhost_send(vdev, &reply);
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

    vdev->supported_features = g_default_features | vhd_vdev_get_features(vdev);
    return vhost_send_reply(vdev, msg, vdev->supported_features);
}

static int vhost_set_features(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    uint64_t requested_features = msg->payload.u64;
    vdev->negotiated_features = requested_features & vdev->supported_features;

    if (0 != (requested_features & ~vdev->supported_features)) {
        VHD_LOG_WARN("Master attempts to set device features we don't support: "
                     "supported 0x%lx, requested 0x%lx, negotiated 0x%lx",
                     vdev->supported_features,
                     requested_features,
                     vdev->negotiated_features);
    }

    return 0;
}

static int vhost_set_owner(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();
    VHD_UNUSED(msg);

    /* We don't support changing session owner */
    if (vdev->is_owned) {
        VHD_LOG_WARN("Client attempts to set owner a second time, ignoring");
    }

    vdev->is_owned = true;
    return 0;
}

static int vhost_reset_owner(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    VHD_UNUSED(vdev);
    VHD_UNUSED(msg);

    /*
     * This is no longer used in vhost-spec spec so we don't support it either
     */
    return ENOTSUP;
}

static void vhost_reset_mem_table(struct vhd_vdev *vdev)
{
    if (!vdev->guest_memmap) {
        return;
    }

    vhd_memmap_unref(vdev->guest_memmap);
    vdev->guest_memmap = NULL;
}

static int vhost_set_mem_table(struct vhd_vdev *vdev,
                               struct vhost_user_msg *msg,
                               int *fds, size_t num_fds)
{
    VHD_LOG_TRACE();

    int ret = 0;
    struct vhost_user_mem_desc *desc;
    struct vhd_guest_memory_map *mm;
    uint32_t i;

    vhost_reset_mem_table(vdev);

    desc = &msg->payload.mem_desc;
    if (desc->nregions > VHOST_USER_MEM_REGIONS_MAX) {
        VHD_LOG_ERROR("Invalid number of memory regions %d", desc->nregions);
        return -EINVAL;
    }
    if (desc->nregions != num_fds) {
        VHD_LOG_ERROR("#memory regions != #fds: %u != %zu", desc->nregions,
                      num_fds);
        return -EINVAL;
    }

    mm = vhd_zalloc(sizeof(*mm) + desc->nregions * sizeof(mm->regions[0]));
    objref_init(&mm->ref, memmap_release);
    mm->num = desc->nregions;
    mm->unmap_cb = vdev->unmap_cb;
    mm->priv = vdev->priv;

    for (i = 0; i < desc->nregions; i++) {
        struct vhost_user_mem_region *region = &desc->regions[i];
        ret = map_guest_region(&mm->regions[i], region->guest_addr,
                               region->user_addr, region->size,
                               region->mmap_offset, fds[i], vdev->map_cb,
                               vdev->priv);
        if (ret < 0) {
            while (i--) {
                unmap_guest_region(&mm->regions[i], vdev->unmap_cb, vdev->priv);
            }
            vhd_free(mm);
            goto out;
        }
    }

    vdev->guest_memmap = mm;
out:
    for (i = 0; i < num_fds; i++) {
        close(fds[i]);
    }
    return ret;
}

static int vhost_get_config(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{

    struct vhost_user_config_space *config = &msg->payload.config;

    VHD_LOG_DEBUG("msg->size %d, config->size %d",
                  msg->size,
                  config->size);

    /* check that msg has enough space for requested buffer */
    if (msg->size < VHOST_CONFIG_HDR_SIZE + config->size) {
        VHD_LOG_WARN("Message size is not enough for requested data");
        config->size = msg->size - VHOST_CONFIG_HDR_SIZE;
    }

    config->size = vhd_vdev_get_config(vdev,
                                       config->payload,
                                       config->size,
                                       config->offset);

    /* zero-fill leftover space */
    memset(config->payload + config->size,
           0,
           msg->size - VHOST_CONFIG_HDR_SIZE - config->size);

    msg->flags = VHOST_USER_MSG_FLAGS_REPLY;

    return vhost_send(vdev, msg);
}

static int vhost_set_config(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    VHD_UNUSED(msg);
    VHD_UNUSED(vdev);

    /* TODO */
    return ENOTSUP;
}

static int vhost_get_queue_num(struct vhd_vdev *vdev,
                               struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    return vhost_send_reply(vdev, msg, vdev->max_queues);
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

static struct vhd_vring *get_vring_not_enabled(struct vhd_vdev *vdev, int index)
{
    struct vhd_vring *vring = get_vring(vdev, index);
    if (vring && vring->is_enabled) {
        VHD_LOG_ERROR("vring %d is enabled", index);
        return NULL;
    }

    return vring;
}

enum vring_desc_type { VRING_KICKFD, VRING_CALLFD, VRING_ERRFD };

static int vhost_set_vring_fd_common(struct vhd_vdev *vdev,
                                     struct vhost_user_msg *msg, int fd,
                                     enum vring_desc_type type)
{
    VHD_LOG_DEBUG("payload = 0x%llx", (unsigned long long) msg->payload.u64);

    uint8_t vring_idx = msg->payload.u64 & VHOST_VRING_IDX_MASK;
    bool has_fd = (msg->payload.u64 & VHOST_VRING_INVALID_FD) == 0;

    if (!has_fd) {
        VHD_LOG_ERROR("vring polling mode is not supported");
        return ENOTSUP;
    }

    struct vhd_vring *vring = get_vring(vdev, vring_idx);
    if (!vring) {
        return EINVAL;
    }

    switch (type) {
    case VRING_KICKFD: {
        vring->kickfd = fd;

        /*
         * If we did not negotiate VHOST_USER_F_PROTOCOL_FEATURES
         * then vring should start automatically
         * when we get VHOST_USER_SET_VRING_KICK from guest.
         * Otherwise we should wait for explicit VHOST_USER_SET_VRING_ENABLE(1)
         */
        if (!has_feature(vdev->negotiated_features,
                         VHOST_USER_F_PROTOCOL_FEATURES)) {
            return vring_set_enable(vring, true);
        }

        break;
    }

    case VRING_CALLFD: {
        vring->callfd = fd;
        if (vring->is_enabled) {
            virtq_set_notify_fd(&vring->vq, fd);
        }

        break;
    }

    case VRING_ERRFD: {
        vring->errfd = fd;
        break;
    }

    default:
        VHD_ASSERT(0);
    }

    return 0;
}

static int vhost_set_vring_call(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    VHD_LOG_DEBUG("payload = 0x%llx, fd = %d",
                  (unsigned long long)msg->payload.u64, fds[0]);
    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return -EINVAL;
    }
    return vhost_set_vring_fd_common(vdev, msg, fds[0], VRING_CALLFD);
}

static int vhost_set_vring_kick(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    VHD_LOG_DEBUG("payload = 0x%llx, fd = %d",
                  (unsigned long long)msg->payload.u64, fds[0]);
    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return -EINVAL;
    }
    return vhost_set_vring_fd_common(vdev, msg, fds[0], VRING_KICKFD);
}

static int vhost_set_vring_err(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    VHD_LOG_DEBUG("payload = 0x%llx, fd = %d",
                  (unsigned long long)msg->payload.u64, fds[0]);
    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return -EINVAL;
    }
    return vhost_set_vring_fd_common(vdev, msg, fds[0], VRING_ERRFD);
}

static int vhost_set_vring_num(struct vhd_vdev *vdev,
                               struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state *vrstate = &msg->payload.vring_state;

    struct vhd_vring *vring = get_vring_not_enabled(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    vring->client_info.num = vrstate->num;
    return 0;
}

static int vhost_set_vring_base(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state *vrstate = &msg->payload.vring_state;

    struct vhd_vring *vring = get_vring_not_enabled(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    vring->client_info.base = vrstate->num;
    return 0;
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
     * If we did not negotiate VHOST_USER_F_PROTOCOL_FEATURES
     * then vring should stop automatically
     * when we get VHOST_USER_GET_VRING_BASE from guest.
     * Otherwise we should wait for explicit VHOST_USER_SET_VRING_ENABLE(0)
     */
    if (!has_feature(vdev->negotiated_features,
                     VHOST_USER_F_PROTOCOL_FEATURES)) {
        int error = vring_set_enable(vring, false);
        if (error) {
            VHD_LOG_ERROR("Could not disable vring: %d", error);
            return error;
        }
    }

    return vhost_send_vring_state(vdev, msg, vring->vq.last_avail);
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

    /* TODO: we don't have to do full lookup 3 times, we can do it in 1 */
    void *desc_addr = map_uva(vdev->guest_memmap, vraddr->desc_addr);
    void *used_addr = map_uva(vdev->guest_memmap, vraddr->used_addr);
    void *avail_addr = map_uva(vdev->guest_memmap, vraddr->avail_addr);

    if (!vring->is_enabled) {
        if (!desc_addr || !used_addr || !avail_addr) {
            VHD_LOG_ERROR("invalid vring %d component address (%p, %p, %p)",
                vraddr->index, desc_addr, used_addr, avail_addr);
            return EINVAL;
        }

        vring->client_info.flags = vraddr->flags;
        vring->client_info.desc_addr = desc_addr;
        vring->client_info.used_addr = used_addr;
        vring->client_info.avail_addr = avail_addr;
        vring->client_info.used_gpa_base = vraddr->used_gpa_base;
    } else {
        if (vring->client_info.desc_addr != desc_addr ||
            vring->client_info.used_addr != used_addr ||
            vring->client_info.avail_addr != avail_addr ||
            vring->client_info.used_gpa_base != vraddr->used_gpa_base)
        {
            VHD_LOG_ERROR("Enabled vring parameters mismatch");
            return EINVAL;
        }
        vring->client_info.flags = vraddr->flags;
        vring->vq.flags = vraddr->flags;
    }


    return 0;
}

static int vhost_set_vring_enable(struct vhd_vdev *vdev,
                                  struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_vring_state *vrstate = &msg->payload.vring_state;
    struct vhd_vring *vring = get_vring(vdev, vrstate->index);
    if (!vring) {
        return EINVAL;
    }

    return vring_set_enable(vring, vrstate->num == 1);
}

bool vhd_logging_started(struct virtio_virtq *vq)
                                 __attribute__ ((weak));
bool vhd_logging_started(struct virtio_virtq *vq)
{
    struct vhd_vring *vring = containerof(vq, struct vhd_vring, vq);
    return has_feature(vring->vdev->negotiated_features, VHOST_F_LOG_ALL);
}

static int vhost_set_log_base(struct vhd_vdev *vdev,
                              struct vhost_user_msg *msg,
                              int *fds,
                              size_t num_fds)
{
    VHD_LOG_TRACE();

    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return EINVAL;
    }

    if (vdev->guest_memmap->log_addr) {
        VHD_LOG_ERROR("updating log region is not supported");
        close(fds[0]);
        return ENOTSUP;
    }

    struct vhost_user_log *log = &msg->payload.log;

    void *log_addr = mmap(NULL, log->size, PROT_READ | PROT_WRITE, MAP_SHARED,
                          fds[0], log->offset);
    close(fds[0]);

    if (log_addr == MAP_FAILED) {
        VHD_LOG_ERROR("can't mmap fd = %d, size = %lu", fds[0], log->size);
        return errno;
    }

    vdev->guest_memmap->log_addr = log_addr;
    vdev->guest_memmap->log_size = log->size;

    return vhost_send_reply(vdev, msg, 0);
}

static void inflight_split_region_init(struct inflight_split_region *region,
        uint16_t qsize)
{
    region->features = 0;
    region->version = 1;
    region->desc_num = qsize;
    region->last_batch_head = 0;
    region->used_idx = 0;
}

static int inflight_mmap_region(struct vhd_vdev *vdev, int fd, uint64_t size)
{
    void *buf;

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        VHD_LOG_ERROR("can't mmap fd = %d, size = %lu", fd, size);
        return errno;
    }
    vdev->inflight_mem = buf;
    vdev->inflight_size = size;

    return 0;
}

static int vhost_get_inflight_fd(struct vhd_vdev *vdev,
                                 struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();

    struct vhost_user_inflight_desc *idesc;
    uint64_t size;
    int fd;
    int ret;
    void *buf;
    int i;

    /*
     * TODO: should it be carefully cleanup? Could we get this command
     * during vringq processing?
     */
    vhd_vdev_inflight_cleanup(vdev);

    idesc = &msg->payload.inflight_desc;

    /* Calculate the size of the inflight buffer. */
    size = vring_inflight_buf_size(idesc->queue_size);
    size *= idesc->num_queues;

    fd = memfd_create("vhost_get_inflight_fd", MFD_CLOEXEC);
    if (fd == -1) {
        VHD_LOG_ERROR("can't create memfd object");
        return -errno;
    }
    ret = ftruncate(fd, size);
    if (ret == -1) {
        VHD_LOG_ERROR("can't truncate fd = %d, to size = %lu",
                fd, size);
        ret = -errno;
        goto out;
    }
    ret = inflight_mmap_region(vdev, fd, size);
    if (ret) {
        goto out;
    }
    memset(vdev->inflight_mem, 0, vdev->inflight_size);

    /* Prepare reply to the master side. */
    idesc->mmap_size = size;
    idesc->mmap_offset = 0;

    /* Initialize the inflight region for each virtqueue. */
    buf = vdev->inflight_mem;
    size = vring_inflight_buf_size(idesc->queue_size);
    for (i = 0; i < idesc->num_queues; i++) {
        inflight_split_region_init(buf, idesc->queue_size);
        buf = (void *)((uint64_t)buf + size);
    }

    msg->flags = VHOST_USER_MSG_FLAGS_REPLY;
    ret = vhost_send_fds(vdev, msg, &fd, 1);
    if (ret) {
        VHD_LOG_ERROR("can't send reply to get_inflight_fd command");
        munmap(vdev->inflight_mem, vdev->inflight_size);
        vdev->inflight_mem = NULL;
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

    struct vhost_user_inflight_desc *idesc;
    int ret;

    if (num_fds != 1) {
        VHD_LOG_ERROR("unexpected #fds: %zu", num_fds);
        return -EINVAL;
    }

    vhd_vdev_inflight_cleanup(vdev);

    idesc = &msg->payload.inflight_desc;
    ret = inflight_mmap_region(vdev, fds[0], idesc->mmap_size);
    close(fds[0]);

    return ret;
}

/*////////////////////////////////////////////////////////////////////////////*/

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
    if (!(msg->flags & VHOST_USER_MSG_FLAGS_REPLY_ACK)) {
        return 0;
    }

    /*
     * We negotiated REPLY_ACK but message already has an explicit reply
     * which was successfully sent
     */
    if (ret == 0) {
        switch (msg->req) {
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

/*
 * Return 0 in case of success, otherwise return error code.
 */
static int vhost_handle_request(struct vhd_vdev *vdev,
                                struct vhost_user_msg *msg,
                                int *fds, size_t num_fds)
{
    int ret;

    VHD_ASSERT(msg);

    ret = 0;
    VHD_LOG_DEBUG("Handle command %d, flags 0x%x, size %u",
                  msg->req, msg->flags, msg->size);
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
        ret = vhost_set_mem_table(vdev, msg, fds, num_fds);
        break;
    case VHOST_USER_GET_QUEUE_NUM:
        ret = vhost_get_queue_num(vdev, msg);
        break;
    case VHOST_USER_SET_LOG_BASE:
        ret = vhost_set_log_base(vdev, msg, fds, num_fds);
        break;

    /*
     * vrings
     */

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
    case VHOST_USER_SET_VRING_ENABLE:
        ret = vhost_set_vring_enable(vdev, msg);
        break;

    /*
     * TODO
     */

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
        VHD_LOG_WARN("Command = %d, not supported", msg->req);
        ret = ENOTSUP;
        break;
    case VHOST_USER_GET_INFLIGHT_FD:
        ret = vhost_get_inflight_fd(vdev, msg);
        break;
    case VHOST_USER_SET_INFLIGHT_FD:
        ret = vhost_set_inflight_fd(vdev, msg, fds, num_fds);
        break;
    case VHOST_USER_NONE:
    default:
        VHD_LOG_ERROR("Command = %d, not defined", msg->req);
        ret = EINVAL;
        break;
    }

    if (ret != 0) {
        VHD_LOG_ERROR("Request %d failed with %d", msg->req, ret);
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

/*////////////////////////////////////////////////////////////////////////////*/

void vhd_vdev_stop(struct vhd_vdev *vdev)
{
    for (uint32_t i = 0; i < vdev->max_queues; ++i) {
        vhd_vring_stop(vdev->vrings + i);
    }

}

void vhd_vdev_release(struct vhd_vdev *vdev)
{
    close(vdev->listenfd);
    close(vdev->connfd);

    vhd_vdev_inflight_cleanup(vdev);

    LIST_REMOVE(vdev, vdev_list);
    vhd_free(vdev->vrings);
    vdev->type->free(vdev);
}

static int change_device_state(struct vhd_vdev *vdev,
                               enum vhd_vdev_state new_state)
{
    int ret = 0;

    if (new_state == VDEV_LISTENING) {

        switch (vdev->state) {
        case VDEV_CONNECTED:
            /*
             * We're terminating existing connection
             * and going back to listen mode
             */
            vhd_del_vhost_event(vdev->connfd);
            vdev->is_owned = false;

            vhd_vdev_stop(vdev);

            vhost_reset_mem_table(vdev);

            close(vdev->connfd);
            vdev->connfd = -1; /* Not nessesary, just defensive */
            /* Fall thru */

        case VDEV_INITIALIZED:
            /* Normal listening init */
            ret = vhd_add_vhost_event(vdev->listenfd, vdev, &g_server_sock_ops,
                                      &vdev->sock_ev);
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
            ret = vhd_add_vhost_event(vdev->connfd, vdev, &g_conn_sock_ops,
                                      &vdev->sock_ev);
            if (ret != 0) {
                return ret;
            }

            /*
             * Remove server fd from event loop.
             * We don't want multiple clients
             */
            vhd_del_vhost_event(vdev->listenfd);
            break;
        default:
            goto invalid_transition;
        };

    } else if (new_state == VDEV_TERMINATING) {

        switch (vdev->state) {
        case VDEV_LISTENING:
            vhd_del_vhost_event(vdev->listenfd);
            break;
        case VDEV_CONNECTED:
            vhd_del_vhost_event(vdev->connfd);
            break;
        case VDEV_INITIALIZED:
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
    VHD_ASSERT(vdev);

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
int sock_create_server(const char *path)
{
    int fd;
    int flags;
    int ret;
    struct sockaddr_un sockaddr;

    VHD_VERIFY(path);

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

void vdev_ref(struct vhd_vdev *vdev)
{
    vdev->refcount++;
}

void vdev_unref(struct vhd_vdev *vdev)
{
    vdev->refcount--;

    if (!vdev->refcount) {
        if (vdev->unregister_cb) {
            vdev->unregister_cb(vdev->unregister_arg);
        }
        vhd_vdev_release(vdev);
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

    VHD_VERIFY(socket_path);
    VHD_VERIFY(type);
    VHD_VERIFY(vdev);
    VHD_VERIFY(max_queues > 0);

    memset(vdev, 0, sizeof(*vdev));

    listenfd = sock_create_server(socket_path);
    if (listenfd < 0) {
        return -1;
    }

    vdev->priv = priv;
    vdev->type = type;
    vdev->listenfd = listenfd;
    vdev->connfd = -1;
    vdev->rq = rq;
    vdev->map_cb = map_cb;
    vdev->unmap_cb = unmap_cb;

    vdev->supported_protocol_features = g_default_protocol_features;
    vdev->max_queues = max_queues;
    /* May be overriden later by SET_CONFIG, but should be <= max_queues */
    vdev->num_queues = max_queues;
    vdev->vrings = vhd_calloc(max_queues, sizeof(vdev->vrings[0]));
    for (int i = 0; i < max_queues; ++i) {
        vhd_vring_init(vdev->vrings + i, i, vdev);
    }

    vdev->refcount = 1;

    vdev->inflight_mem = NULL;
    vdev->inflight_size = 0;

    LIST_INSERT_HEAD(&g_vdevs, vdev, vdev_list);

    vdev->state = VDEV_INITIALIZED; /* Initial state */

    ret = change_device_state(vdev, VDEV_LISTENING);
    if (ret != 0) {
        vhd_vdev_release(vdev);
    }

    return ret;
}

void vhd_vdev_stop_server(struct vhd_vdev *vdev,
                          void (*unregister_complete)(void *), void *arg)
{
    if (!vdev) {
        return;
    }

    if (unregister_complete) {
        vdev->unregister_cb = unregister_complete;
        vdev->unregister_arg = arg;
    }

    change_device_state(vdev, VDEV_TERMINATING);
    vhd_vdev_stop(vdev);
    vhd_run_in_rq(vdev->rq, vdev_unregister_bh, vdev);
}

static void vhd_vdev_inflight_cleanup(struct vhd_vdev *vdev)
{
    if (!vdev->inflight_mem) {
        /* Nothing to clean up. */
        return;
    }

    munmap(vdev->inflight_mem, vdev->inflight_size);
    vdev->inflight_mem = NULL;
}

/*////////////////////////////////////////////////////////////////////////////*/

static int vring_io_event(void *ctx)
{
    struct vhd_vring *vring = (struct vhd_vring *) ctx;
    VHD_ASSERT(vring);

    /*
     * TODO: is it possible for client to enqueue a bunch of requests
     * and then disable queue?
     */
    if (!vring->is_enabled) {
        VHD_LOG_WARN("Somehow we got an event on disabled vring %d", vring->id);
        return 0;
    }

    /*
     * Clear vring event now, before processing virtq.
     * Otherwise we might lose events if guest has managed to
     * signal eventfd again while we were processing
     */
    vhd_clear_eventfd(vring->kickfd);
    return vhd_vdev_dispatch_requests(vring->vdev, vring);
}

static int vring_set_enable(struct vhd_vring *vring, bool do_enable)
{
    if (do_enable == vring->is_enabled) {
        VHD_LOG_WARN(
            "strange VRING_ENABLE call from client (vring %d is already %s)",
            vring->id, vring->is_enabled ? "enabled" : "disabled");
        return 0;
    }

    if (do_enable) {
        int res;

        vring_inflight_addr_init(vring);
        res = virtio_virtq_attach(&vring->vq,
                vring->client_info.flags,
                vring->client_info.desc_addr,
                vring->client_info.avail_addr,
                vring->client_info.used_addr,
                vring->client_info.used_gpa_base,
                vring->client_info.num,
                vring->client_info.base,
                vring->client_info.inflight_addr);
        if (res != 0) {
            VHD_LOG_ERROR("virtq attach failed: %d", res);
            return res;
        }

        virtq_set_notify_fd(&vring->vq, vring->callfd);

        static const struct vhd_event_ops g_vring_ops = {
            .read = vring_io_event,
        };

        vring->kickev.priv = vring;
        vring->kickev.ops = &g_vring_ops;
        vring->is_enabled = true;
        res = vhd_attach_event(vring->vdev->rq, vring->kickfd, &vring->kickev);
        if (res != 0) {
            vring->is_enabled = false;
            virtio_virtq_release(&vring->vq);
            VHD_LOG_ERROR("Could not create vring event from kickfd: %d", res);
            return res;
        }

    } else {
        vhd_detach_event(vring->vdev->rq, vring->kickfd);
        vring->is_enabled = false;
        virtio_virtq_release(&vring->vq);
    }

    return 0;
}

void vhd_vring_init(struct vhd_vring *vring, int id, struct vhd_vdev *vdev)
{
    VHD_ASSERT(vring);

    /*
     * According to vhost spec we should check that PROTOCOL_FEATURES
     * have been negotiated with the client here. However we explicitly
     * don't support clients that don't negotiate it, so it makes no difference.
     */
    vring->is_enabled = false;

    vring->id = id;
    vring->kickfd = -1;
    vring->callfd = -1;
    vring->vdev = vdev;
}

void vhd_vring_stop(struct vhd_vring *vring)
{
    if (!vring || !vring->is_enabled) {
        return;
    }

    vring_set_enable(vring, false);
}

/*////////////////////////////////////////////////////////////////////////////*/

void *vhd_vdev_get_priv(struct vhd_vdev *vdev)
{
    return vdev->priv;
}

/* Return size of per queue inflight buffer. */
static uint64_t vring_inflight_buf_size(int num)
{
    uint64_t size;

    size = sizeof(struct inflight_split_region) +
        num * sizeof(struct inflight_split_desc);

    return size;
}

static void vring_inflight_addr_init(struct vhd_vring *vring)
{
    struct inflight_split_region *mem;
    uint64_t size;
    uint64_t qsize;
    uint8_t idx;

    vring->client_info.inflight_addr = NULL;

    mem = vring->vdev->inflight_mem;
    if (!mem) {
        return;
    }
    size = vring->vdev->inflight_size;
    idx = vring->id;
    qsize = vring_inflight_buf_size(vring->client_info.num);
    if (qsize * (idx + 1) > size) {
        VHD_LOG_WARN(
            "inflight buffer for queue %d ends at %lu and doesn't fit in buffer of size %lu",
            idx, qsize * (idx + 1), size);
        return;
    }

    vring->client_info.inflight_addr = (void *)mem + qsize * idx;
}

/**
 * metrics - output parameter.
 * Returns 0 on success, -errno on failure
 */
int vhd_vdev_get_queue_stat(struct vhd_vdev *vdev, uint32_t queue_num,
                            struct vhd_vq_metrics *metrics)
{
    VHD_VERIFY(vdev);

    if (queue_num >= vdev->num_queues) {
        return -EINVAL;
    }

    virtio_virtq_get_stat(&vdev->vrings[queue_num].vq, metrics);

    return 0;
}
