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

static void vring_inflight_addr_init(struct vhd_vring *vring)
{
    struct inflight_split_region *mem;
    uint64_t size;
    uint64_t qsize;
    uint16_t idx = vring_idx(vring);

    mem = vring->vdev->inflight_mem;
    if (!mem) {
        return;
    }
    size = vring->vdev->inflight_size;
    qsize = vring_inflight_buf_size(vring->vq.qsz);
    if (qsize * (idx + 1) > size) {
        VHD_LOG_WARN(
            "inflight buffer for queue %d ends at %lu and doesn't fit in buffer of size %lu",
            idx, qsize * (idx + 1), size);
        return;
    }

    vring->vq.inflight_region = (void *)mem + qsize * idx;
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

    vring_inflight_addr_init(vring);
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
    struct vhost_user_msg reply = {
        .req = msgin->req,
        .size = sizeof(u64),
        .flags = VHOST_USER_MSG_FLAGS_REPLY,
        .payload.u64 = u64,
    };

    return vhost_send(vdev, &reply);
}

static int vhost_send_vring_base(struct vhd_vring *vring)
{
    int ret;
    uint16_t idx = vring_idx(vring);
    struct vhost_user_msg reply = {
        .req = VHOST_USER_GET_VRING_BASE,
        .size = sizeof(reply.payload.vring_state),
        .flags = VHOST_USER_MSG_FLAGS_REPLY,
        .payload.vring_state = {
            .index = idx,
            .num = vring->vq.last_avail,
        },
    };

    ret = vhost_send(vring->vdev, &reply);
    if (ret) {
        VHD_LOG_ERROR("Can't send vring base to master. vring id: %d", idx);
    }
    return ret;
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

    return 0;
}

static int vhost_set_owner(struct vhd_vdev *vdev, struct vhost_user_msg *msg)
{
    VHD_LOG_TRACE();
    VHD_UNUSED(vdev);
    VHD_UNUSED(msg);
    return 0;
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

    config->size = vdev->type->get_config(vdev, config->payload,
                                          config->size, config->offset);

    /* zero-fill leftover space */
    memset(config->payload + config->size,
           0,
           msg->size - VHOST_CONFIG_HDR_SIZE - config->size);

    msg->flags = VHOST_USER_MSG_FLAGS_REPLY;

    return vhost_send(vdev, msg);
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

    void *desc_addr = map_uva(vdev->guest_memmap, vraddr->desc_addr);
    void *used_addr = map_uva(vdev->guest_memmap, vraddr->used_addr);
    void *avail_addr = map_uva(vdev->guest_memmap, vraddr->avail_addr);

    if (!vring->is_started) {
        if (!desc_addr || !used_addr || !avail_addr) {
            VHD_LOG_ERROR("invalid vring %d component address (%p, %p, %p)",
                vraddr->index, desc_addr, used_addr, avail_addr);
            return EINVAL;
        }

        vring->vq.flags = vraddr->flags;
        vring->vq.desc = desc_addr;
        vring->vq.used = used_addr;
        vring->vq.avail = avail_addr;
        vring->vq.used_gpa_base = vraddr->used_gpa_base;
    } else {
        if (vring->vq.desc != desc_addr ||
            vring->vq.used != used_addr ||
            vring->vq.avail != avail_addr ||
            vring->vq.used_gpa_base != vraddr->used_gpa_base)
        {
            VHD_LOG_ERROR("Enabled vring parameters mismatch");
            return EINVAL;
        }
        vring->vq.flags = vraddr->flags;
    }


    return 0;
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
    int ret;
    void *buf;

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        ret = -errno;
        VHD_LOG_ERROR("can't mmap fd = %d, size = %lu", fd, size);
        return ret;
    }
    vdev->inflight_mem = buf;
    vdev->inflight_size = size;

    return 0;
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
        ret = -errno;
        VHD_LOG_ERROR("can't create memfd object");
        return ret;
    }
    ret = ftruncate(fd, size);
    if (ret == -1) {
        ret = -errno;
        VHD_LOG_ERROR("can't truncate fd = %d, to size = %lu", fd, size);
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
    int ret = 0;

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
        ret = vhost_set_mem_table(vdev, msg, fds, num_fds);
        break;
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
        VHD_LOG_WARN("Command = %d, not supported", msg->req);
        ret = -ENOTSUP;
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

    VHD_ASSERT(vring->refcount >= 0);

    /*
     * vring->refcount == 0 only when we unref-ed vring
     * for disabling
     */
    if (!vring->refcount) {
        if (vring->on_drain_cb) {
            vring->on_drain_cb(vring);
            vring_clear_on_drain_cb(vring);
            virtio_virtq_release(&vring->vq);
        }
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
    vhd_run_in_rq(vdev->rq, vdev_unregister_bh, vdev);

    vdev_complete_work(vdev, 0);
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
