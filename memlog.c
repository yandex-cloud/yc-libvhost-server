#include <stdatomic.h>
#include <string.h>

#include "catomic.h"
#include "logging.h"
#include "memlog.h"
#include "memmap.h"

struct vhd_memory_log {
    atomic_ulong *base;
    size_t size;
};

struct vhd_memory_log *vhd_memlog_new(size_t size, int fd, off_t offset)
{
    struct vhd_memory_log *log;
    void *base;

    base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (base == MAP_FAILED) {
        VHD_LOG_ERROR("mmap(%zu, %d, %zu): %s", size, fd, offset,
                      strerror(errno));
        return NULL;
    }

    log = vhd_alloc(sizeof(*log));
    *log = (struct vhd_memory_log) {
        .base = base,
        .size = size,
    };
    return log;
}

void vhd_memlog_free(struct vhd_memory_log *log)
{
    munmap(log->base, log->size);
    vhd_free(log);
}

#define VHOST_LOG_PAGE 0x1000

void vhd_mark_gpa_range_dirty(struct vhd_memory_log *log, uint64_t gpa,
                              size_t len)
{
    atomic_ulong *log_addr = log->base;
    if (!log_addr) {
        VHD_LOG_WARN("No logging addr set");
        return;
    }

    uint64_t log_size = log->size;

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

void vhd_mark_range_dirty(struct vhd_memory_log *log,
                          struct vhd_memory_map *mm, void *ptr, size_t len)
{
    uint64_t gpa = ptr_to_gpa(mm, ptr);
    if (gpa != TRANSLATION_FAILED) {
        vhd_mark_gpa_range_dirty(log, gpa, len);
    }
}
