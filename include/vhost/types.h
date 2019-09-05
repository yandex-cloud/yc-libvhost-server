/**
 * Common types' definitions
 */

#pragma once

#include <stdbool.h>

typedef uint64_t vhd_paddr_t;
typedef uint64_t vhd_uaddr_t;

struct vhd_buffer
{
    void* base;
    size_t len;

    /* Buffer is write-only if true and read-only if false */
    bool write_only;
};

static inline bool vhd_buffer_is_read_only(const struct vhd_buffer* buf)
{
    return !buf->write_only;
}

static inline bool vhd_buffer_is_write_only(const struct vhd_buffer* buf)
{
    return buf->write_only;
}

static inline bool vhd_buffer_can_read(const struct vhd_buffer* buf)
{
    return vhd_buffer_is_read_only(buf);
}

static inline bool vhd_buffer_can_write(const struct vhd_buffer* buf)
{
    return vhd_buffer_is_write_only(buf);
}
