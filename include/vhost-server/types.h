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
    bool writable;
};
