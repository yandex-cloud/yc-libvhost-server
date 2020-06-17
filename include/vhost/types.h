/**
 * Common types' definitions
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

struct vhd_buffer
{
    void* base;
    size_t len;

    /* Buffer is write-only if true and read-only if false */
    bool write_only;
};
