#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <sys/queue.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1ul << PAGE_SHIFT)

////////////////////////////////////////////////////////////////////////////////

#if !defined(containerof)
#   define containerof(ptr, type, member) ((type *) ((char *)(ptr) - offsetof(type, member)))
#endif

#if !defined(countof)
#   define countof(a) (sizeof(a) / sizeof(*a))
#endif

// TODO: compiler-specifics for non-gcc?
#ifdef __GNUC__
#   define __STRINGIFY(x)           #x
#   define vhd_noreturn             __attribute__((noreturn))
#   define vhd_typeof               typeof
#   define VHD_PACKED               __attribute__((packed))

#   define VHD_CONTAINEROF(ptr, type, member) ({                \
        const typeof(((type *)0)->member)*__mptr = (ptr);       \
        (type *)((char *)__mptr - offsetof(type, member)); })
#else
#   error Implement me
#endif

#if !defined(MIN)
#   define MIN(num1, num2) ((num1) < (num2) ? (num1) : (num2))
#endif

#ifdef __cplusplus
#   define VHD_STATIC_ASSERT(pred) static_assert((pred), __STRINGIFY(pred))
#elif (__STDC_VERSION__ >= 201112L)
#   define VHD_STATIC_ASSERT(pred)  _Static_assert((pred), __STRINGIFY(pred))
#else
#   error Implement me
#endif

////////////////////////////////////////////////////////////////////////////////

// TODO: smarter logging
#ifdef _DEBUG
#   define VHD_LOG_DEBUG(fmt, ...)           \
    do {                                     \
        fprintf(stderr, "DEBUG: %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#   define VHD_LOG_DEBUG(fmt, ...)
#endif

#define VHD_LOG_INFO(fmt, ...)               \
    do {                                     \
        fprintf(stderr, "INFO: %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define VHD_LOG_WARN(fmt, ...)               \
    do {                                     \
        fprintf(stderr, "WARN: %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define VHD_LOG_ERROR(fmt, ...)              \
    do {                                     \
        fprintf(stderr, "ERROR: %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define VHD_LOG_TRACE() VHD_LOG_DEBUG("\n");

static inline void vhd_noreturn _vhd_verify_helper(
    const char* what,
    const char* file,
    unsigned long line)
{
    // TODO: smarter logging
    fprintf(stderr, "Verify failed: \"%s\" at %s:%lu\n", what, file, line);
    exit(EXIT_FAILURE);
}

#define VHD_ASSERT(cond) assert(cond)

// Verify is not compiled out in release builds
#define VHD_VERIFY(cond)                                  \
    do {                                                  \
        if (!(cond)) {                                    \
            _vhd_verify_helper(#cond, __FILE__, __LINE__); \
        }                                                 \
    } while (0);

////////////////////////////////////////////////////////////////////////////////

#ifdef VHD_MEMCHECK
#   include <valgrind/memcheck.h>
#   define VHD_MEMCHECK_DEFINED(addr, len)      VALGRIND_MAKE_MEM_DEFINED(addr, len)
#   define VHD_MEMCHECK_UNDEFINED(addr, len)    VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
#else
#   define VHD_MEMCHECK_DEFINED(addr, len)
#   define VHD_MEMCHECK_UNDEFINED(addr, len)
#endif

////////////////////////////////////////////////////////////////////////////////

#define __VHD_ALIGN_MASK(x,mask)    (((x) + (mask)) & ~(mask))
#define VHD_ALIGN_UP(x, a)          __VHD_ALIGN_MASK(x, (vhd_typeof(x))(a) - 1)
#define VHD_IS_ALIGNED(x, a)        (!((x) & ((vhd_typeof(x))(a) - 1)))

#define VHD_NEW(type)               vhd_zalloc(sizeof(type))

static inline void* vhd_alloc(size_t bytes)
{
    // malloc actually accepts 0 sizes, but this is still most likely a bug..
    VHD_ASSERT(bytes != 0);

    void* p = malloc(bytes);
    VHD_VERIFY(p != NULL);
    return p;
}

static inline void* vhd_zalloc(size_t bytes)
{
    // calloc actually accepts 0 sizes, but this is still most likely a bug..
    VHD_ASSERT(bytes != 0);

    void* p = calloc(bytes, 1);
    VHD_VERIFY(p != NULL);
    return p;
}

static inline void* vhd_calloc(size_t nmemb, size_t size)
{
    VHD_ASSERT(nmemb != 0 && size != 0);

    void* p = calloc(nmemb, size);
    VHD_VERIFY(p != NULL);
    return p;
}

// TODO: aligned alloc

static inline void vhd_free(void* p)
{
    free(p);
}

////////////////////////////////////////////////////////////////////////////////

static inline void vhd_compiler_barrier(void)
{
    __asm volatile(""
                   :
                   :
                   : "memory");
}

#define vhd_smp_mb  __sync_synchronize()

/* We assume only x86_64 where rmb and wmb are noops for normal memory types */
#define vhd_smp_rmb() vhd_compiler_barrier()
#define vhd_smp_wmb() vhd_compiler_barrier()

/* A wrapper to yield hardware thread in case of cpu-level multithreading */
static inline void vhd_yield_cpu(void)
{
#if defined(__x86_64__)
    __asm__ volatile("pause");
#else
#   error "Don't know how to pause on this architecture"
#endif
}

////////////////////////////////////////////////////////////////////////////////
