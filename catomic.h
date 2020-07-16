/*
 * More traditional interfaces to atomic operations.
 * Modelled after QEMU qemu/atomic.h, but fully relying on C11 stdatomic.
 * References:
 *    https://en.wikipedia.org/wiki/Memory_ordering
 *    https://en.cppreference.com/w/c/atomic
 *    QEMU docs/devel/atomics.rst
 *
 * Note: definitions in this file use standard C11 names (e.g.
 * atomic_load_explicit, memory_order_acq_rel) rather than GCC intrinsics and
 * macros (__atomic_load_n, __ATOMIC_ACQ_REL).  With clang they translate to
 * clang intrinsics that also check the type to be _Atomic-qualified.
 */

#pragma once

#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#endif

/* Compiler barrier */
#define barrier()   atomic_signal_fence(memory_order_acq_rel)

/*
 * Reportedly atomic_thread_fence does not include a compiler barrier, so add
 * one here.
 */
#define smp_mb()                        \
    ({ barrier(); atomic_thread_fence(memory_order_seq_cst); })
#define smp_mb_release()                \
    ({ barrier(); atomic_thread_fence(memory_order_release); })
#define smp_mb_acquire()                \
    ({ barrier(); atomic_thread_fence(memory_order_acquire); })
/*
 * FIXME: reportedly current compilers promote consume order to acquire and
 * slow this down unnecessarily.  This seems not to be the case on x86_64; need
 * to recheck if we ever build for another arch.
 */
#ifndef __x86_64__
#error Verify smp_read_barrier_depends incurs no extra costs
#endif
#define smp_read_barrier_depends()      \
    ({ barrier(); atomic_thread_fence(memory_order_consume); })

#define smp_wmb()   smp_mb_release()
#define smp_rmb()   smp_mb_acquire()

#define atomic_read(ptr)                \
    atomic_load_explicit(ptr, memory_order_relaxed)
#define atomic_set(ptr, val)            \
    atomic_store_explicit(ptr, val, memory_order_relaxed)

#define atomic_load_acquire(ptr)        \
    atomic_load_explicit(ptr, memory_order_acquire)
#define atomic_store_release(ptr, val)  \
    atomic_store_explicit(ptr, val, memory_order_release)

/*
 * FIXME: atomic_rcu_read potentially has the same issue with consume order as
 * smp_read_barrier_depends, see above.
 */
#ifndef __x86_64__
#error Verify atomic_rcu_read incurs no extra costs
#endif
#define atomic_rcu_read(ptr)    \
    atomic_load_explicit(ptr, memory_order_consume)
#define atomic_rcu_set(ptr, val)        \
    atomic_store_explicit(ptr, val, memory_order_release)

/* All the remaining operations are fully sequentially consistent */
#define atomic_xchg(ptr, val)           \
    atomic_exchange(ptr, val)
#define atomic_cmpxchg(ptr, old, new)    ({                     \
    __auto_type _old = (old);                                  \
    (void) atomic_compare_exchange_strong(ptr, &_old, new);     \
    _old; })



#define atomic_fetch_inc(ptr) atomic_fetch_add(ptr, 1)
#define atomic_fetch_dec(ptr) atomic_fetch_sub(ptr, 1)

#define atomic_inc(ptr)    ((void) atomic_fetch_add(ptr, 1))
#define atomic_dec(ptr)    ((void) atomic_fetch_sub(ptr, 1))
#define atomic_add(ptr, n) ((void) atomic_fetch_add(ptr, n))
#define atomic_sub(ptr, n) ((void) atomic_fetch_sub(ptr, n))
#define atomic_and(ptr, n) ((void) atomic_fetch_and(ptr, n))
#define atomic_or(ptr, n)  ((void) atomic_fetch_or(ptr, n))
#define atomic_xor(ptr, n) ((void) atomic_fetch_xor(ptr, n))
