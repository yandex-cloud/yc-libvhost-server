#pragma once

/*
 * This is a compiler barrier, it doesn't prevent the CPU from reordering loads
 * and stores in any way, but prevents compiler optimizations such as
 * reordering code around. Mostly used internally by this header to make other
 * helpers fully atomic.
 */
#define barrier()   __atomic_signal_fence(__ATOMIC_ACQ_REL)

/*
 * Reportedly atomic_thread_fence does not include a compiler barrier, so add
 * one here.
 */
#define smp_mb()                        \
    ({ barrier(); __atomic_thread_fence(__ATOMIC_SEQ_CST); })
#define smp_mb_release()                \
    ({ barrier(); __atomic_thread_fence(__ATOMIC_RELEASE); })
#define smp_mb_acquire()                \
    ({ barrier(); __atomic_thread_fence(__ATOMIC_ACQUIRE); })

/*
 * Reportedly current compilers promote consume order to acquire and
 * slow this down unnecessarily. This seems not to be the case on x86_64; need
 * to recheck if we ever build for another arch.
 */
#ifndef __x86_64__
#error Verify smp_read_barrier_depends incurs no extra costs
#endif
#define smp_read_barrier_depends()      \
    ({ barrier(); __atomic_thread_fence(__ATOMIC_CONSUME); })

#define smp_wmb()   smp_mb_release()
#define smp_rmb()   smp_mb_acquire()

#define atomic_read(ptr)       __atomic_load_n(ptr, __ATOMIC_RELAXED)
#define atomic_set(ptr, val)   __atomic_store_n(ptr, val, __ATOMIC_RELAXED)

#define atomic_load_acquire(ptr)        \
    __atomic_load_n(ptr, __ATOMIC_ACQUIRE)
#define atomic_store_release(ptr, val)  \
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE)

/*
 * atomic_rcu_read potentially has the same issue with consume order as
 * smp_read_barrier_depends, see above.
 */
#ifndef __x86_64__
#error Verify atomic_rcu_read incurs no extra costs
#endif
#define atomic_rcu_read(ptr)      __atomic_load_n(ptr, __ATOMIC_CONSUME)
#define atomic_rcu_set(ptr, val)  __atomic_store_n(ptr, val, __ATOMIC_RELEASE)

#define atomic_xchg(ptr, val)           \
    __atomic_exchange_n(ptr, val, __ATOMIC_SEQ_CST)
#define atomic_cmpxchg(ptr, old, new)    ({                                 \
    __auto_type _old = (old);                                               \
    (void) __atomic_compare_exchange_n(ptr, &_old, new, false,              \
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); \
    _old; })

#define atomic_fetch_add(ptr, n) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub(ptr, n) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_and(ptr, n) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_or(ptr, n)  __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor(ptr, n) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST)

#define atomic_fetch_inc(ptr) atomic_fetch_add(ptr, 1)
#define atomic_fetch_dec(ptr) atomic_fetch_sub(ptr, 1)

#define atomic_add(ptr, n) ((void) atomic_fetch_add(ptr, n))
#define atomic_sub(ptr, n) ((void) atomic_fetch_sub(ptr, n))
#define atomic_and(ptr, n) ((void) atomic_fetch_and(ptr, n))
#define atomic_or(ptr, n)  ((void) atomic_fetch_or(ptr, n))
#define atomic_xor(ptr, n) ((void) atomic_fetch_xor(ptr, n))
#define atomic_inc(ptr)    ((void) atomic_fetch_inc(ptr))
#define atomic_dec(ptr)    ((void) atomic_fetch_dec(ptr))
