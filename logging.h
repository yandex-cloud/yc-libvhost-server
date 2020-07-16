#pragma once

#include "platform.h"

#include "vhost/server.h"

extern log_function __attribute__((format(printf, 2, 3))) g_log_fn;

#define VHD_LOG(level, fmt, ...)                                \
    do {                                                        \
        if (g_log_fn) {                                         \
            g_log_fn(level, "%s:%d: " fmt,                      \
                     __func__, __LINE__, ##__VA_ARGS__);        \
        }                                                       \
    } while (0)

#ifdef VHD_DEBUG
#   define VHD_LOG_DEBUG(fmt, ...) VHD_LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#   define VHD_LOG_DEBUG(fmt, ...)
#endif

#define VHD_LOG_INFO(fmt, ...)     VHD_LOG(LOG_INFO, fmt, ##__VA_ARGS__)

#define VHD_LOG_WARN(fmt, ...)     VHD_LOG(LOG_WARNING, fmt, ##__VA_ARGS__)

#define VHD_LOG_ERROR(fmt, ...)    VHD_LOG(LOG_ERROR, fmt, ##__VA_ARGS__)

#define VHD_LOG_TRACE()            VHD_LOG_DEBUG("")
