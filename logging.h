#pragma once

#include "platform.h"

// TODO: smarter logging
#define VHD_LOG(level, fmt, ...)         \
do {                                     \
        fprintf(stderr, level ": %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#ifdef VHD_DEBUG
#   define VHD_LOG_DEBUG(fmt, ...) VHD_LOG("DEBUG", fmt, ##__VA_ARGS__)
#else
#   define VHD_LOG_DEBUG(fmt, ...)
#endif

#define VHD_LOG_INFO(fmt, ...)     VHD_LOG("INFO", fmt, ##__VA_ARGS__)

#define VHD_LOG_WARN(fmt, ...)     VHD_LOG("WARN", fmt, ##__VA_ARGS__)

#define VHD_LOG_ERROR(fmt, ...)    VHD_LOG("ERROR", fmt, ##__VA_ARGS__)

#define VHD_LOG_TRACE()            VHD_LOG_DEBUG("")
