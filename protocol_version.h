#ifndef PROTOCOL_VERSION_H
#define PROTOCOL_VERSION_H

#include <stdint.h>

// Version packing and unpacking
#define MAKE_VERSION(major, minor) (((uint16_t)(major) << 8) | ((uint16_t)(minor)))
#define GET_MAJOR(version) (((version) >> 8) & 0xFF)
#define GET_MINOR(version) ((version) & 0xFF)

// Current and supported protocol versions
#define PROTOCOL_VERSION MAKE_VERSION(1, 0)
#define PROTOCOL_VERSION_MIN MAKE_VERSION(1, 0)
#define PROTOCOL_VERSION_MAX MAKE_VERSION(1, 1)

#endif // PROTOCOL_VERSION_H