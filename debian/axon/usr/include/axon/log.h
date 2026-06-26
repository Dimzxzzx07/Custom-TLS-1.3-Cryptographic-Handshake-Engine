#ifndef LOGGING_H
#define LOGGING_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    LOG_LEVEL_NONE,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE
} log_level_t;

void log_set_level(log_level_t level);
void log_set_output(void (*output_func)(const char* msg));
void log_error(const char* format, ...);
void log_warning(const char* format, ...);
void log_info(const char* format, ...);
void log_debug(const char* format, ...);
void log_trace(const char* format, ...);
void log_hexdump(log_level_t level, const char* label, const uint8_t* data, size_t len);

#endif