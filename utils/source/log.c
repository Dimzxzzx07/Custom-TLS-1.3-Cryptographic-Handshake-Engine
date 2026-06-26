#include "log.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static log_level_t current_log_level = LOG_LEVEL_INFO;
static void (*log_output_func)(const char* msg) = NULL;

void log_set_level(log_level_t level) {
    current_log_level = level;
}

void log_set_output(void (*output_func)(const char* msg)) {
    log_output_func = output_func;
}

static void log_printf(log_level_t level, const char* prefix, const char* format, va_list args) {
    if (level > current_log_level) return;
    
    char buffer[2048];
    int len = snprintf(buffer, sizeof(buffer), "[%s] ", prefix);
    if (len < 0) return;
    
    vsnprintf(buffer + len, sizeof(buffer) - len, format, args);
    
    if (log_output_func) {
        log_output_func(buffer);
    } else {
        puts(buffer);
    }
}

void log_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_printf(LOG_LEVEL_ERROR, "ERROR", format, args);
    va_end(args);
}

void log_warning(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_printf(LOG_LEVEL_WARNING, "WARN", format, args);
    va_end(args);
}

void log_info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_printf(LOG_LEVEL_INFO, "INFO", format, args);
    va_end(args);
}

void log_debug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_printf(LOG_LEVEL_DEBUG, "DEBUG", format, args);
    va_end(args);
}

void log_trace(const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_printf(LOG_LEVEL_TRACE, "TRACE", format, args);
    va_end(args);
}

void log_hexdump(log_level_t level, const char* label, const uint8_t* data, size_t len) {
    if (level > current_log_level || !data || len == 0) return;
    
    char buffer[2048];
    int pos = 0;
    
    if (label) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "[HEX] %s: ", label);
    }
    
    for (size_t i = 0; i < len && pos < (int)sizeof(buffer) - 4; i++) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%02X ", data[i]);
        if ((i + 1) % 16 == 0) {
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\n");
        }
    }
    
    if (log_output_func) {
        log_output_func(buffer);
    } else {
        puts(buffer);
    }
}
