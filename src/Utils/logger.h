#ifndef LOGGER_H
#define LOGGER_H

typedef enum
{
    LL_ERROR = 0,
    LL_WARNING = 1,
    LL_INFO = 2,
    LL_DEBUG = 3
} LogLevel;

void init_logger(const char *log_file_path, LogLevel console_level, LogLevel file_level);
void cleanup_logger(void);
void log_message(LogLevel level, const char *format, ...);

// Renamed macros to avoid conflicts
#define LOG_ERR_MSG(format, ...) log_message(LL_ERROR, format, ##__VA_ARGS__)
#define LOG_WARN_MSG(format, ...) log_message(LL_WARNING, format, ##__VA_ARGS__)
#define LOG_INFO_MSG(format, ...) log_message(LL_INFO, format, ##__VA_ARGS__)
#define LOG_DEBUG_MSG(format, ...) log_message(LL_DEBUG, format, ##__VA_ARGS__)

#endif