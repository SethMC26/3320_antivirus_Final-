#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <syslog.h>
#include "logger.h"

#define LOG_FILE_PATH "/var/log/pproc.log"

static FILE *log_file = NULL;
static LogLevel console_log_level = LL_INFO;
static LogLevel file_log_level = LL_INFO;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *level_strings[] = {
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG"};

void init_logger(const char *log_file_path, LogLevel console_level, LogLevel file_level)
{
    console_log_level = console_level;
    file_log_level = file_level;

    if (log_file_path)
    {
        log_file = fopen(log_file_path, "a");
        if (!log_file)
        {
            fprintf(stderr, "Failed to open log file: %s\n", log_file_path);
        }
    }

    openlog("pproc", LOG_PID | LOG_CONS, LOG_DAEMON);
}

void cleanup_logger(void)
{
    if (log_file)
    {
        fclose(log_file);
        log_file = NULL;
    }
    closelog();
}

void log_message(LogLevel level, const char *format, ...)
{
    pthread_mutex_lock(&log_mutex);

    time_t now;
    time(&now);
    char timestamp[26];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0'; // Remove newline

    va_list args;
    va_start(args, format);
    char message[1024];
    vsnprintf(message, sizeof(message), format, args);

    // Console output
    if (level <= console_log_level)
    {
        fprintf(stderr, "[%s] [%s] %s\n",
                timestamp, level_strings[level], message);
    }

    // File output
    if (log_file && level <= file_log_level)
    {
        fprintf(log_file, "[%s] [%s] %s\n",
                timestamp, level_strings[level], message);
        fflush(log_file);
    }

    // System log
    int syslog_priority;
    switch (level)
    {
    case LL_ERROR:
        syslog_priority = LOG_ERR;
        break;
    case LL_WARNING:
        syslog_priority = LOG_WARNING;
        break;
    case LL_INFO:
        syslog_priority = LOG_INFO;
        break;
    case LL_DEBUG:
        syslog_priority = LOG_DEBUG;
        break;
    default:
        syslog_priority = LOG_INFO;
        break;
    }
    syslog(syslog_priority, "%s", message);

    va_end(args);
    pthread_mutex_unlock(&log_mutex);
}
