#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "Utils/scanner.h"
#include "pproc-service.h"

// Directory to watch for new files
#define DEFAULT_DOWNLOADS_DIR "/Downloads"

const char* get_downloads_dir() {
    static char downloads_dir[PATH_MAX];
    FILE *fp = popen("xdg-user-dir DOWNLOAD", "r");
    if (fp == NULL) {
        perror("Failed to run xdg-user-dir command");
        return "/tmp"; // Fallback if command fails
    }

    if (fgets(downloads_dir, sizeof(downloads_dir), fp) != NULL) {
        // Remove newline character from the end
        downloads_dir[strcspn(downloads_dir, "\n")] = '\0';
    } else {
        // Fallback to home directory if xdg-user-dir fails
        const char* home_dir = getenv("HOME");
        if (home_dir) {
            snprintf(downloads_dir, sizeof(downloads_dir), "%s%s", home_dir, DEFAULT_DOWNLOADS_DIR);
        } else {
            strcpy(downloads_dir, "/tmp");
        }
    }

    pclose(fp);
    return downloads_dir;
}

#define WATCH_DIR get_downloads_dir()

// Log file
#define LOG_FILE "/var/log/pproc-service.log"

// Function to log messages
void log_message_service(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char time_buffer[26];
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(log_file, "[%s] %s\n", time_buffer, message);
        fclose(log_file);
    }
}

// Function to handle file scanning when a new file is created
void handle_new_file(const char *file_path) {
    char log_msg[1024];
    snprintf(log_msg, sizeof(log_msg), "Starting scan for new file: %s", file_path);
    log_message_service(log_msg);

    // Call scan_file with automated_mode = 1
    scan_file((char*)file_path);

    snprintf(log_msg, sizeof(log_msg), "Scan complete for file: %s", file_path);
    log_message_service(log_msg);
}

// Main function that monitors the directory and scans new files
void start_pproc_service() {
    int fd = inotify_init();
    if (fd == -1) {
        perror("inotify_init failed");
        return;
    }

    int wd = inotify_add_watch(fd, WATCH_DIR, IN_CREATE | IN_MOVED_TO);
    if (wd == -1) {
        perror("inotify_add_watch failed");
        return;
    }

    char buffer[1024];
    while (1) {
        int length = read(fd, buffer, sizeof(buffer));
        if (length < 0) {
            perror("Read error");
            break;
        }

        for (int i = 0; i < length; i += sizeof(struct inotify_event) + ((struct inotify_event *)&buffer[i])->len) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->mask & IN_CREATE || event->mask & IN_MOVED_TO) {
                char file_path[512];
                snprintf(file_path, sizeof(file_path), "%s/%s", WATCH_DIR, event->name);

                // Log the event of a new file being detected
                char log_msg[1024];
                snprintf(log_msg, sizeof(log_msg), "New file detected: %s", file_path);
                log_message_service(log_msg);

                handle_new_file(file_path);
            }
        }
    }

    close(fd);
}

#ifdef SERVICE_MAIN
// Main function for the service (to be compiled only for the service program)
int main() {
    log_message_service("Starting pproc-service...");
    start_pproc_service();  // Call the service function to start monitoring the directory
    return 0;  // We return 0 to indicate the program ran successfully
}
#endif
