#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "Utils/scanner.h"
#include "pproc-service.h"

// Directory to watch for new files
#define WATCH_DIR "/home/user/Downloads/"

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
    // Log the file path before starting the scan
    char log_msg[1024];
    snprintf(log_msg, sizeof(log_msg), "Starting scan for new file: %s", file_path);
    log_message_service(log_msg);

    // Cast file_path to a non-const char* as expected by scan_file function
    scan_file((char*)file_path);

    // Log the file path after the scan is complete
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
