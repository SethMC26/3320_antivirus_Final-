#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <linux/limits.h>

#include "Crypto/fingerprint.h"
#include "Utils/logger.h"
#include "Utils/fileHandler.h"
#include "scanner.h"

#define MAX_THREADS 10 // Max number of concurrent threads to avoid overload
// Path to the whitelist file
#define WHITELIST_PATH "/usr/local/share/pproc/whitelist.txt"

// Mutex for synchronization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread data structure to hold the file or directory path
typedef struct
{
    char *path;
    int is_directory; // 1 if directory, 0 if file
} thread_data_t;

int active_threads = 0;

// private method not included in header so we declare it here

/**
 * Scans over a list of hashes stored in file to see if any match target hash
 * @param target_hash String of hash to check for
 * @param target_file String of file of target_hash needed incase file is malicious
 * @param hash_file String of file with hash list
 * @param hash_buffer_size Size of buffer needed for hash
 *
 * @returns 0 if scan did not find a matching hash, 1 if scan did find a matching has, -1 for an error
 */
int scan_hashes(char *target_hash, char *target_file, char *hash_file, unsigned int hash_buffer_size, int automated_mode);

int is_whitelisted(const char* target_path) {
    int result = 0;
    pthread_mutex_lock(&whitelist_mutex);
    
    FILE* whitelist_file = fopen(WHITELIST_PATH, "r");
    if (whitelist_file == NULL) {
        log_message(LL_DEBUG, "Whitelist file not found, assuming file is not whitelisted");
        pthread_mutex_unlock(&whitelist_mutex);
        return 0;
    }

    char line[PATH_MAX];
    while (fgets(line, sizeof(line), whitelist_file)) {
        // Remove newline character
        line[strcspn(line, "\n")] = 0;
        
        if (strcmp(line, target_path) == 0) {
            result = 1;
            break;
        }
    }

    fclose(whitelist_file);
    pthread_mutex_unlock(&whitelist_mutex);
    return result;
}

void add_to_whitelist(const char* file_path) {
    pthread_mutex_lock(&whitelist_mutex);
    
    char command[PATH_MAX * 2];
    
    // Create directory and set permissions
    snprintf(command, sizeof(command), 
        "sudo sh -c '"
        "mkdir -p /usr/local/share/pproc && "
        "touch /usr/local/share/pproc/whitelist.txt && "
        "chmod 777 /usr/local/share/pproc && "
        "chmod 666 /usr/local/share/pproc/whitelist.txt'"
    );
    
    if (system(command) != 0) {
        log_message(LL_ERROR, "Failed to setup whitelist directory and permissions");
        pthread_mutex_unlock(&whitelist_mutex);
        return;
    }

    // Append to whitelist using echo and sudo
    snprintf(command, sizeof(command), 
        "echo '%s' | sudo tee -a /usr/local/share/pproc/whitelist.txt > /dev/null", 
        file_path
    );
    
    if (system(command) != 0) {
        log_message(LL_ERROR, "Failed to add entry to whitelist");
        pthread_mutex_unlock(&whitelist_mutex);
        return;
    }

    log_message(LL_INFO, "Added %s to whitelist", file_path);
    pthread_mutex_unlock(&whitelist_mutex);
}

int scan_file(char *target_file, int automated_mode)
{
    // Check whitelist before scanning
    if (is_whitelisted(target_file)) {
        log_message(LL_INFO, "Skipping whitelisted file: %s", target_file);
        return 0;
    }
    
    // Hold different hashes for this file
    char target_sha1_hash[SHA1_BUFFER_SIZE];
    char target_sha256_hash[SHA256_BUFFER_SIZE];
    char target_md5_hash[MD5_BUFFER_SIZE];
    int scan_result;

    log_message(LL_INFO, "Starting File Scan for %s", target_file);

    // scan over sha1 hashes
    log_message(LL_DEBUG, "Scanning sha-1 hashes for %s", target_file);

    if (sha1_fingerprint_file(target_file, target_sha1_hash) != 0) {
        log_message(LL_ERROR, "sha-1 file fingerprint failed for %s", target_file);
        return 1;
    }

    scan_result = scan_hashes(target_sha1_hash, target_file, "/usr/local/share/pproc/sha1-hashes.txt", SHA1_BUFFER_SIZE, automated_mode);
    if (scan_result == 1) {
        log_message(LL_WARNING, "Malicious file detected (SHA1) in %s", target_file);
        return 0;
    } else if (scan_result == -1) {
        log_message(LL_ERROR, "Could not scan sha1 hash list for %s", target_file);
        return 1;
    }

    log_message(LL_DEBUG, "SHA1 scan complete for %s", target_file);

    // scan over sha256 hashes
    log_message(LL_DEBUG, "Scanning sha-256 hashes for %s", target_file);

    if (sha256_fingerprint_file(target_file, target_sha256_hash) != 0)
    {
        log_message(LL_ERROR, "sha-256 file fingerprint failed for %s", target_file);
        return 1;
    }

    scan_result = scan_hashes(target_sha256_hash, target_file, "/usr/local/share/pproc/sha256-hashes.txt", SHA256_BUFFER_SIZE, automated_mode);
    if (scan_result == 1)
    {
        log_message(LL_WARNING, "Malicious file detected (SHA256) in %s", target_file);
        return 0;
    }
    else if (scan_result == -1)
    {
        log_message(LL_ERROR, "Could not scan sha-256 hash list for %s", target_file);
        return 1;
    }

    log_message(LL_DEBUG, "SHA256 scan complete for %s", target_file);

    // scan over md5 hashes
    log_message(LL_DEBUG, "Scanning md5 hashes for %s", target_file);

    if (md5_fingerprint_file(target_file, target_md5_hash) != 0)
    {
        log_message(LL_ERROR, "md5 file fingerprint failed for %s", target_file);
        return 1;
    }

    scan_result = scan_hashes(target_md5_hash, target_file, "/usr/local/share/pproc/md5-hashes.txt", MD5_BUFFER_SIZE, automated_mode);
    if (scan_result == 1)
    {
        log_message(LL_WARNING, "Malicious file detected (MD5) in %s", target_file);
        return 0;
    }
    else if (scan_result == -1)
    {
        log_message(LL_ERROR, "Could not scan sha-256 hash list for %s", target_file);
        return 1;
    }

    log_message(LL_DEBUG, "MD5 scan complete for %s", target_file);

    log_message(LL_DEBUG, "sha-1 hash: %s", target_sha1_hash);
    log_message(LL_DEBUG, "sha-256 hash: %s", target_sha256_hash);
    log_message(LL_DEBUG, "md5 hash: %s", target_md5_hash);

    return 0;
}

void *scan_file_thread(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    log_message(LL_DEBUG, "Thread started for path: %s", data->path);

    if (data->is_directory)
    {
        // If it's a directory, recursively scan it
        scan_dir(data->path);
    }
    else
    {
        // If it's a file, scan it
        log_message(LL_INFO, "Scanning file: %s", data->path);
        scan_file(data->path, 0);  // 0 for non-automated mode
    }

    log_message(LL_DEBUG, "Freeing resources for path: %s", data->path);
    free(data->path);
    free(data);

    pthread_exit(NULL);
}

/**
 * Scans a directory and spawns threads to scan its files
 * @param target_dir String of target directory to scan
 * @return int 0 if success, 1 if error
 */
int scan_dir(char *target_dir)
{
    log_message(LL_INFO, "Starting directory scan: %s", target_dir);

    DIR *dir = opendir(target_dir);
    if (dir == NULL)
    {
        log_message(LL_ERROR, "Error opening directory: %s", target_dir);
        return 1;
    }

    struct dirent *entry;
    pthread_t threads[MAX_THREADS];
    int thread_indices[MAX_THREADS] = {0};
    int local_active_threads = 0;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", target_dir, entry->d_name);

        struct stat statbuf;
        if (stat(path, &statbuf) == -1)
        {
            log_message(LL_ERROR, "Error getting file status for %s", path);
            continue;
        }

        thread_data_t *data = malloc(sizeof(thread_data_t));
        if (data == NULL)
        {
            log_message(LL_ERROR, "Memory allocation failed for path: %s", path);
            continue;
        }
        data->path = strdup(path);
        data->is_directory = S_ISDIR(statbuf.st_mode);

        // If we've reached max threads, wait for some to complete
        if (local_active_threads >= MAX_THREADS)
        {
            // Wait for all current threads to finish
            for (int i = 0; i < MAX_THREADS; i++)
            {
                if (thread_indices[i])
                {
                    pthread_join(threads[i], NULL);
                    thread_indices[i] = 0;
                }
            }
            local_active_threads = 0;
        }

        // Create new thread
        int slot = -1;
        for (int i = 0; i < MAX_THREADS; i++)
        {
            if (thread_indices[i] == 0)
            {
                slot = i;
                thread_indices[i] = 1;
                break;
            }
        }

        if (slot != -1)
        {
            pthread_create(&threads[slot], NULL, scan_file_thread, (void *)data);
            local_active_threads++;
        }
    }

    // Wait for remaining threads to complete
    for (int i = 0; i < MAX_THREADS; i++)
    {
        if (thread_indices[i])
        {
            pthread_join(threads[i], NULL);
        }
    }

    log_message(LL_INFO, "Finished scanning directory: %s", target_dir);
    closedir(dir);
    return 0;
}

/**
 * Scans the entire system by calling scan_dir on the root directory
 * @return int 0 if success, 1 if error
 */
int scan_system()
{
    log_message(LL_INFO, "Starting system scan...");
    int result = scan_dir("/"); // Scan from root directory
    if (result == 0)
    {
        log_message(LL_INFO, "System scan completed successfully.");
    }
    else
    {
        log_message(LL_ERROR, "System scan failed.");
    }
    return result; // Return the result from scan_dir
}

int scan_hashes(char *target_hash, char *target_file, char *hash_file, unsigned int hash_buffer_size, int automated_mode)
{
    char *current_hash = malloc(hash_buffer_size);
    FILE *hashes = fopen(hash_file, "r");

    if (hashes == NULL) {
        log_message(LL_ERROR, "Could not find hash file %s", hash_file);
        free(current_hash);
        return -1;
    }

    while (fgets(current_hash, hash_buffer_size, hashes)) {
        if (strcmp(current_hash, target_hash) == 0) {
            log_message(LL_WARNING, "Malicious file detected: %s", target_file);
            
            struct stat file_stat;
            unsigned int file_permissions;

            if (stat(target_file, &file_stat) == -1) {
                log_message(LL_ERROR, "Could not stat file %s", target_file);
                free(current_hash);
                fclose(hashes);
                return -1;
            }

            file_permissions = file_stat.st_mode;

            if (chmod(target_file, S_IRUSR | S_IRGRP | S_IROTH) == -1) {
                log_message(LL_ERROR, "Failed to change file permissions");
                free(current_hash);
                fclose(hashes);
                return 1;
            }

            if (automated_mode) {
                log_message(LL_INFO, "Automated mode: Removing malicious file %s", target_file);
                if (remove(target_file) != 0) {
                    log_message(LL_ERROR, "Failed to remove file in automated mode: %s", strerror(errno));
                }
            } else {
                printf("\nPossible malicious file detected: %s", target_file);
                if (get_user_input("\nWould you like to remove the file Y/N:") == 1) {
                    log_message(LL_INFO, "Removing file %s", target_file);
                    if (remove(target_file) != 0) {
                        log_message(LL_ERROR, "Failed to remove file: %s", strerror(errno));
                    }
                } else {
                    if (get_user_input("\nWould you like to quarantine the file Y/N:") == 1) {
                        struct stat st = {0};
                        if (stat("/usr/local/share/pproc/quarantine", &st) == -1) {
                            if (mkdir("/usr/local/share/pproc/quarantine", 0777) == -1) {
                                log_message(LL_ERROR, "Failed to create quarantine directory: %s", strerror(errno));
                                chmod(target_file, file_permissions);
                                break;
                            }
                            chmod("/usr/local/share/pproc/quarantine", 0777);
                        }

                        const char *filename = strrchr(target_file, '/');
                        filename = filename ? filename + 1 : target_file;
                        
                        char quarantine_path[PATH_MAX];
                        snprintf(quarantine_path, sizeof(quarantine_path), 
                                "/usr/local/share/pproc/quarantine/%s", filename);

                        // Open source file
                        FILE *src = fopen(target_file, "rb");
                        if (!src) {
                            log_message(LL_ERROR, "Failed to open source file for quarantine: %s", strerror(errno));
                            chmod(target_file, file_permissions);
                            break;
                        }

                        // Open destination file with explicit permissions
                        FILE *dst = fopen(quarantine_path, "wb");
                        if (!dst) {
                            log_message(LL_ERROR, "Failed to open quarantine destination: %s", strerror(errno));
                            fclose(src);
                            chmod(target_file, file_permissions);
                            break;
                        }

                        // Set permissions on the quarantine file
                        chmod(quarantine_path, 0666);

                        // Copy file contents
                        char buf[8192];
                        size_t size;
                        int copy_success = 1;
                        
                        while ((size = fread(buf, 1, sizeof(buf), src)) > 0) {
                            if (fwrite(buf, 1, size, dst) != size) {
                                copy_success = 0;
                                break;
                            }
                        }

                        fclose(src);
                        fclose(dst);

                        if (copy_success) {
                            // Log the original path and permissions before removing the file
                            FILE *quarantine_log = fopen("/usr/local/share/pproc/quarantine_log.txt", "a");
                            if (quarantine_log) {
                                fprintf(quarantine_log, "%s %o\n", target_file, file_permissions);
                                fclose(quarantine_log);
                            } else {
                                log_message(LL_ERROR, "Failed to open quarantine log file");
                            }

                            if (remove(target_file) == 0) {
                                log_message(LL_INFO, "File quarantined successfully: %s", filename);
                            } else {
                                log_message(LL_ERROR, "Failed to remove original file after quarantine: %s", strerror(errno));
                                chmod(target_file, file_permissions);
                                remove(quarantine_path);
                            }
                        } else {
                            log_message(LL_ERROR, "Failed to copy file to quarantine: %s", strerror(errno));
                            chmod(target_file, file_permissions);
                            remove(quarantine_path);
                        }
                    } else {
                        if (get_user_input("\nWould you like to add this file to the whitelist Y/N:") == 1) {
                            add_to_whitelist(target_file);
                        }
                        chmod(target_file, file_permissions);
                    }
                }
            }
            
            free(current_hash);
            fclose(hashes);
            return 1;
        }
    }

    free(current_hash);
    fclose(hashes);
    return 0;
}