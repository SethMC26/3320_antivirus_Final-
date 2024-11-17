#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/limits.h>

#include "Crypto/fingerprint.h"
#include "Utils/logger.h"
#include "Utils/fileHandler.h"
#include "scanner.h"

#define MAX_THREADS 10 // Max number of concurrent threads to avoid overload

pthread_mutex_t file_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
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

int scan_file(char *target_file, int automated_mode)
{
    // Check whitelist before scanning
    pthread_mutex_lock(&whitelist_mutex);
    if (is_whitelisted(target_file)) {
        log_message(LL_INFO, "Skipping whitelisted file: %s", target_file);
        return 0;
    }
    pthread_mutex_unlock(&whitelist_mutex);
    
    // Hold different hashes for this file
    char target_sha1_hash[SHA1_BUFFER_SIZE];
    char target_sha256_hash[SHA256_BUFFER_SIZE];
    char target_md5_hash[MD5_BUFFER_SIZE];

    //hold result of scan
    int scan_result;

    log_message(LL_DEBUG, "Starting File Scan for %s", target_file);

    // scan over sha1 hashes
    log_message(LL_DEBUG, "Scanning sha-1 hashes for %s", target_file);

    if (sha1_fingerprint_file(target_file, target_sha1_hash) != 0) {
        log_message(LL_ERROR, "sha-1 file fingerprint failed for %s", target_file);
        return 1;
    }

    scan_result = scan_hashes(target_sha1_hash, target_file, "/usr/local/share/pproc/sha1-hashes.txt", SHA1_BUFFER_SIZE, automated_mode);

    if (scan_result == 1) {
        log_message(LL_INFO, "Malicious file detected (SHA1) in %s", target_file);
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
        log_message(LL_DEBUG, "Scanning file: %s", data->path);
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
    log_message(LL_DEBUG, "Starting directory scan: %s", target_dir);

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

    log_message(LL_DEBUG, "Finished scanning directory: %s", target_dir);
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
            //free resources we found out the file is bad
            free(current_hash);
            fclose(hashes);

            //handle the file only one thread should do this at a time 
            pthread_mutex_lock(&file_handler_mutex);

            if (handle_malicious_file(target_file) != 0) {
                log_message(LL_ERROR, "Could not proprely deal with file");
                pthread_mutex_unlock(&file_handler_mutex);
                return -1;
            }

            pthread_mutex_unlock(&file_handler_mutex);
            
            return 1;
        }
    }

    free(current_hash);
    fclose(hashes);
    return 0;
}