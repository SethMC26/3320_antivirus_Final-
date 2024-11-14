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
#include "scanner.h"

// Thread data structure to hold the file or directory path
typedef struct
{
    char *path;
    int is_directory; // 1 if directory, 0 if file
} thread_data_t;

#define MAX_THREADS 10 // Max number of concurrent threads to avoid overload

// Mutex for synchronization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

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
int scan_hashes(char *target_hash, char *target_file, char *hash_file, unsigned int hash_buffer_size);

/**
 * Gets yes or no user input
 *
 * @param prompt String with prompt for user
 *
 * @returns 1 if yes 0 if no
 */
int get_user_input(char *prompt);

int scan_file(char *target_file)
{
    // TO:DO add logic for scanning a file
    // may want to change how return works as needed

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

    scan_result = scan_hashes(target_sha1_hash, target_file, "/usr/local/share/pproc/sha1-hashes.txt", SHA1_BUFFER_SIZE);
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

    scan_result = scan_hashes(target_sha256_hash, target_file, "/usr/local/share/pproc/sha256-hashes.txt", SHA256_BUFFER_SIZE);
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

    scan_result = scan_hashes(target_md5_hash, target_file, "/usr/local/share/pproc/md5-hashes.txt", MD5_BUFFER_SIZE);
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

    if (!data->is_directory)
    {
        log_message(LL_INFO, "Scanning file: %s", data->path);
        scan_file(data->path); // Call your existing scan_file function
    }

    log_message(LL_DEBUG, "Freeing resources for path: %s", data->path);
    free(data->path); // Free the allocated memory for the path
    free(data);       // Free the thread data structure

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
    pthread_t threads[MAX_THREADS]; // Array of threads
    int thread_count = 0;

    log_message(LL_INFO, "Scanning directory: %s", target_dir);

    // Iterate over each entry in the directory
    while ((entry = readdir(dir)) != NULL)
    {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        // Construct the full path of the entry
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", target_dir, entry->d_name);

        struct stat statbuf;
        if (stat(path, &statbuf) == -1)
        {
            log_message(LL_ERROR, "Error getting file status for %s", path);
            continue;
        }

        // Check if it's a directory or a file
        if (S_ISDIR(statbuf.st_mode))
        {
            // If it's a directory, recursively scan it (also threaded)
            log_message(LL_DEBUG, "Directory found: %s", path); // Log the path of the subdirectory being scanned

            thread_data_t *data = malloc(sizeof(thread_data_t));
            if (data == NULL)
            {
                log_message(LL_ERROR, "Memory allocation failed for path: %s", path);
                continue;
            }
            data->path = strdup(path);
            data->is_directory = 1;

            // Check if we have space to create a new thread
            if (thread_count < MAX_THREADS)
            {
                log_message(LL_DEBUG, "Creating thread for directory: %s", path);
                pthread_create(&threads[thread_count], NULL, scan_file_thread, (void *)data);
                thread_count++;
            }
            else
            {
                // If max threads reached, wait for some to finish
                for (int i = 0; i < MAX_THREADS; i++)
                {
                    pthread_join(threads[i], NULL);
                }
                // Reset thread counter
                thread_count = 0;
            }
        }
        else
        {
            // If it's a file, scan it
            log_message(LL_DEBUG, "File found: %s", path); // Print the path of the file being scanned

            thread_data_t *data = malloc(sizeof(thread_data_t));
            data->path = strdup(path);
            data->is_directory = 0;

            // Check if we have space to create a new thread
            if (thread_count < MAX_THREADS)
            {
                pthread_create(&threads[thread_count], NULL, scan_file_thread, (void *)data);
                thread_count++;
            }
            else
            {
                // If max threads reached, wait for some to finish
                for (int i = 0; i < MAX_THREADS; i++)
                {
                    pthread_join(threads[i], NULL);
                }
                // Reset thread counter
                thread_count = 0;
            }
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < thread_count; i++)
    {
        pthread_join(threads[i], NULL);
    }

    log_message(LL_INFO, "Finished scanning directory: %s", target_dir);
    closedir(dir);
    return 0; // Return 0 for success
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

int scan_hashes(char *target_hash, char *target_file, char *hash_file, unsigned int hash_buffer_size)
{
    // current hash in hash list
    char *current_hash = malloc(hash_buffer_size);

    // open list of malicious hashes
    FILE *hashes = fopen(hash_file, "r");

    if (hashes == NULL) {
        log_message(LL_ERROR, "Could not find hash file %s", hash_file);
        return -1;
    }

    // go line by line through malicious hashes and see if the file hash matches
    while (fgets(current_hash, hash_buffer_size, hashes)) {
        // if file malicious file is detected ask user if we should remove it
        if (strcmp(current_hash, target_hash) == 0) {
            log_message(LL_WARNING, "Malicious file detected: %s", target_file);
            
            // save original file permissions in case we should restore
            struct stat file_stat;
            unsigned int file_permissions;

            if (stat(target_file, &file_stat) == -1) {
                log_message(LL_ERROR, "Could not stat file %s", target_file);
                return -1;
            }

            file_permissions = file_stat.st_mode;

            // set file to readonly mode
            if (chmod(target_file, S_IRUSR | S_IRGRP | S_IROTH) == -1)
            {
                log_message(LL_ERROR, "Failed to change file permissions");
                return 1;
            }

            log_message(LL_WARNING, "Possible malicious file detected: %s", target_file);

            switch (get_user_input("Would you like to remove the file Y/N:"))
            {
            case 0:
                // restore file permissions
                chmod(target_file, file_permissions);
                // add to white list
                log_message(LL_INFO, "Add file to white list feature not implemented");
                break;
            case 1:
                // remove file
                log_message(LL_INFO, "Removing file %s", target_file);
                remove(target_file);
                break;
            }
            return 1;
        }
    }

    // clean up by freeing resources
    fclose(hashes);
    free(current_hash);

    return 0;
}

int get_user_input(char *prompt)
{
    char input;

    // iterate until we get a good value
    while (1)
    {
        log_message(LL_INFO, "%s", prompt);
        scanf("%c", &input);
        if (input == 'y' || input == 'Y')
        {
            return 1;
        }
        else if (input == 'n' || input == 'N')
        {
            return 0;
        }
        else
        {
            log_message(LL_ERROR, "Invalid input must be Y or N");
        }
    }
}