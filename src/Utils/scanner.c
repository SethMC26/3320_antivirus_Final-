#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "Crypto/fingerprint.h"

#include "scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>

#include "Crypto/fingerprint.h"
#include "scanner.h"
#include <linux/limits.h>

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

    printf("Starting File Scan for %s \n", target_file);

    // scan over sha1 hashes
    printf("Scanning sha-1 hashes...");

    if (sha1_fingerprint_file(target_file, target_sha1_hash) != 0)
    {
        fprintf(stderr, "\nError: sha-1 file fingerprint failed\n");
        return 1;
    }

    scan_result = scan_hashes(target_sha1_hash, target_file, "/usr/local/share/pproc/sha1-hashes.txt", SHA1_BUFFER_SIZE);
    if (scan_result == 1)
    {
        return 0;
    }
    else if (scan_result == -1)
    {
        fprintf(stderr, "Error: Could not scan sha1 hash list\n");
        return 1;
    }

    printf("[DONE]\n");

    // scan over sha256 hashes
    printf("Scanning sha-256 hashes...");

    if (sha256_fingerprint_file(target_file, target_sha256_hash) != 0)
    {
        fprintf(stderr, "Error: sha-256 file fingerprint failed\n");
        return 1;
    }

    scan_result = scan_hashes(target_sha256_hash, target_file, "/usr/local/share/pproc/sha256-hashes.txt", SHA256_BUFFER_SIZE);
    if (scan_result == 1)
    {
        return 0;
    }
    else if (scan_result == -1)
    {
        fprintf(stderr, "Error: Could not scan sha-256 hash list\n");
        return 1;
    }

    printf("[DONE]\n");

    // scan over md5 hashes
    printf("Scanning md5 hashes...");

    if (md5_fingerprint_file(target_file, target_md5_hash) != 0)
    {
        fprintf(stderr, "Error: md5 file fingerprint failed\n");
        return 1;
    }

    scan_result = scan_hashes(target_md5_hash, target_file, "/usr/local/share/pproc/md5-hashes.txt", MD5_BUFFER_SIZE);
    if (scan_result == 1)
    {
        return 0;
    }
    else if (scan_result == -1)
    {
        fprintf(stderr, "Error: Could not scan sha-256 hash list\n");
        return 1;
    }

    printf("[DONE]\n");

    printf("DEBUG: sha-1 hash: %s \n", target_sha1_hash);
    printf("DEBUG: sha-256 hash: %s \n", target_sha256_hash);
    printf("DEBUG: md5 hash: %s \n", target_md5_hash);

    return 0;
}

void *scan_file_thread(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;

    if (!data->is_directory)
    {
        printf("Scanning file: %s\n", data->path);
        scan_file(data->path); // Call your existing scan_file function
    }

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
    DIR *dir = opendir(target_dir);
    if (dir == NULL)
    {
        perror("Error opening directory");
        return 1; // Return 1 for error
    }

    struct dirent *entry;
    pthread_t threads[MAX_THREADS]; // Array of threads
    int thread_count = 0;
    printf("Scanning directory: %s\n", target_dir); // Print the directory being scanned

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
            perror("Error getting file status");
            continue;
        }

        // Check if it's a directory or a file
        if (S_ISDIR(statbuf.st_mode))
        {
            // If it's a directory, recursively scan it (also threaded)
            printf("Directory found: %s\n", path); // Print the path of the subdirectory being scanned

            thread_data_t *data = malloc(sizeof(thread_data_t));
            data->path = strdup(path);
            data->is_directory = 1;

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
        else
        {
            // If it's a file, scan it
            printf("File found: %s\n", path); // Print the path of the file being scanned

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

    closedir(dir);
    return 0; // Return 0 for success
}

/**
 * Scans the entire system by calling scan_dir on the root directory
 * @return int 0 if success, 1 if error
 */
int scan_system()
{
    printf("Starting system scan...\n");
    int result = scan_dir("/"); // Scan from root directory
    if (result == 0)
    {
        printf("System scan completed successfully.\n");
    }
    else
    {
        printf("System scan failed.\n");
    }
    return result; // Return the result from scan_dir
}

int scan_hashes(char *target_hash, char *target_file, char *hash_file, unsigned int hash_buffer_size)
{
    // current hash in hash list
    char *current_hash = malloc(hash_buffer_size);

    // open list of malicious hashes
    FILE *hashes = fopen(hash_file, "r");

    if (hashes == NULL)
    {
        fprintf(stderr, "Error: Could not find hash file %s\n", hash_file);
        return -1;
    }

    // go line by line through malicious hashes and see if the file hash matches
    while (fgets(current_hash, hash_buffer_size, hashes))
    {
        // printf("%s\n", current_hash);
        // if file malicious file is detected ask user if we should remove it
        if (strcmp(current_hash, target_hash) == 0)
        {
            // quarantine file by removing execute permissions
            struct stat file_stat;
            unsigned int file_permissions;

            // save orignal file permissions in case we should restore
            if (stat(target_file, &file_stat) == -1)
            {
                perror("Could not stat file");
                return -1;
            }

            file_permissions = file_stat.st_mode;

            // set file to readonly mode
            if (chmod(target_file, S_IRUSR | S_IRGRP | S_IROTH) == -1)
            {
                perror("Failed to change file permissions");
                return 1;
            }

            printf("\n\nPossible malicious file detected: %s \n", target_file);

            switch (get_user_input("Would you like to remove the file Y/N:"))
            {
            case 0:
                // restore file permissions
                chmod(target_file, file_permissions);
                // add to white list
                printf("Add file to white list feature not implemented\n");
                break;
            case 1:
                // remove file
                printf("Removing file %s \n", target_file);
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
        printf("%s", prompt);
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
            printf("\nInvalid input must be Y or N \n");
        }
    }
}