#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "Crypto/fingerprint.h"
#include "Utils/logger.h"

#include "fileHandler.h"

// Path to the whitelist file
#define WHITELIST_PATH "/usr/local/etc/pproc/whitelist.txt"

int add_to_whitelist(const char* target_path);

int handle_malicious_file(const char* target_file) {
    log_message(LL_WARNING, "Malicious file detected: %s", target_file);
    
    struct stat file_stat;
    unsigned int file_permissions;

    if (stat(target_file, &file_stat) == -1) {
        log_message(LL_ERROR, "Could not stat file %s", target_file);
        return -1;
    }

    file_permissions = file_stat.st_mode;

    if (chmod(target_file, S_IRUSR | S_IRGRP | S_IROTH) == -1) {
        log_message(LL_ERROR, "Failed to change file permissions");
        return 1;
    }

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
            }

            // Open destination file with explicit permissions
            FILE *dst = fopen(quarantine_path, "wb");
            if (!dst) {
                log_message(LL_ERROR, "Failed to open quarantine destination: %s", strerror(errno));
                fclose(src);
                chmod(target_file, file_permissions);
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


int is_whitelisted(const char* target_file) {  
    char absolute_path[PATH_MAX];

    //add absolute path of file to white list 
    if (realpath(target_file, absolute_path) == NULL) {
        log_message(LL_ERROR, "Failed to resolve absolute path");
        return -1;
    }

    FILE* whitelist_file = fopen(WHITELIST_PATH, "r");

    if (whitelist_file == NULL) {
        log_message(LL_ERROR, "Whitelist file not found");
        return -1;
    }

    char line[PATH_MAX];

    while (fgets(line, sizeof(line), whitelist_file)) {
        // Remove newline character
        line[strcspn(line, "\n")] = 0;
        
        if (strcmp(line, absolute_path) == 0) {
            fclose(whitelist_file);
            return 1;
        }
    }

    fclose(whitelist_file);
    return 0;
}

int add_to_whitelist(const char* file_path) {  
    char absolute_path[PATH_MAX];

    //add absolute path of file to white list 
    if (realpath(file_path, absolute_path) == NULL) {
        log_message(LL_ERROR, "Failed to resolve absolute path");
        return -1;
    }

    // Open the whitelist file in append mode
    FILE* whitelist_file = fopen(WHITELIST_PATH, "a");

    if (whitelist_file == NULL) {
        perror("fopen failed");  // This will print the actual error
        log_message(LL_ERROR, "Whitelist file not found");
        return -1;
    }

    // Append the absolute path to the file, followed by a newline
    log_message(LL_WARNING, "Added %s to whitelist", absolute_path);

    fprintf(whitelist_file, "%s\n", absolute_path);

    // Close the file
    fclose(whitelist_file);
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

        //clear input buffer for next call 
        getchar();
        
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
            printf("\nInvalid input must be Y or N");
        }

        // Clear the buffer in case of invalid input
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }
}

// Function to get the hash of a file
void get_file_hash(const char* file_path) {
    char sha1_hash[SHA1_BUFFER_SIZE];
    char sha256_hash[SHA256_BUFFER_SIZE];
    char md5_hash[MD5_BUFFER_SIZE];

    if (sha1_fingerprint_file(file_path, sha1_hash) == 0) {
        printf("SHA1: %s\n", sha1_hash);
    } else {
        printf("Failed to calculate SHA1 hash for %s\n", file_path);
    }

    if (sha256_fingerprint_file(file_path, sha256_hash) == 0) {
        printf("SHA256: %s\n", sha256_hash);
    } else {
        printf("Failed to calculate SHA256 hash for %s\n", file_path);
    }

    if (md5_fingerprint_file(file_path, md5_hash) == 0) {
        printf("MD5: %s\n", md5_hash);
    } else {
        printf("Failed to calculate MD5 hash for %s\n", file_path);
    }
}