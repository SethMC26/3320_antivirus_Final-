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

int handle_malicious_file(const char* target_file) {
    log_message(LL_DEBUG, "Malicious file detected: %s", target_file);
    
    //hold file paths 
    char real_target_file_path[PATH_MAX];
    char quaratine_filepath[PATH_MAX];

    //find absolute file path of target
    realpath(target_file, real_target_file_path);

    // Find the last '/' in the path
    char *filename = strrchr(real_target_file_path, '/');
    
    // If a '/' was found, move past it to get the file name
    if (filename) {
        filename++;  // Skip the '/' character
    } else {
        filename = real_target_file_path;  // If no '/', the whole path is the file name
    }
    
    snprintf(quaratine_filepath,PATH_MAX, "%s%s","/var/pproc/quarantine/", filename);

    log_message(LL_INFO, "Quarantining malicious file: %s to %s", real_target_file_path, quaratine_filepath);

    //move file to quarantine directory
    rename(real_target_file_path, quaratine_filepath);

    // Log the original path
    FILE *quarantine_log = fopen("/usr/local/etc/pproc/quarantine_log.txt", "a");
    
    if (quarantine_log == NULL) {
        log_message(LL_ERROR, "Could not open quarantine log file");
    }

    //add original file path to log 
    fprintf(quarantine_log, "%s\n", real_target_file_path);
    fclose(quarantine_log);

    printf("\nPossible malicious file detected: %s", target_file);
    //defer to user on what to do with the file 
    if (get_user_input("\nWould you like to remove the file Y/N:") == 1) {
        log_message(LL_INFO, "Removing file %s", target_file);
        //remove file and check for errors 
        if (remove(target_file) != 0) {
            log_message(LL_ERROR, "Failed to remove file: %s", strerror(errno));
            return -1;
        }
    //if they do not want to remove it ask user if they would like to add it to white list 
    } else  {
        if (get_user_input("\nWould you like to add this file to the whitelist Y/N:") == 1) {
            //we are adding to whitelist so unquarantine the file 
            //NOTE: this must be done first so absolute path of file will be correct when we add it to the whitelist
            log_message(LL_DEBUG, "Restoring file: %s from quarantine", target_file);
            restore_quarantined_file(filename);
            //add file to the whitelist 
            log_message(LL_DEBUG, "Adding file to white  absolute path f absolute path f %s", target_file);
            add_to_whitelist(target_file);
        }
        else {
            log_message(LL_INFO, "File: %s has been quarantined, if this is a mistake please do pproc quarantine -r %s", target_file, filename);
        }
    }
    return 0;
}



int is_whitelisted(const char* target_file) {  
    char absolute_path[PATH_MAX];

    //add absolute path of file to white list 
    if (realpath(target_file, absolute_path) == NULL) {
        log_message(LL_ERROR, "Failed to resolve absolute path");
        return -1;
    }
    //open whitelist file 
    FILE* whitelist_file = fopen(WHITELIST_PATH, "r");

    if (whitelist_file == NULL) {
        log_message(LL_ERROR, "Whitelist file not found");
        return -1;
    }
    //line for each files in the whitelist file 
    char line[PATH_MAX];
    //check each line of the file to see if it matches 
    while (fgets(line, sizeof(line), whitelist_file)) {
        // Remove newline character
        line[strcspn(line, "\n")] = 0;
        //found a match return 1
        if (strcmp(line, absolute_path) == 0) {
            fclose(whitelist_file);
            return 1;
        }
    }
    //no match 
    fclose(whitelist_file);
    return 0;
}

int add_to_whitelist(const char* file_path) {  
    log_message(LL_DEBUG, "Adding file to whitelist %s", file_path);

    char absolute_path[PATH_MAX];

    //add absolute path of file to white list 
    if (realpath(file_path, absolute_path) == NULL) {
        log_message(LL_ERROR, "Failed to resolve absolute path for file %s: ", file_path);
        return -1;
    }

    // Open the whitelist file in append mode
    FILE* whitelist_file = fopen(WHITELIST_PATH, "a");

    if (whitelist_file == NULL) {
        perror("fopen failed");  // This will print the actual error
        log_message(LL_ERROR, "Whitelist file not found");
        return -1;
    }

    log_message(LL_DEBUG, "Added %s to whitelist", absolute_path);

    // Append the absolute path to the file, followed by a newline
    fprintf(whitelist_file, "%s\n", absolute_path);

    // Close the file
    fclose(whitelist_file);
    return 0;
}

// Function to restore a quarantined file
void restore_quarantined_file(const char* file_name) {
    char original_path[PATH_MAX];
    char quarantine_file_path[PATH_MAX];

    int found = 0;

    //open log of file paths before quarantine 
    FILE *quarantine_log = fopen("/usr/local/etc/pproc/quarantine_log.txt", "r");
    if (quarantine_log == NULL) {
        log_message(LL_ERROR, "Could not find quarantine log file");
        return;
    }
    //find the file to restore
    while (fscanf(quarantine_log, "%s", original_path) != EOF) {
        if (strcmp(file_name, strrchr(original_path, '/') + 1) == 0) {
            //found file so stop the search
            found = 1;
            break;
        }
    }

    fclose(quarantine_log);
    
    //append the filename to place where file is in quarantine in /var/pproc/quarantine/
    snprintf(quarantine_file_path,PATH_MAX, "%s%s","/var/pproc/quarantine/", file_name);

    if (found) {
        //lets move file 
        rename(quarantine_file_path, original_path);
    } else {
        log_message(LL_ERROR, "Could not find file: %s to restore please use pproc quarantine -l to see options", file_name);
    }
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