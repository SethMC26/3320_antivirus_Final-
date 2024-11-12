#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "Crypto/fingerprint.h"

#include "scanner.h"

//private method not included in header so we declare it here 

/**
 * Scans over a list of hashes stored in file to see if any match target hash
 * @param target_hash String of hash to check for
 * @param target_file String of file of target_hash needed incase file is malicious 
 * @param hash_file String of file with hash list
 * @param hash_buffer_size Size of buffer needed for hash
 * 
 * @returns 0 if scan did not find a matching hash, 1 if scan did find a matching has, -1 for an error 
 */
int scan_hashes(char* target_hash, char* target_file, char* hash_file, unsigned int hash_buffer_size);

/**
 * Gets yes or no user input 
 * 
 * @param prompt String with prompt for user
 * 
 * @returns 1 if yes 0 if no 
 */
int get_user_input(char* prompt);

int scan_file(char* target_file) {
    //TO:DO add logic for scanning a file 
    //may want to change how return works as needed

    //Hold different hashes for this file  
    char target_sha1_hash[SHA1_BUFFER_SIZE];
    char target_sha256_hash[SHA256_BUFFER_SIZE];
    char target_md5_hash[MD5_BUFFER_SIZE];
    int scan_result;
    
    printf("Starting File Scan for %s \n", target_file);

    //scan over sha1 hashes
    printf("Scanning sha-1 hashes..."); 
    

    if (sha1_fingerprint_file(target_file, target_sha1_hash) != 0 ) {
        fprintf(stderr, "\nError: sha-1 file fingerprint failed\n");
        return 1;
    }

    scan_result = scan_hashes(target_sha1_hash, target_file, "/usr/local/share/pproc/sha1-hashes.txt", SHA1_BUFFER_SIZE);
    if ( scan_result == 1 ) {
        return 0;
    }
    else if (scan_result == -1 ) {
        fprintf(stderr, "Error: Could not scan sha1 hash list\n");
        return 1;
    }

    printf("[DONE]\n");
    
    //scan over sha256 hashes
    printf("Scanning sha-256 hashes...");

    if (sha256_fingerprint_file(target_file, target_sha256_hash) != 0 ) {
        fprintf(stderr, "Error: sha-256 file fingerprint failed\n");
        return 1;
    }

    scan_result = scan_hashes(target_sha256_hash, target_file,  "/usr/local/share/pproc/sha256-hashes.txt", SHA256_BUFFER_SIZE);
    if ( scan_result == 1 ) {
        return 0;
    }
    else if (scan_result == -1 ) {
        fprintf(stderr, "Error: Could not scan sha-256 hash list\n");
        return 1;
    }

    printf("[DONE]\n");
    
    //scan over md5 hashes 
    printf("Scanning md5 hashes...");

    if (md5_fingerprint_file(target_file, target_md5_hash) != 0)  {
        fprintf(stderr, "Error: md5 file fingerprint failed\n");
        return 1;
    }

    scan_result = scan_hashes(target_md5_hash, target_file, "/usr/local/share/pproc/md5-hashes.txt", MD5_BUFFER_SIZE);
    if ( scan_result == 1 ) {
        return 0;
    }
    else if (scan_result == -1 ) {
        fprintf(stderr, "Error: Could not scan sha-256 hash list\n");
        return 1;
    }

    printf("[DONE]\n");

    printf("DEBUG: sha-1 hash: %s \n", target_sha1_hash);
    printf("DEBUG: sha-256 hash: %s \n", target_sha256_hash);
    printf("DEBUG: md5 hash: %s \n", target_md5_hash);

    return 0;
}


int scan_dir(char* target_dir) {
 //TO:DO add logic for scanning a file 
    //may want to change how return works as needed 
    printf("Scanning directory %s \n", target_dir);
    printf("Scan directory not implemeted yet\n");
    return 0;
}

int scan_system() {
    printf("Starting system scan...");
    printf("System scan not implemented yet\n"); 
    return 0;
}

int scan_hashes(char* target_hash, char* target_file, char* hash_file, unsigned int hash_buffer_size) {
    //current hash in hash list 
    char* current_hash = malloc(hash_buffer_size);

    //open list of malicious hashes
    FILE* hashes = fopen(hash_file, "r");

    if (hashes == NULL ) {
        fprintf(stderr, "Error: Could not find hash file %s\n", hash_file);
        return -1;
    }

    //go line by line through malicious hashes and see if the file hash matches 
    while(fgets(current_hash, hash_buffer_size, hashes)) {
        //printf("%s\n", current_hash);
        //if file malicious file is detected ask user if we should remove it
        if (strcmp(current_hash, target_hash) == 0  ) {
            //quarantine file by removing execute permissions 
            struct stat file_stat;
            unsigned int file_permissions; 
            
            //save orignal file permissions in case we should restore
            if (stat(target_file, &file_stat) == -1) {
                perror("Could not stat file");
                return -1;

            }

            file_permissions = file_stat.st_mode;

            //set file to readonly mode 
            if (chmod(target_file, S_IRUSR | S_IRGRP | S_IROTH) == -1) {
                perror("Failed to change file permissions");
                return 1;
            }       

            printf("\n\nPossible malicious file detected: %s \n", target_file);
            
            switch(get_user_input("Would you like to remove the file Y/N:")) {
                case 0:
                    //restore file permissions 
                    chmod(target_file, file_permissions);
                    //add to white list
                    printf("Add file to white list feature not implemented\n");
                    break;
                case 1: 
                    //remove file 
                    printf("Removing file %s \n", target_file);
                    remove(target_file);
                    break;
            }
            return 1;
        }
    }

    //clean up by freeing resources
    fclose(hashes);
    free(current_hash);

    return 0;
}

int get_user_input(char* prompt) {
    char input;

    //iterate until we get a good value 
    while(1) {
        printf("%s", prompt);
        scanf("%c", &input);
        if (input == 'y' || input == 'Y') {
                return 1;
            }
        else if (input == 'n' || input == 'N') {
                return 0;
            }
        else {
            printf("\nInvalid input must be Y or N \n");
        }
    }
}