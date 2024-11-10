#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Crypto/fingerprint.h"

#include "scanner.h"

//private method not included in header so we declare it here 

int scan_hashes(char* target_hash, char* hash_file, int hash_buffer_size);

int scan_file(char* target_file) {
    //TO:DO add logic for scanning a file 
    //may want to change how return works as needed

    //Hold different hashes for this file  
    char target_sha1_hash[SHA1_BUFFER_SIZE];
    char target_sha256_hash[SHA256_BUFFER_SIZE];
    char target_md5_hash[MD5_BUFFER_SIZE];

    printf("Starting File Scan for %s \n", target_file);

    printf("Scanning sha-1 hashes..."); 
    
    if (sha1_fingerprint_file(target_file, target_sha1_hash) != 0 ) {
        fprintf(stderr, "Error: sha-1 file fingerprint failed\n");
        return 1;
    }
    
    if (scan_hashes(target_sha1_hash, "/usr/local/share/pproc/sha1-hashes.txt", SHA1_BUFFER_SIZE) != 0 ) {
        fprintf(stderr, "Error: Could not scan md5 hash list\n");
        return 1;
    }

    printf("[DONE]\n");

    printf("Scanning sha-256 hashes...");

    if (sha256_fingerprint_file(target_file, target_sha256_hash) != 0 ) {
        fprintf(stderr, "Error: sha-256 file fingerprint failed\n");
        return 1;
    }

    if (scan_hashes(target_sha256_hash, "/usr/local/share/pproc/sha256-hashes.txt", SHA256_BUFFER_SIZE) != 0 ) {
        fprintf(stderr, "Error: Could not scan sha-256 hash list\n");
    }

    printf("[DONE]\n");
    
    printf("Scanning md5 hashes...");

    if (md5_fingerprint_file(target_file, target_md5_hash) != 0)  {
        fprintf(stderr, "Error: md5 file fingerprint failed\n");
    }

    if (scan_hashes(target_md5_hash, "/usr/local/share/pproc/md5-hashes.txt", MD5_BUFFER_SIZE) != 0 ) {
        fprintf(stderr, "Error: Could not scan md5 hash list\n");
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

int scan_hashes(char* target_hash, char* hash_file, int hash_buffer_size) {
    //current hash in hash list 
    char* current_hash = malloc(hash_buffer_size);

    //open list of malicious hashes
    FILE* hashes = fopen(hash_file, "r");

    if (hashes == NULL ) {
        fprintf(stderr, "Error: Could not find hash file %s\n", hash_file);
        return 1;
    }

    //go line by line through malicious hashes and see if the file hash matches 
    while(fgets(current_hash, hash_buffer_size, hashes)) {
        //printf("%s\n", current_hash);
        if (strcmp(current_hash, target_hash) == 0) {
            printf("\nVIRUS DETECTED!!! \n");
            //TO:DO handle dealing with virus 
        }
    }

    //clean up by freeing resources
    fclose(hashes);
    free(current_hash);

    return 0;
}
