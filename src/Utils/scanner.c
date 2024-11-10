#include <stdio.h>
#include <stdlib.h>
#include "Crypto/fingerprint.h"

#include "scanner.h"

int scan_file(char* target_file) {
    //TO:DO add logic for scanning a file 
    //may want to change how return works as needed 

    printf("scanning file %s...", target_file);

    //compute sha1 hash of file 
    char file_hash[SHA1_BUFFER_SIZE];

    if (sha1_fingerprint_file(target_file, file_hash) == 1) {
        fprintf(stderr, "Error in Scan: Failed to compute sha-1 of file");
        return 1;
    };

    //open list of sha1-hashes 
    FILE* sha1_hashes = fopen("/usr/local/share/pproc/sha1-hashes.txt", "r");

    if (sha1_hashes == NULL ) {
        fprintf(stderr, "Error: Could not find sha-1 hashes");
        return 0;
    }
    //buffer for current hash in list 
    char current_hash[SHA1_BUFFER_SIZE];

    printf("\n scanning over files hashes: \n");
    while(fgets(current_hash, sizeof(current_hash), sha1_hashes)) {
        if (compare_hashes(current_hash, file_hash) == 0) {
            printf("\nVIRUS DETECTED!!! \n");
            //TO:DO handle dealing with virus 
        }
    }
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
