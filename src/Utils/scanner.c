#include <stdio.h>
#include <stdlib.h>
#include "Crypto/fingerprint.h"

#include "scanner.h"

int scan_file(char* target_file) {
    //TO:DO add logic for scanning a file 
    //may want to change how return works as needed 
    printf("scanning file %s...", target_file);

    char hash[41];

    if (sha1_fingerprint_file(target_file, hash) == 1) {
        fprintf(stderr, "Error in Scan: Failed to compute sha-1 of file");
        return 1;
    };

    printf("hash %s \n", hash);
    printf("Scan file not implemeted yet\n");

    //free(hash);
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
