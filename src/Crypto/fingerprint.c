#include <stdio.h>
#include <stdlib.h> 
#include <string.h>

#include <openssl/evp.h>

#include "fingerprint.h"

//private method not included in header so we declare it here 

/**
 * Computes a hash of a file from openssl library 
 * @param target_file String with target_file 
 * @param hash_buffer char array to write output hash into must be size hash_length * 2 + 1
 */
int compute_hash(char* target_file, char* hash_buffer, const EVP_MD* hashing_algorithm, unsigned int hash_length);

int compare_hashes(char* hash1, char* hash2) {
    return strcmp(hash1, hash2);
}

int sha1_fingerprint_file(char* target_file, char* hash_buffer) {
    return compute_hash(target_file, hash_buffer, EVP_sha1(), SHA1_LENGTH);
}

int sha256_fingerprint_file(char* target_file, char* hash_buffer) {
    return compute_hash(target_file, hash_buffer, EVP_sha256(), SHA256_LENGTH);
}

int md5_fingerprint_file(char* target_file, char* hash_buffer) {
    return compute_hash(target_file, hash_buffer, EVP_md5(), MD5_LENGTH);
}


int compute_hash(char* target_file, char* hash_buffer, const EVP_MD* hashing_algorithm, unsigned int hash_length) {
    //open file to compute hash of 
    FILE* file = fopen(target_file, "rb");
    if (!file) {
        perror("Error opening file ");
        return 1;
    }
    
    //create context for message digest 
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    //catch errors while creating context 
    if (!mdctx){ 
        fclose(file);
        fprintf(stderr, "Error in Fingerprint: Cannot create context\n");
        return 1;
    }

    //initalize context for specific hashing algorithm 
    if (EVP_DigestInit_ex(mdctx, hashing_algorithm, NULL) != 1 ) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        fprintf(stderr, "Error in Fingerprint: Cannot initialize context\n");
        return 1;
    }

    //create a buffer for reading in data from file 
    unsigned char buffer[4096]; 
    size_t bytes_read;
    //create hash from all bytes in file 
    while((bytes_read = fread(buffer, 1, sizeof(buffer), file) > 0)) {
        //update message digest and check for erros
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            fprintf(stderr, "Error in fingerprint: Cannot updating digest\n");
            return 1;
        }
    }

    //hold hash value
    unsigned char hash[hash_length];

    //get final hash value 
    if (EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        fprintf(stderr, "Error finalizing digest\n");
        return 1;
    }

    // Clean up
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    // Convert the hash to hexadecimal represntation and save into our buffer
    for (unsigned int i = 0; i < hash_length; i++) {
        sprintf(hash_buffer + i * 2, "%02x", hash[i]);
    }
    hash_buffer[hash_length * 2] = '\0';  // Null-terminate the string

    return 0;
}