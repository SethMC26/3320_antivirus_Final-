//header guard to prevent multiple defines
#define SHA1_LENGTH 20
#define SHA256_LENGTH 32
#define MD5_LENGTH 16 


#define SHA1_BUFFER_SIZE 41
#define SHA256_BUFFER_SIZE 65
#define MD5_BUFFER_SIZE 33



#ifndef FINGERPRINT_H
#define FINGERPRINT_H

/**
 * Compare two hashes 
 * @param hash1 First hash to compare
 * @param hash2 Second hash to compare 
 * 
 * @returns 0 if hashes match, non-zero otherwise 
 */
int compare_hashes(char* hash1, char* hash2);

/**
 * Compute the sha-1 hash of a file 
 * @param target_file string - file to hash
 * @param hash_buffer char array -  buffer to write hash to 
 * 
 * @returns 0 if successful, 1 if there is an error. 
 */
int sha1_fingerprint_file(char* target_file, char* hash_buffer);

/**
 * Computes the sha-256 hash of a file 
 * @param target_file String - file to hash
 * @param hash_buffer char array - buffer to write hash to
 * 
 * @returns 0 if successful, 1 if there is an error. 
 */
int sha256_fingerprint_file(char* target_file, char* hash_buffer);

/**
 * Computes the md5 hash of a file 
 * @param target_file String - file to hash
 * @param hash_buffer char array - buffer to write hash to 
 * 
 * @returns 0 if successful, 1 if there is an error. 
 */
int md5_fingerprint_file(char* target_file, char* hash_buffer);

#endif