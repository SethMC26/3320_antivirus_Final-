#ifndef SCANNER_H
#define SCANNER_H

/**
 * Scans file for hashes.
 * @param target_file String of target file to scan
 * @return int 1 if true, 0 if false, 1 if error 
 */
int scan_file(char* target_file);

/**
 * Scans all files in a directory 
 * @param target_dir String of target directory to scan
 * @return int 0 if success, 1 if error 
 */
int scan_dir(char* target_dir);

/**
 * Scans all files in the system
 * @return int 0 if success, 1 if error 
 */
int scan_system();

/**
 * Scans over a list of hashes stored in file to see if any match target hash.
 * @param target_hash String of hash to check for
 * @param target_file String of file of target_hash needed in case file is malicious 
 * @param hash_file String of file with hash list
 * @param hash_buffer_size Size of buffer needed for hash
 * @returns 0 if scan did not find a matching hash, 1 if scan did find a matching hash, -1 for an error
 */
int scan_hashes(char* target_hash, char* target_file, char* hash_file, unsigned int hash_buffer_size);

#endif