#ifndef FILEHANDLER_H
#define FILEHANDLER_H

/**
 * Handles a possibly malicious file
 * 
 * @param target_file string of target file to handle
 */
int handle_malicious_file(const char* target_file);
/**
 * Check if a file is on the whitelist
 * 
 * @param target_file string of file to check
 */
int is_whitelisted(const char* target_file);

/**
 * Adds absolute path of file to white list 
 * 
 * @param target_file adds file to white list 
 */
int add_to_whitelist(const char* target_file);


void restore_quarantined_file(const char* file_name);

/**
 * Gets yes or no user input
 *
 * @param prompt String with prompt for user
 *
 * @returns 1 if yes 0 if no
 */
int get_user_input(char *prompt);

void get_file_hash(const char* file_path);

#endif