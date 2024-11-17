#ifndef FILEHANDLER_H
#define FILEHANDLER_H

int handle_malicious_file(const char* target_file);

int is_whitelisted(const char* target_path);
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