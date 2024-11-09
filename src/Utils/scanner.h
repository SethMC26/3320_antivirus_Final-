//header guard to prevent multiple defines
#ifndef SCANNER_H
#define SCANNER_H

/**
 * Scans file 
 * @param target_file String of target file to scan
 * @return int 1 if true 0 if false 
 */
int scan_file(char* target_file);

/**
 * Scans all files in a directory 
 * @param target_dir String of target directory to scan
 * @return int 1 if true 0 if false 
 */
int scan_dir(char* target_dir);

/**
 * Scans all files in the system
 * @return int 1 if true 0 if false 
 */
int scan_system();

#endif
