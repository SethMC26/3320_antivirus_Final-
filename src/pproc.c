#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "Utils/logger.h"
#include "Utils/scanner.h"
#include <linux/limits.h>

//might remove ascii art later but it is kinda fun 
void printAsciiArt() {
    const char* asciiArt[] = {
        "                        @%%  += ",
        "                     @@ @%%%#+.%",
        "                    **#####*%#.%",
        "                    *+#@##*=%+.%",
        "                     =+###*==:.%",
        "              @%     +=+%@%@%:=%",
        "              =+      =+##+*#.#%",
        "   %#+  @%#+--:#*      ##%-+@@@ ",
        "    ##+#%*-......+       %-+%   ",
        "      @%*==-=*#*#@        -*%   ",
        "     %##@@%#*+--=%@       =*#   ",
        "       @@@@%#+=-=%@@@     *+#   ",
        "        @@@@%+...=%%@@@   #=*   ",
        "   %#+++=:.::......+@@@@@ @%%@  ",
        " @###****++-.........+@@@@@%%@  ",
        "@%########*+=-........+@@@@@%@@ ",
        "%##%######*#*+=.......:%@@ @%@  ",
        "#*#%%###++###*+=.......=@@ %%@@ ",
        "#=*@@%%#######*=-......=@@      ",
        "#+#@@%%%#####*=-.....+@@@      ",
        "  %%%%%%%%##*+*#*#%@@@@@@       ",
        "   @@@@@%%%%%@@@@@@@@@@@        ",
        "       @@@%#**+=+ #++==+#       ",
        "          #%%#%@@  @@@@@@    "
    };

    int size = sizeof(asciiArt) / sizeof(asciiArt[0]);
    for (int i = 0; i < size; i++) {
        printf("%s\n", asciiArt[i]);
    }
}

void print_usage(const char *program_name) {
    printf("Penguin Protector Usage: \n");
    printf("\nScan for malware \n");
    printf("  %s scan <file_path>\n", program_name);
    printf("  %s scan --all\n", program_name);
    printf("  %s scan --directory\n", program_name);
    printf("Options:\n");
    printf("  -a, --all\t\tScan entire system for malware.\n");
    printf("  -d, -dir, --directory\tScan files within a directory.\n");
    printf("\nVerbosity Options:\n");
    printf("  -v, --verbose\t\tSet verbosity level (default: info)\n");
    printf("    error\t\tShow only errors\n");
    printf("    warning\t\tShow errors and warnings\n");
    printf("    info\t\tShow errors, warnings, and info\n");
    printf("    debug\t\tShow all messages\n");
    printf("\nAdd file to whitelist\n");
    printf("  %s add <file_path>\n", program_name);
    printf("\nDisplay this message\n");
    printf("  %s --help\n", program_name);
    printf("Options:\n");
    printf("  -h, --help\t\tDisplay this help message.\n");
}


int main(int argc, char* argv[]) {
    // Default verbosity level
    LogLevel verbosity = LL_INFO;
    
    // Parse verbosity flag before initializing logger
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            if (i + 1 < argc) {
                if (strcmp(argv[i + 1], "error") == 0) {
                    verbosity = LL_ERROR;
                } else if (strcmp(argv[i + 1], "warning") == 0) {
                    verbosity = LL_WARNING;
                } else if (strcmp(argv[i + 1], "info") == 0) {
                    verbosity = LL_INFO;
                } else if (strcmp(argv[i + 1], "debug") == 0) {
                    verbosity = LL_DEBUG;
                } else {
                    fprintf(stderr, "Invalid verbosity level. Using default (info)\n");
                }
                // Skip the next argument since we processed it
                i++;
            }
        }
    }

    // Initialize logger with verbosity settings
    if (geteuid() != 0) {
        const char *home = getenv("HOME");
        if (home == NULL) {
            fprintf(stderr, "Cannot determine home directory\n");
            return 1;
        }
        char log_file_path[PATH_MAX];
        snprintf(log_file_path, sizeof(log_file_path), "%s/pproc.log", home);
        init_logger(log_file_path, verbosity, LL_DEBUG);
        log_message(LL_DEBUG, "Logger initialized for non-root user at %s", log_file_path);
    } else {
        init_logger("/var/log/pproc.log", verbosity, LL_DEBUG);
        log_message(LL_DEBUG, "Logger initialized for root user at /var/log/pproc.log");
    }

    // At program startup (after logger init)
    log_message(LL_INFO, "Penguin Protector v1.0 starting up");
    log_message(LL_DEBUG, "Command line arguments: argc=%d", argc);
    for (int i = 0; i < argc; i++) {
        log_message(LL_DEBUG, "argv[%d]: %s", i, argv[i]);
    }
    
    // Before root check
    log_message(LL_DEBUG, "Checking root privileges...");
    
    // After root check
    if (geteuid() != 0) {
        log_message(LL_WARNING, "Running without root privileges - limited functionality");
    } else {
        log_message(LL_INFO, "Running with root privileges");
    }
    
    //file to scan
    char* target_file = NULL;
    //directory to scan
    char* target_directory = NULL;
    //scan entire system
    int scan_all = 0;
    //add file
    char* file_to_add = NULL;

    //catch case of not enough args to avoid undefined behavoir
    if (argc < 2) {
        log_message(LL_ERROR, "Insufficient arguments provided");
        printAsciiArt();
        print_usage(argv[0]);
        return 0;
    }
    //print help 
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        log_message(LL_INFO, "Help requested");
        print_usage(argv[0]);
        return 0;
    }

    //scan command 
    if ((strcmp(argv[1], "scan") == 0 )) {
        log_message(LL_INFO, "Scan command received");
        
        //catch lack of arguments
        if (argc < 3) {
            log_message(LL_ERROR, "Error: Missing argument for 'scan'.");
            print_usage(argv[0]);
            return 1;
        }
        //scan all
        if ((strcmp(argv[2], "-a") == 0) || (strcmp(argv[2], "--all") == 0)) {
            log_message(LL_INFO, "Scanning entire system");
            scan_all = 1;
        }
        //scan directory
        else if ((strcmp(argv[2], "-d") == 0) || (strcmp(argv[2], "-dir") == 0) || (strcmp(argv[2], "--directory") == 0)) {
            if (argc < 4) {
                log_message(LL_ERROR, "Error: Missing directory for 'scan %s'.", argv[2]);
                print_usage(argv[0]);
                return 1;
            }
            target_directory = argv[3];
            log_message(LL_INFO, "Scanning directory: %s", target_directory);
        }
        else if ((strcmp(argv[2], "-v") == 0 ) || strcmp(argv[2], "--verbose") == 0 ) {
            //ignore we already handled this 
            ;
        }
        else if (argv[2][0] == '-') {
            log_message(LL_ERROR, "Error: No argument %s exists", argv[2]);
            print_usage(argv[0]);
            return 1;
        }
        //scan a single file
        else {
            //check if file exists
            if (access(argv[2], F_OK) == -1) {
                log_message(LL_ERROR, "Error: Could not find file %s", argv[2]);
                print_usage(argv[0]);
                return 1;
            } 
            target_file = argv[2];
            log_message(LL_INFO, "Scanning file: %s", target_file);
        }
    }
    //add file to white list 
    else if ((strcmp(argv[1], "add") == 0 )) {
        if (argc < 3) {
            log_message(LL_ERROR, "Error: Missing argument for 'add'.");
            print_usage(argv[0]);
            return 1;
        }
        file_to_add = argv[2];
        log_message(LL_INFO, "Adding file to whitelist: %s", file_to_add);
    }
    else {
        log_message(LL_ERROR, "Error: Unrecognized option '%s'.", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    //do target file scan
    if ( target_file != NULL) {
        log_message(LL_DEBUG, "Initiating file scan for %s", target_file);
        scan_file(target_file);
    }
    //do target directory scan
    else if (target_directory != NULL) {
        log_message(LL_DEBUG, "Initiating directory scan for %s", target_directory);
        scan_dir(target_directory);
    }
    //scan entire file system
    else if ( scan_all ) {
        log_message(LL_DEBUG, "Initiating system-wide scan");
        scan_system();
        //may want to use scanning a directory logic but set directory to "/";
    }
    //add file 
    else if ( file_to_add != NULL) {
        log_message(LL_INFO, "Adding file %s", file_to_add);
        log_message(LL_INFO, "Adding files not implemented");
    }
    else {
        log_message(LL_ERROR, "Error: No valid arguments provided.");
        print_usage(argv[0]);
        return 1;
    }

    // Log program end
    log_message(LL_INFO, "Penguin Protector shutting down");
    cleanup_logger();
    return 0;
}