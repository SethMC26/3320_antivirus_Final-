#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "Utils/logger.h"
#include "Utils/scanner.h"

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
    printf("\nAdd file to whitelist\n");
    printf("  %s add <file_path>\n", program_name);
    printf("\nDisplay this message\n");
    printf("  %s --help\n", program_name);
    printf("Options:\n");
    printf("  -h, --help\t\tDisplay this help message.\n");
}


int main(int argc, char* argv[]) {
    // Initialize logger with default settings
    char log_file_path[512];

    if (geteuid() != 0) {
        fprintf(stderr, "Warning: Not running as root. Logging to ~/pproc.log instead\n");
        // Expand ~ to home directory
        const char *home = getenv("HOME");
        if (home == NULL) {
            fprintf(stderr, "Cannot determine home directory\n");
            return 1;
        }
        snprintf(log_file_path, sizeof(log_file_path), "%s/pproc.log", home);
        init_logger(log_file_path, LL_INFO, LL_DEBUG);
    } else {
        init_logger("/var/log/pproc.log", LL_INFO, LL_DEBUG);
    }
    
    // Test logging system
    log_message(LL_INFO, "Penguin Protector started");
    log_message(LL_DEBUG, "Debug logging enabled");
    
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
        printAsciiArt();
        print_usage(argv[0]);
        return 0;
    }
    //print help 
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    //scan command 
    if ((strcmp(argv[1], "scan") == 0 )) {
        //catch lack of arguments
        if (argc < 3) {
            fprintf(stderr, "Error: Missing argument for 'scan'.\n");
            print_usage(argv[0]);
            return 1;
        }
        //scan all
        if ((strcmp(argv[2], "-a") == 0) || (strcmp(argv[2], "--all") == 0)) {
            scan_all = 1;
        }
        //scan directory
        else if ((strcmp(argv[2], "-d") == 0) || (strcmp(argv[2], "-dir") == 0) || (strcmp(argv[2], "--directory") == 0)) {
            if (argc < 4) {
                fprintf(stderr, "Error: Missing directory for 'scan %s'.\n", argv[2]);
                print_usage(argv[0]);
                return 1;
            }
            target_directory = argv[3];
        }
        else if (argv[2][0] == '-') {
            fprintf(stderr, "Error: No argument %s exists\n", argv[2]);
            print_usage(argv[0]);
            return 1;
        }
        //scan a single file
        else {
            //check if file exists
            if (access(argv[2], F_OK) == -1) {
                fprintf(stderr, "Error: Could not find file %s\n", argv[2]);
                print_usage(argv[0]);
                return 1;
            } 
            target_file = argv[2];
        }
    }
    //add file to white list 
    else if ((strcmp(argv[1], "add") == 0 )) {
        if (argc < 3) {
            fprintf(stderr,"Error: Missing argument for 'add'.\n");
            print_usage(argv[0]);
            return 1;
        }
        file_to_add = argv[2];
    }
    else {
        fprintf(stderr, "Error: Unrecognized option '%s'.\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    //do target file scan
    if ( target_file != NULL) {
        scan_file(target_file);
    }
    //do target directory scan
    else if (target_directory != NULL) {
        scan_dir(target_directory);
    }
    //scan entire file system
    else if ( scan_all ) {
        scan_system();
        //may want to use scanning a directory logic but set directory to "/";
    }
    //add file 
    else if ( file_to_add != NULL) {
        printf("adding file %s\n", file_to_add);
        printf("Adding files not implemented\n");
    }
    else {
        fprintf(stderr, "Error: No valid arguments provided.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Log program end
    log_message(LL_INFO, "Penguin Protector shutting down");
    cleanup_logger();
    return 0;
}