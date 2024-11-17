#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <sys/stat.h>

#include "Utils/scanner.h"
#include "Utils/fileHandler.h"
#include "Services/scheduler.h"

// Forward declaration of the function if not included via a header
void add_to_whitelist(const char* file_path);

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
    printf("Usage: %s <command> [options]\n", program_name);
    printf("Commands:\n");
    printf("  scan <file_path>          Scan a specific file for malware.\n");
    printf("  scan -d <directory_path>  Scan all files within a directory.\n");
    printf("  scan --all                Scan the entire system for malware.\n");
    printf("  add <file_path>           Add a file to the whitelist.\n");
    printf("  schedule <cron> <dir>     Schedule a directory scan using cron.\n");
    printf("  list-schedules            List all scheduled directory scans.\n");
    printf("  delete-schedule           Delete a scheduled directory scan.\n");
    printf("  list-quarantine           List all files in quarantine.\n");
    printf("  restore <file_name>        Restore a file from quarantine.\n");
    printf("  get-hash <file_path>      Get the hash of a file.\n");
    printf("  --help, -h                Display this help message.\n");
}

// Function to list quarantined files
void list_quarantined_files() {
    printf("Listing quarantined files:\n");
    system("ls /usr/local/share/pproc/quarantine | nl");
}

// Function to restore a quarantined file
void restore_quarantined_file(const char* file_name) {
    char restore_command[PATH_MAX * 2];
    FILE *quarantine_log = fopen("/usr/local/share/pproc/quarantine_log.txt", "r");
    if (quarantine_log) {
        char original_path[PATH_MAX];
        unsigned int original_permissions;
        int found = 0;

        while (fscanf(quarantine_log, "%s %o", original_path, &original_permissions) != EOF) {
            if (strcmp(file_name, strrchr(original_path, '/') + 1) == 0) {
                found = 1;
                break;
            }
        }
        fclose(quarantine_log);

        if (found) {
            if (snprintf(restore_command, sizeof(restore_command), "mv /usr/local/share/pproc/quarantine/%s %s", file_name, original_path) < (int)sizeof(restore_command)) {
                if (system(restore_command) == 0) {
                    chmod(original_path, original_permissions);
                    printf("Restored file: %s\n", file_name);
                } else {
                    printf("Failed to restore file: %s\n", file_name);
                }
            } else {
                printf("Restore command buffer overflow for file: %s\n", file_name);
            }
        } else {
            printf("Original path and permissions not found for file: %s\n", file_name);
        }
    } else {
        printf("Failed to open quarantine log file\n");
    }
}

int main(int argc, char* argv[]) {
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

    // Schedule a directory scan
    if (strcmp(argv[1], "schedule") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: Missing arguments for 'schedule'.\n");
            print_usage(argv[0]);
            return 1;
        }
        const char* schedule = argv[2];
        const char* directory = argv[3];
        schedule_directory_scan(schedule, directory);
        return 0;
    }

    // List scheduled scans
    if (strcmp(argv[1], "list-schedules") == 0) {
        list_scheduled_scans();
        return 0;
    }

    // Delete a scheduled scan
    if (strcmp(argv[1], "delete-schedule") == 0) {
        delete_scheduled_scan();
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
    else if (strcmp(argv[1], "list-quarantine") == 0) {
        list_quarantined_files();
        return 0;
    }
    else if (strcmp(argv[1], "restore") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing argument for 'restore'.\n");
            print_usage(argv[0]);
            return 1;
        }
        restore_quarantined_file(argv[2]);
        return 0;
    }
    else if (strcmp(argv[1], "get-hash") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing argument for 'get-hash'.\n");
            print_usage(argv[0]);
            return 1;
        }
        get_file_hash(argv[2]);
        return 0;
    }
    else {
        fprintf(stderr, "Error: Unrecognized option '%s'.\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    //do target file scan
    if ( target_file != NULL) {
        scan_file(target_file, 0);
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
        printf("Adding file %s to whitelist\n", file_to_add);
        add_to_whitelist(file_to_add);
    }
    else {
        fprintf(stderr, "Error: No valid arguments provided.\n");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}