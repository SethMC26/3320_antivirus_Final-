#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <sys/stat.h>

#include "Utils/scanner.h"
#include "Utils/logger.h"
#include "Utils/fileHandler.h"
#include "Services/scheduler.h"

void check_if_root();
void *check_thread(void *args);

// might remove ascii art later but it is kinda fun
void printAsciiArt()
{
    const char *asciiArt[] = {
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
        "          #%%#%@@  @@@@@@    "};

    int size = sizeof(asciiArt) / sizeof(asciiArt[0]);
    for (int i = 0; i < size; i++)
    {
        printf("%s\n", asciiArt[i]);
    }
}

void print_usage(const char *program_name)
{
    printf("Usage: %s <command> [options]\n", program_name);
    printf("\n---- General Commands ----\n");
    printf("  -h, --help                  Display this help message.\n");
    printf("  -v, --verbose <level>       Set verbosity level (error, warning, info, debug).\n");

    printf("\n---- Scan Commands ----\n");
    printf("  scan <file_path>            Scan a specific file for malware.\n");
    printf("  -d, --dir <directory_path>  Scan all files within a directory.\n");
    printf("  -a, --all                   Scan the entire system for malware.\n");

    printf("\n---- Whitelist Commands ----\n");
    printf("  -a, --add <file_path>       Add a file to the whitelist.\n");
    printf("  -l, --list                  List all files in the whitelist.\n");

    printf("\n---- Scheduled Scans ----\n");
    printf("  schedule <cron> <dir>       Schedule a directory scan using cron.\n");
    printf("  list-schedules              List all scheduled directory scans.\n");
    printf("  delete-schedule             Delete a scheduled directory scan.\n");

    printf("\n---- Quarantine Commands ----\n");
    printf("  -l, --list                  List all files in quarantine.\n");
    printf("  -r, --restore <file_name>   Restore a file from quarantine.\n");

    printf("\n---- Utility Commands ----\n");
    printf("  get-hash <file_path>        Get the hash of a file.\n");

    printf("\n---- Threading Commands ----\n");
    printf("  --threads <num_threads>        Get number of threads.\n");

    printf("\n---- Examples ----\n");
    printf("  %s scan /path/to/file            Scan a specific file for malware.\n", program_name);
    printf("  %s scan -d /path/to/directory    Scan all files in a directory.\n", program_name);
    printf("  %s scan -a                       Scan the entire system for malware.\n", program_name);
    printf("  %s whitelist --add /path/to/file Add a file to the whitelist.\n", program_name);
    printf("  %s schedule \"0 0 * * *\" /path    Schedule a nightly scan at midnight.\n", program_name);
    printf("  %s quarantine --list             List all files in quarantine.\n", program_name);
    printf("  %s quarantine --restore file.txt Restore a quarantined file.\n", program_name);

    printf("\nNote: Some commands require root privileges. Run with sudo if needed.\n");
}

// create thread function

int main(int argc, char *argv[])
{
    // Default verbosity level
    LogLevel verbosity = LL_INFO;

    // Parse verbosity flag before initializing logger
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        {
            if (i + 1 < argc)
            {
                if (strcmp(argv[i + 1], "error") == 0)
                {
                    verbosity = LL_ERROR;
                }
                else if (strcmp(argv[i + 1], "warning") == 0)
                {
                    verbosity = LL_WARNING;
                }
                else if (strcmp(argv[i + 1], "info") == 0)
                {
                    verbosity = LL_INFO;
                }
                else if (strcmp(argv[i + 1], "debug") == 0)
                {
                    verbosity = LL_DEBUG;
                }
                else
                {
                    fprintf(stderr, "Invalid verbosity level. Using default (info)\n");
                }
                // Skip the next argument since we processed it
                i++;
            }
        }
    }

    // Initialize logger with verbosity settings
    if (geteuid() != 0)
    {
        const char *home = getenv("HOME");
        if (home == NULL)
        {
            fprintf(stderr, "Cannot determine home directory\n");
            return 1;
        }
        char log_file_path[PATH_MAX];
        snprintf(log_file_path, sizeof(log_file_path), "%s/pproc.log", home);
        init_logger(log_file_path, verbosity, LL_DEBUG);
        log_message(LL_DEBUG, "Logger initialized for non-root user at %s", log_file_path);
    }
    else
    {
        init_logger("/var/log/pproc.log", verbosity, LL_DEBUG);
        log_message(LL_DEBUG, "Logger initialized for root user at /var/log/pproc.log");
    }

    // At program startup (after logger init)
    log_message(LL_INFO, "Penguin Protector v1.0 starting up");
    log_message(LL_DEBUG, "Command line arguments: argc=%d", argc);
    for (int i = 0; i < argc; i++)
    {
        log_message(LL_DEBUG, "argv[%d]: %s", i, argv[i]);
    }

    // Before root check
    log_message(LL_DEBUG, "Checking root privileges...");

    // catch case of not enough args to avoid undefined behavoir
    if (argc < 2)
    {
        printAsciiArt();
        print_usage(argv[0]);
        return 0;
    }
    // print help
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        print_usage(argv[0]);
        return 0;
    }

    // Schedule a directory scan
    if (strcmp(argv[1], "schedule") == 0)
    {
        if (argc < 4)
        {
            fprintf(stderr, "Error: Missing arguments for 'schedule'.\n");
            print_usage(argv[0]);
            return 1;
        }
        const char *schedule = argv[2];
        const char *directory = argv[3];
        schedule_directory_scan(schedule, directory);
        return 0;
    }

    // List scheduled scans
    if (strcmp(argv[1], "list-schedules") == 0)
    {
        list_scheduled_scans();
        return 0;
    }

    // Delete a scheduled scan
    if (strcmp(argv[1], "delete-schedule") == 0)
    {
        delete_scheduled_scan();
        return 0;
    }

    // scan command
    if ((strcmp(argv[1], "scan") == 0))
    {
        // catch lack of arguments
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing argument for 'scan'.\n");
            print_usage(argv[0]);
            return 1;
        }
        // scan all argument
        if ((strcmp(argv[2], "-a") == 0) || (strcmp(argv[2], "--all") == 0))
        {
            check_if_root();
            scan_system();
            log_message(LL_INFO, "Scan of system complete");
            return 0;
        }

        // scan directory argument
        else if ((strcmp(argv[2], "-d") == 0) || (strcmp(argv[2], "-dir") == 0) || (strcmp(argv[2], "--directory") == 0))
        {
            check_if_root();
            if (argc < 4)
            {
                fprintf(stderr, "Error: Missing directory for 'scan %s'.\n", argv[2]);
                print_usage(argv[0]);
                return 1;
            }
            scan_dir(argv[3]);
            log_message(LL_INFO, "Scan of directory: %s complete ", argv[3]);
            return 0;
        }
        // user gave bad argument
        else if (argv[2][0] == '-')
        {
            fprintf(stderr, "Error: No argument %s exists\n", argv[2]);
            print_usage(argv[0]);
            return 1;
        }
        // scan a single file
        else
        {
            // check if file exists
            if (access(argv[2], F_OK) == -1)
            {
                fprintf(stderr, "Error: Could not find file %s\n", argv[2]);
                print_usage(argv[0]);
                return 1;
            }
            check_if_root();
            scan_file(argv[2]);
            log_message(LL_INFO, "Scan of file: %s complete", argv[2]);
            return 0;
        }
    }

    // white list option
    else if ((strcmp(argv[1], "whitelist") == 0))
    {
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing argument for whitelist.\n");
            print_usage(argv[0]);
            return 1;
        }

        // add file to white list
        if ((strcmp(argv[2], "-a") == 0) || (strcmp(argv[2], "--add") == 0))
        {
            if (argc < 4)
            {
                // check if file exists

                fprintf(stderr, "Error: Missing file for 'whitelist %s'.\n", argv[2]);
                print_usage(argv[0]);
                return 1;
            }
            // check if file exists
            if (access(argv[3], F_OK) == -1)
            {
                fprintf(stderr, "Error: Could not find file %s\n", argv[3]);
                print_usage(argv[0]);
                return 1;
            }

            check_if_root();
            add_to_whitelist(argv[3]);
            return 0;
        }
        else if ((strcmp(argv[2], "-l") == 0) || (strcmp(argv[2], "--list") == 0))
        {
            // check_if_root();
            printf("Whitelist file: \n");
            system("cat /usr/local/etc/pproc/whitelist.txt");
        }
        // user gave us bad argument
        else if (argv[2][0] == '-')
        {
            fprintf(stderr, "Error: No argument %s exists\n", argv[2]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // quarantine command
    else if (strcmp(argv[1], "quarantine") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing argument for quarantine.\n");
            print_usage(argv[0]);
            return 1;
        }

        // list quarantined files
        if ((strcmp(argv[2], "-l") == 0) || (strcmp(argv[2], "--list") == 0))
        {
            // check_if_root();
            printf("Listing quarantined files:\n");
            system("cat /usr/local/etc/pproc/quarantine_log.txt");
            return 0;
        }
        // restore files
        else if ((strcmp(argv[2], "-r") == 0) || (strcmp(argv[2], "--restore") == 0))
        {
            if (argc < 4)
            {
                fprintf(stderr, "Error: missing filename .\n");
                print_usage(argv[0]);
                return 1;
            }
            check_if_root();
            // restore file
            restore_quarantined_file(argv[3]);
            return 0;
        }

        // user gave us bad argument
        else if (argv[2][0] == '-')
        {
            fprintf(stderr, "Error: No argument %s exists\n", argv[2]);
            print_usage(argv[0]);
            return 1;
        }
    }
    // get hash of file
    else if (strcmp(argv[1], "get-hash") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Error: Missing argument for 'get-hash'.\n");
            print_usage(argv[0]);
            return 1;
        }
        get_file_hash(argv[2]);
        return 0;
    }
    else
    {
        fprintf(stderr, "Error: Unrecognized option '%s'.\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
}

void check_if_root()
{
    // Check if the current user is root
    if (getuid() != 0)
    {
        fprintf(stderr, "\nThis program requires superuser privileges. Please run it with sudo.\n");
        exit(1); // Exit the program if not root
    }
}