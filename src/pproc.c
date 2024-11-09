#include <stdio.h>
#include <string.h>

void print_usage(const char *program_name) {
    printf("Usage: \n");
    printf("\nScan for viruses \n");
    printf("  %s scan <file_path>\n", program_name);
    printf("  %s scan --all\n", program_name);
    printf("  %s scan --directory\n", program_name);
    printf("Options:\n");
    printf("  -a, --all\t\tScan entire system for viruses.\n");
    printf("  -d, -dir, --directory\tScan files within a directory.\n");
    printf("\nAdd file to thingy mickgiger\n");
    printf("  %s add <file_path>\n", program_name);
    printf("\nDisplay this message\n");
    printf("  %s --help\n", program_name);
    printf("Options:\n");
    printf("  -h, --help\t\tDisplay this help message.\n");
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
        printf("Error: Too few arguments.\n");
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
            printf("Error: Missing argument for 'scan'.\n");
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
                printf("Error: Missing directory for 'scan %s'.\n", argv[2]);
                print_usage(argv[0]);
                return 1;
            }
            target_directory = argv[3];
        }
        else if (argv[2][0] == '-') {
            printf("Error: No argument %s exists\n", argv[2]);
            print_usage(argv[0]);
            return 1;
        }
        //scan a single file
        else {
            target_file = argv[2];
            printf("Target_File %s\n", target_file);
        }
    }
    //add file to white list 
    else if ((strcmp(argv[1], "add") == 0 )) {
        if (argc < 3) {
            printf("Error: Missing argument for 'add'.\n");
            print_usage(argv[0]);
            return 1;
        }
        file_to_add = argv[2];
    }
    else {
        printf("Error: Unrecognized option '%s'.\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    //do target file scan
    if ( target_file != NULL) {
        printf("scanning file %s \n", target_file);
        printf("scanning files not implemented yet \n");
    }
    //do target directory scan
    else if (target_directory) {
        printf("Scanning directory %s \n", target_directory);
        printf("scanning directory not implemented yet \n");
    }
    //scan entire file system
    else if ( scan_all ) {
        printf("Scan all function not implemented yet :(\n" );
        //may want to use scanning a directory logic but set directory to "/";
    }
    //add file 
    else if ( file_to_add != NULL) {
        printf("adding file %s\n", file_to_add);
        printf("Adding files not implemented\n");
    }
    else {
        printf("Error: No valid arguments provided.\n");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}