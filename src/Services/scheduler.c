#include <stdio.h>
#include <stdlib.h>

// Function to schedule a directory scan using cron
void schedule_directory_scan(const char* schedule, const char* directory) {
    char cron_command[512];
    snprintf(cron_command, sizeof(cron_command), "(crontab -l 2>/dev/null; echo \"%s /usr/local/bin/pproc scan -d %s\") | crontab -", schedule, directory);
    system(cron_command);
    printf("Scheduled directory scan for %s with cron: %s\n", directory, schedule);
}

// Function to list scheduled scans
void list_scheduled_scans() {
    printf("Listing scheduled scans:\n");
    system("crontab -l | grep 'pproc scan -d' | nl");
}

// Function to delete a scheduled scan
void delete_scheduled_scan() {
    list_scheduled_scans();
    char choice[10];
    int line_number;
    printf("Enter the number of the scheduled scan to delete: ");
    fgets(choice, sizeof(choice), stdin);
    line_number = atoi(choice);

    if (line_number <= 0) {
        printf("Invalid selection.\n");
        return;
    }

    printf("Are you sure you want to delete schedule number %d? (Y/N): ", line_number);
    fgets(choice, sizeof(choice), stdin);

    if (choice[0] == 'Y' || choice[0] == 'y') {
        char delete_command[512];
        snprintf(delete_command, sizeof(delete_command), "crontab -l | grep -v 'pproc scan -d' | sed '%dd' | crontab -", line_number);
        system(delete_command);
        printf("Deleted schedule number %d.\n", line_number);
    } else {
        printf("Deletion cancelled.\n");
    }
}