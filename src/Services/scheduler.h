#ifndef SCHEDULER_H
#define SCHEDULER_H

void schedule_directory_scan(const char* schedule, const char* directory);
void list_scheduled_scans();
void delete_scheduled_scan();

#endif
