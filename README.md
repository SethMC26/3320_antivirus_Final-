# Penguin Protector Anti-Malware 
<img src="https://upload.wikimedia.org/wikipedia/commons/b/ba/Pax_tux.png" alt="Penguin Protector Logo" width="150"/>

Welcome to Penguin Protector, an anti-malware tool for Linux! To keep all of our Penguin friends safe from harm.

# Quick start
## Using install script  
```bash 
git clone https://github.com/SethMC26/FeatherstoneVaranoHoltzman_3320_Final.git

./scripts/build.sh
```

# Usage 

## Scan for Malware
Scan a file 
```bash
pproc scan <file_path>
```

Scan a directory
```bash
pproc scan -d <directory_path>
pproc scan -dir <directory_path>
pproc scan --directory <directory_path>
```

Scan entire system
```bash
pproc scan -a
pproc scan --all
```

## Add files to whitelist 
Add to whitelist?(still WIP) 
```bash
pproc add <file_path>
```
## Schedule Directory Scans

You can schedule directory scans using the `schedule` command. This command uses `cron` to automate the scanning process for a specific directory.

### Example Usage

To schedule a daily scan of `/home/user/Documents` at midnight, use the following command:

```bash
pproc schedule "0 0 * * *" /home/user/Documents
```

This will add a cron job that runs the scan every day at midnight for the specified directory.

### Cron Schedule Format

The schedule should be provided in the standard cron format:

- `* * * * *` - Minute, Hour, Day of Month, Month, Day of Week
- Example: `0 0 * * *` for daily at midnight

### List Scheduled Scans

To list all scheduled directory scans, use the following command:

```bash
pproc list-schedules
```

This will display all cron jobs related to directory scans.

### Delete a Scheduled Scan

To delete a scheduled directory scan, use the following command:

```bash
pproc delete-schedule
```

You will be prompted to enter the number of the scheduled scan you wish to delete.

## Print usage 
```bash
pproc -h 
pproc --help
```

## Print usage with ASCII art 
`>$ pproc`
```
                        @%%  += 
                     @@ @%%%#+.%
                    **#####*%#.%
                    *+#@##*=%+.%
                     =+###*==:.%
              @%     +=+%@%@%:=%
              =+      =+##+*#.#%
   %#+  @%#+--:#*      ##%-+@@@ 
    ##+#%*-......+       %-+%   
      @%*==-=*#*#@        -*%   
     %##@@%#*+--=%@       =*#   
       @@@@%#+=-=%@@@     *+#   
        @@@@%+...=%%@@@   #=*   
   %#+++=:.::......+@@@@@ @%%@  
 @###****++-.........+@@@@@%%@  
@%########*+=-........+@@@@@%@@ 
%##%######*#*+=.......:%@@ @%@  
#*#%%###++###*+=.......=@@ %%@@ 
#=*@@%%#######*=-......=@@      
#+#@@%%%#####*=-.....+@@@      
  %%%%%%%%##*+*#*#%@@@@@@       
   @@@@@%%%%%@@@@@@@@@@@        
       @@@%#**+=+ #++==+#       
          #%%#%@@  @@@@@@    
Penguin Protector Usage: 

Scan for malware 
  pproc scan <file_path>
  pproc scan --all
  pproc scan --directory
Options:
  -a, --all		Scan entire system for malware.
  -d, -dir, --directory	Scan files within a directory.

Add file to whitelist
  pproc add <file_path>

Display this message
  pproc --help
Options:
  -h, --help		Display this help message.

```
# Features
- Scans files against over 70,000 known malicious hashes
- Quarantines and removes malicious files

# Sources 
- The malicious hash files list has been sourced [here](https://github.com/romainmarcoux/malicious-hash)
- Logo for the project [here](https://commons.wikimedia.org/wiki/File:Pax_tux.png) with license [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/)


## pproc-service: Automatic File Scanning Service

### Overview
The `pproc-service` is a background service that automatically scans new files in the `/downloads` directory for malware. It uses `inotify` to monitor the directory, and when a new file is added, it triggers the scan and logs the result. The service is managed via `systemd` and starts automatically on boot.

### Features:
- **Real-time File Scanning**: Automatically scans files as soon as they are added to the Downloads directory.
- **Logging**: Logs the status of each file scan, including any detected malicious files, to `/var/log/pproc-service.log`.
- **Systemd Integration**: The service runs in the background and can be easily controlled using `systemctl`.

### Installation and Setup:



1. **Start the Service**:
   The service will start automatically. If you need to start it manually, you can use:
   ```bash
   sudo systemctl start pproc-service
   ```

2. **Enable the Service to Start on Boot**:
   To enable the service to start automatically on system boot, run:
   ```bash
   sudo systemctl enable pproc-service
   ```

3. **Check the Service Status**:
   To check if the service is running, use:
   ```bash
   sudo systemctl status pproc-service
   ```

4. **View Logs**:
   You can view the service logs using `journalctl`:
   ```bash
   sudo journalctl -u pproc-service
   ```

### Configuration:
- The service monitors the `/downloads` directory for new files. You can modify the directory being watched by editing the `WATCH_DIR` variable in the source code if needed.
- The service writes logs to `/var/log/pproc-service.log`. You can adjust the logging level and the log file path by modifying the source code.

### Stopping the Service:
To stop the service at any time, use:
```bash
sudo systemctl stop pproc-service
```

### Remove the Service:
To remove the service, use the following commands:
```bash
sudo systemctl stop pproc-service
sudo systemctl disable pproc-service
sudo rm /etc/systemd/system/pproc-service.service
sudo systemctl daemon-reload
```
