#!/bin/bash

# remove stored hash data
echo "Starting uninstall wizard"
sudo systemctl stop pproc-service
sudo systemctl disable pproc-service
sudo rm -f /etc/systemd/system/pproc-service.service
sudo systemctl daemon-reload

# remove hash data
sudo rm -rf /usr/local/share/pproc/
echo "removing hash data from /usr/local/share/pproc/"

#remove config data(white list)
sudo rm -rf /usr/local/etc/pproc
 
 #remove quarantine folder
sudo rm -rf /var/pproc/
# Remove all scheduled cron jobs related to pproc
crontab -l | grep -v 'pproc scan -d' | crontab -
# remove binary
sudo rm /usr/local/bin/pproc
sudo rm /usr/local/bin/pproc-service
echo "Removed binaries from /usr/local"

echo "Removed binary from /usr/local"

#remove logs 
sudo rm /var/log/pproc.log 
sudo rm ~/pproc.log
echo "Removed log files from root and user directories"

echo "Successfully uninstalled program"
