# remove stored hash data
echo "Starting uninstall wizard"
sudo rm -rf /usr/local/share/pproc/
echo "removing hash data from /usr/local/share/pproc/"

# remove binary 
sudo rm /usr/local/bin/pproc
echo "Removed binary from /usr/local"

#remove logs 
sudo rm /var/log/pproc.log 
sudo rm ~/pproc.log
echo "Removed log files from root and user directories"
echo "Successfully uninstalled program"