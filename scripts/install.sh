#!/bin/bash

# Created by chatGPT
echo "Starting install"

# Get the directory of the script (scripts/ directory)
SCRIPT_DIR="$(dirname "$0")"

# Navigate to the project root by moving up one directory from scripts/
PROJECT_ROOT="$(realpath "$SCRIPT_DIR/..")"

# Define the output binaries
OUTPUT_BINARY="pproc"
SERVICE_BINARY="pproc-service"

# Find all .c files in the src directory and its subdirectories
SRC_FILES=$(find "$PROJECT_ROOT/src" -name "*.c")

# Check if there are any source files
if [ -z "$SRC_FILES" ]; then
    echo "Error: No .c files found in the src directory."
    exit 1
fi

# Create log directory and file with proper permissions
sudo mkdir -p /var/log
sudo touch /var/log/pproc.log
sudo chmod 666 /var/log/pproc.log

# Compile the source files for the CLI program (pproc)
sudo gcc -g -Wall -Wextra -I"$PROJECT_ROOT/src" -pthread $SRC_FILES -o "$OUTPUT_BINARY" -lcrypto 

# Check if compilation succeeded for the CLI program
if [ $? -ne 0 ]; then
    echo "Compilation of $OUTPUT_BINARY failed."
    exit 1
fi
echo "Successfully compiled pproc CLI"

# Now compile the service program (pproc-service), explicitly including the necessary source files
#Note we should find a better way to do this
sudo gcc -g -Wall -Wextra -I"$PROJECT_ROOT/src" \
    "$PROJECT_ROOT/src/pproc-service.c" \
    "$PROJECT_ROOT/src/Utils/scanner.c" \
   "$PROJECT_ROOT/src/Crypto/fingerprint.c" \
    "$PROJECT_ROOT/src/Utils/logger.c" \
    "$PROJECT_ROOT/src/Utils/fileHandler.c" \
    "$PROJECT_ROOT/src/Services/scheduler.c" \
    -o "$SERVICE_BINARY" -lcrypto -D_GNU_SOURCE -DSERVICE_MAIN

# Check if compilation succeeded for the service program
if [ $? -ne 0 ]; then
    echo "Compilation of $SERVICE_BINARY failed."
    exit 1
fi

# Move the binaries to /usr/local/bin (requires sudo)
sudo mv "$OUTPUT_BINARY" /usr/local/bin/$OUTPUT_BINARY
sudo mv "$SERVICE_BINARY" /usr/local/bin/$SERVICE_BINARY
if [ $? -ne 0 ]; then
    echo "Failed to move binaries to /usr/local/bin."
    exit 1
fi

#echo "$OUTPUT_BINARY and $SERVICE_BINARY installed to /usr/local/bin"

# Create directory to hold our data if it does not already exist
sudo mkdir -p /usr/local/share/pproc

# Copy hash data to the data directory with proper permissions
sudo cp "$PROJECT_ROOT/hashes/sha1-hashes.txt" /usr/local/share/pproc/sha1-hashes.txt
echo "sha1 hashes copied to /usr/local/share/pproc/sha1-hashes.txt"
sudo cp "$PROJECT_ROOT/hashes/sha256-hashes.txt" /usr/local/share/pproc/sha256-hashes.txt
echo "sha256 hashes copied to /usr/local/share/pproc/sha256-hashes.txt"
sudo cp "$PROJECT_ROOT/hashes/md5-hashes.txt" /usr/local/share/pproc/md5-hashes.txt
echo "md5 hashes copied to /usr/local/share/pproc/md5-hashes.txt"

# Set proper permissions for the hash files
sudo chmod 644 /usr/local/share/pproc/*.txt
echo "Hash files copied to /usr/local/share/pproc/"

# Create home directory log file for non-root usage
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    touch "$USER_HOME/pproc.log"
    chown "$SUDO_USER:$SUDO_USER" "$USER_HOME/pproc.log"
    chmod 644 "$USER_HOME/pproc.log"
fi

# Create the whitelist file with proper permissions
sudo mkdir -p /usr/local/etc/pproc
sudo touch /usr/local/etc/pproc/whitelist.txt
sudo chmod 644 /usr/local/etc/pproc/whitelist.txt
sudo chown root:users /usr/local/etc/pproc/whitelist.txt
echo "Whitelist file created at /usr/local/etc/pproc/whitelist.txt"

# Add this section to create the quarantine log file
sudo touch /usr/local/etc/pproc/quarantine_log.txt
sudo chmod 666 /usr/local/etc/pproc/quarantine_log.txt
echo "Quarantine log file created at /usr/local/etc/pproc/quarantine_log.txt"

# create quarantine file 
sudo mkdir -p /var/pproc/quarantine
sudo chmod -x /var/pproc/quarantine
sudo chown root:root /var/pproc/quarantine
#sudo chmod 755 /var/pproc/quarantine
echo "Created quarantine directory file"

echo "Program and hash data successfully installed"

# Install systemd service for the service program
sudo cp "$SCRIPT_DIR/pproc-service.service" /etc/systemd/system/pproc-service.service
sudo systemctl daemon-reload
sudo systemctl enable pproc-service
sudo systemctl start pproc-service

echo "Systemd service installed and started"

# Ensure the user can use cron
if ! command -v crontab &> /dev/null; then
    echo "Installing cron..."
    sudo apt-get install cron
fi

# Create quarantine directory with proper permissions
sudo mkdir -p /usr/local/share/pproc/quarantine
sudo chown -R "$SUDO_USER:$SUDO_USER" /usr/local/share/pproc/quarantine
sudo chmod -R 755 /usr/local/share/pproc
sudo chmod 777 /usr/local/share/pproc/quarantine

echo "Installation complete"

