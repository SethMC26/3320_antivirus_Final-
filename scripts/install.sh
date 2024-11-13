#!/bin/bash

#created by chatGPT
echo "Starting install"

# Get the directory of the script (scripts/ directory)
SCRIPT_DIR="$(dirname "$0")"

# Navigate to the project root by moving up one directory from scripts/
PROJECT_ROOT="$(realpath "$SCRIPT_DIR/..")"

# Define the output binary
OUTPUT_BINARY="pproc"

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

# Compile the source files with all necessary flags
gcc -g -Wall -Wextra \
    -I"$PROJECT_ROOT/src" \
    -pthread \
    $SRC_FILES \
    -o "$OUTPUT_BINARY" \
    -lcrypto

# Check if compilation succeeded
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

# Move the binary to /usr/local/bin (requires sudo)
sudo mv "$OUTPUT_BINARY" /usr/local/bin/$OUTPUT_BINARY
if [ $? -ne 0 ]; then
    echo "Failed to move $OUTPUT_BINARY to /usr/local/bin."
    exit 1
fi

echo "$OUTPUT_BINARY installed to /usr/local/bin"

# Create directory to hold our data if it does not already exist
# /usr/local/share is a good place to store read only data for our program 
sudo mkdir -p /usr/local/share/pproc

# Copy hashes data to data directory with proper permissions
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

echo "Program successfully installed"