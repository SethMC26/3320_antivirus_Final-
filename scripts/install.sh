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

# Compile the source files for the CLI program (pproc)
gcc -g -Wall -Wextra -I"$PROJECT_ROOT/src" $SRC_FILES -o "$OUTPUT_BINARY" -lcrypto

# Now compile the service program (pproc-service), explicitly including the necessary source files
# We explicitly add `scanner.c` and `fingerprint.c` to resolve undefined references
gcc -g -Wall -Wextra -I"$PROJECT_ROOT/src" \
    "$PROJECT_ROOT/src/pproc-service.c" \
    "$PROJECT_ROOT/src/Utils/scanner.c" \
    "$PROJECT_ROOT/src/Crypto/fingerprint.c" \
    -o "$SERVICE_BINARY" -lcrypto -D_GNU_SOURCE -DSERVICE_MAIN

# Check if compilation succeeded for both binaries
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

# Move the binaries to /usr/local/bin (requires sudo)
sudo mv "$OUTPUT_BINARY" /usr/local/bin/$OUTPUT_BINARY
sudo mv "$SERVICE_BINARY" /usr/local/bin/$SERVICE_BINARY
if [ $? -ne 0 ]; then
    echo "Failed to move binaries to /usr/local/bin."
    exit 1
fi

echo "$OUTPUT_BINARY and $SERVICE_BINARY installed to /usr/local/bin"

# Create directory to hold our data if it does not already exist
sudo mkdir -p /usr/local/share/pproc

# Copy hash data to the data directory 
sudo cp "$PROJECT_ROOT/hashes/sha1-hashes.txt" /usr/local/share/pproc/sha1-hashes.txt
echo "sha1 hashes copied to /usr/local/share/pproc/sha1-hashes.txt"
sudo cp "$PROJECT_ROOT/hashes/sha256-hashes.txt" /usr/local/share/pproc/sha256-hashes.txt
echo "sha256 hashes copied to /usr/local/share/pproc/sha256-hashes.txt"
sudo cp "$PROJECT_ROOT/hashes/md5-hashes.txt" /usr/local/share/pproc/md5-hashes.txt
echo "md5 hashes copied to /usr/local/share/pproc/md5-hashes.txt"

# Install systemd service
sudo cp "$SCRIPT_DIR/pproc-service.service" /etc/systemd/system/pproc-service.service
sudo systemctl daemon-reload
sudo systemctl enable pproc-service
sudo systemctl start pproc-service

echo "Program and service successfully installed"
