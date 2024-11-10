#!/bin/bash

#created by chatGPT

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
# Compile the source files
gcc -g -Wall -Wextra -I"$PROJECT_ROOT/src" $SRC_FILES -o "$OUTPUT_BINARY" -lcrypto
#gcc -I"$PROJECT_ROOT/src" $SRC_FILES -o "$OUTPUT_BINARY" -lcrypto

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

# create directory to hold our data if it does not already exist
# /usr/local/share is a good place to store read only data for our program 
sudo mkdir -p /usr/local/share/pproc

# copy hashes data to data directory 
sudo cp "$PROJECT_ROOT/hashes/sha1-hashes.txt" /usr/local/share/pproc/sha1-hashes.txt
