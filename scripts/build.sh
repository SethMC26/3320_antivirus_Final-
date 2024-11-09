# Script created by ChatGPT

#!/bin/bash

# Get the directory of the script (scripts/ directory)
SCRIPT_DIR="$(dirname "$0")"

# Navigate to the project root by moving up one directory from scripts/
PROJECT_ROOT="$(realpath "$SCRIPT_DIR/..")"

# Define the source file location and output binary
SRC_FILE="$PROJECT_ROOT/src/pproc.c"
OUTPUT_BINARY="pproc"

# Check if pproc.c exists in src directory
if [ ! -f "$SRC_FILE" ]; then
    echo "Error: Source file pproc.c not found at $SRC_FILE"
    exit 1
fi

# Compile the source file
gcc "$SRC_FILE" -o "$OUTPUT_BINARY"
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
