#!/bin/bash

# ============ CLIENT ============ #
CLIENT_DATA_DIR="client/data"
KEYS_DIR="client/keys/subject_keys"
SESSIONS_DIR="client/sessions"

# Check if all directories exist
if [ ! -d $CLIENT_DATA_DIR ]; then
    echo "Directory $CLIENT_DATA_DIR does not exist"
    exit 1
fi

if [ ! -d $KEYS_DIR ]; then
    echo "Directory $KEYS_DIR does not exist"
    exit 1
fi

if [ ! -d $SESSIONS_DIR ]; then
    echo "Directory $SESSIONS_DIR does not exist"
    exit 1
fi

# Delete all files in the directories

echo "Cleaning $CLIENT_DATA_DIR except 'files' subdirectory and .gitkeep..."
find $CLIENT_DATA_DIR -type f ! -name ".gitkeep" ! -path "$CLIENT_DATA_DIR/files/*" -exec rm -v {} \;

echo "Cleaning $KEYS_DIR except .gitkeep..."
find $KEYS_DIR -type f ! -name ".gitkeep" -exec rm -v {} \;

echo "Cleaning $SESSIONS_DIR except .gitkeep..."
find $SESSIONS_DIR -type f ! -name ".gitkeep" -exec rm -v {} \;

# ============ SERVER ============ #
SERVER_DATA_DIR="server/data"

# Check if dir exists
if [ ! -d $SERVER_DATA_DIR ]; then
    echo "Directory $SERVER_DATA_DIR does not exist"
    exit 1
fi

# Delete all files in the directory

echo "Cleaning $SERVER_DATA_DIR except .gitkeep..."
find $SERVER_DATA_DIR -type f ! -name ".gitkeep" -exec rm -v {} \;

echo "Cleanup complete!"