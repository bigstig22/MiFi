#!/bin/bash

# Define the list of directories
directories=("john" "hc" "logs" "collection" "archive")

# Define the database file
db_file="networks.db"

# Create directories if they don't exist
for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Creating directory: $dir"
        mkdir -p "$dir"
    else
        echo "Directory already exists: $dir"
    fi
done

# Create the database file if it doesn't exist
if [ ! -f "$db_file" ]; then
    echo "Creating database file: $db_file"
    touch "$db_file"
else
    echo "Database file already exists: $db_file"
fi
