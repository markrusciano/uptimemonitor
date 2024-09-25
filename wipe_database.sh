#!/bin/bash

# Path to your SQLite database file
DB_PATH="traceroute.db"

# Check if the database file exists
if [ -f "$DB_PATH" ]; then
    echo "Deleting the database file: $DB_PATH"
    rm "$DB_PATH"
    echo "Database file deleted."
else
    echo "Database file not found: $DB_PATH"
    echo "Proceeding to create a new database."
fi

# Recreate the database file with the necessary schema
echo "Recreating the database with the required schema..."
sqlite3 "$DB_PATH" <<EOF
CREATE TABLE traceroute_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    connection_name TEXT,
    target_ip TEXT,
    packet_loss REAL
);
EOF
echo "Database recreated successfully."
