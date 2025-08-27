#!/bin/bash

# URL of the script to download
SCRIPT_Name="EnrollmentLauncher.sh"
SCRIPT_URL="https://raw.githubusercontent.com/uvaitsei/EEP-Jamf/refs/heads/main/Production/UVA%20Enterprise%20Jamf%20Enrollment/UVA%20Enterprise%20Jamf%20-%20Enrollment%201.0?token=GHSAT0AAAAAADJ4HVJXAAPY37QEBBB4MM6I2FM524Q"

# Temporary file to store the downloaded script

SCRIPT="/tmp/$SCRIPT_Name"

# Delete the script if it already exists
if [ -f "$SCRIPT" ]; then
    rm -f "$SCRIPT"
fi

# Download the latest script
curl -fsSL "$SCRIPT_URL" -o "$SCRIPT"

# Make the script executable
chmod +x "$SCRIPT"

# Run the script
"$SCRIPT"
