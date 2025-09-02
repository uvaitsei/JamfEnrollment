#!/bin/bash

echo "Starting UVA Enterprise Jamf Enrollment Launcher..."
# URL of the script to download
SCRIPT_Name="EnrollmentLauncher.sh"
SCRIPT_URL="https://raw.githubusercontent.com/uvaitsei/JamfEnrollment/refs/heads/main/UVAEnterpriseJamfEnrollment.sh"
ASMAPI="/private/var/tmp/UVAASM/uva.asmprod.plist"

# Confirm ASMAPI exists
if [ ! -f "$ASMAPI" ]; then
    echo "Error: $ASMAPI not found."
    exit 1
fi

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

echo "UVA Enterprise Jamf Enrollment Launcher Complete."