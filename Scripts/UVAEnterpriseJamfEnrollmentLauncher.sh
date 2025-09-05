#!/bin/bash
###########################################################################
#Script Name	:UVA Enterprise Jamf - Enrollment Launcher                                                               
#Description	:				
#				:				
#				:		
#				:                                                     
#Author       	:Matt McChesney                                            
#Email         	:mam5hs@virginia.edu
#Organization	:UVA-ITS
#Last Updated	:
#Version		:2.0
###########################################################################
# Logging Variables
# USER LOG PATH /Users/username/Library/Logs/UVA/ITS-JAMF/
# SYSTEM LOG PATH /var/log/
ScriptName="UVA Enterprise Jamf - Enrollment Launcher"
Title="UVA Enterprise Jamf - Enrollment Launcher"
Summary="Summary"
ScriptVersion="1.6"
ScriptLogPath="/var/log/UVA-JAMF/"
ScriptLogFile="UVA-Jamf-$ScriptName.log"
ScriptLog="$ScriptLogPath$ScriptLogFile"
TimeStamp=$(date +%Y-%m-%d\ %åH:%M:%S)

function CreateLogFile() {
    if [[ ! -f "$ScriptLog" ]]; then
		mkdir -p "$ScriptLogPath"
        touch "$ScriptLog"
		
    fi
}

function UpdateScriptLog() {
    echo -e "$TimeStamp - ${1}" | tee -a "${ScriptLog}"
    webhookputput+=$(echo "$TimeStamp - ${1} <br>" )

}

UpdateScriptLog "Starting UVA Enterprise Jamf Enrollment Launcher..."
# URL of the script to download
SCRIPT_Name="EnrollmentLauncher.sh"
SCRIPT_URL="https://raw.githubusercontent.com/uvaitsei/JamfEnrollment/refs/heads/main/Scripts/UVAEnterpriseJamfEnrollment.sh"
ASMAPI="/Library/Application Support/UVAJamfEnrollment/uva.asmprod.plist"
SITEINFO="/Library/Application\ Support/UVAJamfEnrollment/uva.jamfsite.plist"

# Confirm ASMAPI exists
if [ ! -f "$ASMAPI" ]; then
    UpdateScriptLog "Error: $ASMAPI not found."
    exit 1
fi
# Confirm SITEINFO exists
if [ ! -f "$SITEINFO" ]; then
    UpdateScriptLog "Error: $SITEINFO not found."
    exit 1
fi

# Temporary file to store the downloaded script
SCRIPT="/tmp/$SCRIPT_Name"
UpdateScriptLog "Downloading the latest version of $SCRIPT_Name from $SCRIPT_URL..."

# Delete the script if it already exists
if [ -f "$SCRIPT" ]; then
    rm -f "$SCRIPT"
fi

# Download the latest script
curl -fsSL "$SCRIPT_URL" -o "$SCRIPT"
if [ $? -ne 0 ]; then
    UpdateScriptLog "Error: Failed to download $SCRIPT_Name from $SCRIPT_URL."
    exit 1
fi  

# Make the script executable
chmod +x "$SCRIPT"
UpdateScriptLog "$SCRIPT_Name downloaded and made executable."

# Run the script
"$SCRIPT"
UpdateScriptLog "$SCRIPT_Name Runnig..."
UpdateScriptLog "UVA Enterprise Jamf Enrollment Launcher Complete."