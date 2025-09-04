#!/bin/bash

###########################################################################
#Script Name	:UVA Enterprise Jamf - Enrollment                                                                 
#Description	:				
#				:				
#				:		
#				:                                                     
#Author       	:Matt McChesney                                            
#Email         	:mam5hs@virginia.edu
#Organization	:UVA-ITS
#Last Updated	:
#Version		:1.5

###########################################################################
# Script Change History
###########################################################################
# 
#
#
###########################################################################
###########################################################################
# Functions List
###########################################################################
# CreateLogFile
# UpdateScriptLog
# Check for System Support Variables
# Check for Site Support Variables
# Check for Device Support Variables
# RootCheck
# ToggleJamfLaunchDaemon
# KillProcess
# EnableCaffeinate
# CheckforUVABranding
# WaitForSetupAssis
# WaitForFinder

## Swift Dialog ##
# SwiftDialogInstall
# SwiftDialogCheck

## API Functions ##
# GenerateEncryptedString
# DecryptString
# CheckTokenExpiration
# GetAccessToken
# CheckTokenExpiration
# InvalidateToken
# GetComputerInfoFromAPI

# ManagedPreferencesCheck
# SendTeamsMessage
# CleanUp


#Verbose Mode True or False 
VerboseMode="True"

###########################################################################
#Functions To Call Later (Remove any Unused)
###########################################################################

###########################################################################
# Function : Create and Update Logs File
###########################################################################

# Logging Variables
# USER LOG PATH /Users/username/Library/Logs/UVA/ITS-JAMF/
# SYSTEM LOG PATH /var/log/
ScriptName="UVA Enterprise Jamf - Enrollment"
Title="UVA Enterprise Jamf - Enrollment"
Summary="Summary"
ScriptVersion="1.5"
ScriptLogPath="/var/log/UVA-JAMF/"
ScriptLogFile="UVA-Jamf-$ScriptName.log"
ScriptLog="$ScriptLogPath$ScriptLogFile"
TimeStamp=$(date +%Y-%m-%d\ %H:%M:%S)

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

function DialogUpdate() {
    UpdateScriptLog "SWIFT DIALOG UPDATE: $1"
    echo "$1" >> "$SwiftCommandFile"
}

function CreateSwiftDialogCommandFile() {
    SwiftCommandDirectory="/var/tmp/SwiftCommand"
    if [ -d "$SwiftCommandDirectory" ]; then
        UpdateScriptLog "Swift Command Directory: Removing previous $SwiftCommandDirectory"
        /bin/rm -fR $SwiftCommandDirectory
        UpdateScriptLog "Swift Command Directory: Creating New $SwiftCommandDirectory"
        mkdir $SwiftCommandDirectory
    else 
        UpdateScriptLog "Swift Command Directory: Creating $SwiftCommandDirectory"
        mkdir $SwiftCommandDirectory
    fi

    SwiftCommandFile=$( mktemp $SwiftCommandDirectory/swiftcommand.XXX )
    UpdateScriptLog "Swift Command File: $SwiftCommandFile"

    # Set permissions for all users
    chmod 644 $SwiftCommandFile
    chmod 755 $SwiftCommandDirectory
}


function JamfEnrollment() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	DialogBinary="/usr/local/bin/dialog"  
	
	$DialogBinary \
	--title "$Title" \
	--message "Checking Enrollment Status" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1disabled "true" \
	--commandfile "$SwiftCommandFile" \
	--titlefont "shadow=true, size=40" \
	--progress "100" \
	--progresstext "Checking for Enrollment Status" \
	--height "300" \
	&
	
}

function JamfEnrollmentAutmated() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	DialogBinary="/usr/local/bin/dialog"  
	
	$DialogBinary \
	--title "$Title" \
	--message "Guided Automated Enrollment" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1disabled "true" \
	--commandfile "$SwiftCommandFile" \
	--titlefont "shadow=true, size=40" \
	--progress "100" \
	--progresstext "Checking for Enrollment Status" \
	--height "300" \
	&
	
	if [[ "$JamfEnrolled" == "True" ]]; then
		DialogUpdate "progresstext: Removing Jamf Framework"
		sleep 3
		if /usr/local/bin/jamf removeFramework &> /dev/null; then
			UpdateScriptLog "JAMF REMOVAL: Jamf Framework Removed"
			DialogUpdate "progresstext: Jamf Framework Removed"
			sleep 3

			# Wait up to 5 minutes for MDM profile to be removed
			ProfileRemoved="False"
			for ((i=0; i<300; i++)); do
				if ! /usr/bin/profiles -C | grep "attribute: profileIdentifier: com.jamfsoftware.tcc.management"; then
					ProfileRemoved="True"
					UpdateScriptLog "MDM PROFILE: MDM profile successfully removed."
					break
				fi
				if (( i % 10 == 0 )); then
					UpdateScriptLog "MDM PROFILE: Waiting for up to 5 minutes for MDM Profile to be removed."
					DialogUpdate "progresstext: Waiting for up to 5 minutes for MDM Profile to be removed."
				fi
				sleep 1
			done

			DialogUpdate "progresstext: Starting Automated Enrollment"
			sleep 5
			profiles renew -type enrollment

			# Wait up to 5 minutes for MDM profile to be installed
			ProfileInstalled="False"
			for ((i=0; i<300; i++)); do
				if /usr/bin/profiles -C | grep "attribute: profileIdentifier: com.jamfsoftware.tcc.management"; then
					ProfileInstalled="True"
					UpdateScriptLog "MDM PROFILE: MDM profile successfully installed."
					break
				fi
				if (( i % 10 == 0 )); then
					UpdateScriptLog "MDM PROFILE: Waiting for up to 5 minutes for MDM Profile to install."
					DialogUpdate "progresstext: Waiting for up to 5 minutes for MDM Profile to install."
				fi
				sleep 1
			done
		else
			UpdateScriptLog "JAMF REMOVAL: ERROR: Jamf Framework Could Not be Removed"
			DialogUpdate "progresstext: ERROR: Jamf Framework Could Not be Removed"
			sleep 3
		fi
	fi

	
	if [[ "$ProfileInstalled" == "True" ]]; then
		UpdateScriptLog "MDM PROFILE: MDM profile successfully installed."
		DialogUpdate "progresstext: MDM profile successfully installed."
		sleep 30
		DialogUpdate "quit:"
	else
		UpdateScriptLog "MDM PROFILE: MDM profile could not be found after 5 minutes."
		DialogUpdate "progresstext: MDM profile could not be found after 5 minutes."
		sleep 30
		DialogUpdate "quit:"
	fi

}



function JamfEnrollmentManual() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	DialogBinary="/usr/local/bin/dialog"  
	
	$DialogBinary \
	--title "Guided Manual Enrollment" \
	--message "Please follow the guided instructions" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1disabled "true" \
	--commandfile "$SwiftCommandFile" \
	--titlefont "shadow=true, size=40" \
	--progress "100" \
	--progresstext "Starting Manual Enrollment" \
	--height "300" \
	&

	if [[ "$JamfEnrolled" == "True" ]]; then
		DialogUpdate "progresstext: Removing Jamf Framework"
		sleep 3
		# Remove Jamf Framework
		if /usr/local/bin/jamf removeFramework &> /dev/null; then
			UpdateScriptLog "JAMF REMOVAL: Jamf Framework Removed"
			DialogUpdate "progresstext: Jamf Framework Removed"
			sleep 3
			# Wait up to 5 minutes for MDM profile to be removed
			MDMProfileStatus="Removed"
			MDMProfileIdentifier="com.jamfsoftware.tcc.management"
			ProfileRemoved="False"
			for ((i=0; i<300; i++)); do
				if ! /usr/bin/profiles -C | grep -q "$MDMProfileIdentifier"; then
					ProfileRemoved="True"
					UpdateScriptLog "MDM profile successfully removed."
					break
				fi
				sleep 1
			done
			if [[ "$ProfileRemoved" == "True" ]]; then
				UpdateScriptLog "MDM PROFILE: MDM profile successfully removed."
				DialogUpdate "progresstext: MDM profile successfully removed."
			else
				UpdateScriptLog "MDM PROFILE: MDM profile could not be removed after 5 minutes."
				DialogUpdate "progresstext: MDM profile could not be removed after 5 minutes."
				MDMProfileStatus="NonRemovable"
				JamfMDMProfileUnremoveable
			fi
		fi
	fi

	DialogUpdate "progresstext: Downloading MDM Profile"
	get_mdm_profile
	sleep 3
	DialogUpdate "progresstext: Installing MDM Profile"
	profiles install -type profile -path /tmp/enrollmentProfile.mobileconfig
	DialogUpdate "quit:"
	
}

function JamfMDMProfileUnremoveable() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	EnrollmentInfo="### UVA Enterprise Jamf Non removable MDM Instructions \
	\n This compuer was previously setup in a prestage where the MDM profile was marked as not removable. "

	DialogBinary="/usr/local/bin/dialog"  

	$DialogBinary \
	--title "MDM Profile Not Removable" \
	--message "$EnrollmentInfo" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1text "Continue" \
	--titlefont "shadow=true, size=40" \
	--height "800" 
	
	#Buttons
    case $? in
        0)
        # Button 1 processing here
        UpdateScriptLog "NOT REMOVABLE BUTTON: $CurrentUser Pressed (Continue)"
		JamfEnrollmentManual
		exit 0
        ;;
        *)
        # No Button processing here
        UpdateScriptLog "NOT REMOVABLE BUTTON: $CurrentUser Did not press (Cancel) or (Continue)"
		CleanUp
		exit 1
        ;;
    esac
	
	
}


function DetectJamfEnrollment() {
	#Check for Jamf Enrollment
	if /usr/local/bin/jamf checkJSSConnection &> /dev/null; then
		UpdateScriptLog "JAMF ENROLLMENT: This Computer is enrolled in UVA EnterpriseJamf"
		DialogUpdate "progresstext: This Computer is already enrolled in UVA Enterprise Jamf"
		JamfEnrolled="True"
		sleep 3
	else
		UpdateScriptLog "JAMF ENROLLMENT: This Computer is NOT enrolled in UVA Enterprise Jamf"
		DialogUpdate "progresstext: This Computer is NOT enrolled in UVA Enterprise Jamf"
		JamfEnrolled="False"
		sleep 3
	fi
}

function get_mdm_profile () {

  jamfServer="https://itsemp.jamfcloud.com"
  INVITE="112074622686329411668504078807099522400"
  UpdateScriptLog user: $CurrentUser
  UpdateScriptLog server: $jamfServer
  UpdateScriptLog invite: $INVITE
  /usr/bin/curl "$jamfServer"'/enroll/?' \
    -H 'authority: '"$jamfServer"'' \
    -H 'cache-control: max-age=0' \
    -H 'sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"' \
    -H 'sec-ch-ua-mobile: ?0' \
    -H 'sec-ch-ua-platform: "macOS"' \
    -H 'upgrade-insecure-requests: 1' \
    -H 'origin: '"$jamfServer"'' \
    -H 'content-type: application/x-www-form-urlencoded' \
    -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36' \
    -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H 'sec-fetch-site: same-origin' \
    -H 'sec-fetch-mode: navigate' \
    -H 'sec-fetch-user: ?1' \
    -H 'sec-fetch-dest: document' \
    -H 'referer: '"$jamfServer"'/enroll/?' \
    -H 'accept-language: en-US,en;q=0.9' \
    -H 'cookie: _ga=GA1.1.1641720015.1632512756; _ga_X3HZEK54PC=GS1.1.1635861674.1.0.1635861782.60; JSESSIONID=YWQ4Mzk0MzEtODliZi00YzFjLWFhMWYtYjYwNzkzNTY5Mjk3; AWSALB=Ck4pGD1IbuyOQ+91Dd0c1os/seaZHkbgagBNLJQXdLHpWiRQvsxMojkBZLKY6zTzoYkQJEe8j8iFCs70uTxrf+l1tjchlLMv7wv7iMyRWI/DxGt7r2sydG60nVME; AWSALBCORS=Ck4pGD1IbuyOQ+91Dd0c1os/seaZHkbgagBNLJQXdLHpWiRQvsxMojkBZLKY6zTzoYkQJEe8j8iFCs70uTxrf+l1tjchlLMv7wv7iMyRWI/DxGt7r2sydG60nVME' \
    --data-raw 'lastPage=installEnterpriseProfile.jsp&payload=enterprise&device-detect-complete=&invitation='"$INVITE"'&type=' \
    --compressed -o /tmp/enrollmentProfile.mobileconfig
}


###########################################################################
#Curl Needed Files
###########################################################################
function CheckFilesNeeded() {
	
	ASMAPI="/private/var/tmp/UVAASM/uva.asmprod.plist"
	# Check for the existence of ASM API Config File and delete if it exists
	# Ensure latest ASM API Config File is present
	if [ -f "$ASMAPI" ]; then
		UpdateScriptLog "ASM API CONFIG CHECK: $ASMAPI exists"
	else
		UpdateScriptLog "ASM API CONFIG CHECK: $ASMAPI does not exist"
		exit 1
	fi

	if test -f "$ASMAPI"
	then
		UpdateScriptLog "ASM API VARIABLES CHECK: $ASMAPI Detected"
		ClientID=$(defaults read "$ASMAPI" ClientID 2>/dev/null)
		ClientAssertion=$(defaults read "$ASMAPI" ClientAssertion 2>/dev/null)
		ClientName=$(defaults read "$ASMAPI" ClientName 2>/dev/null)
	else
		UpdateScriptLog "ASM API VARIABLES CHECK: No ASM API Variables Detected Use Default Setting"
		ClientID="Not Found"
		ClientAssertion="Not Found"
		ClientName="Not Found"
	fi

}


###########################################################################
# Check for System Support Variables
###########################################################################
function CheckSystemSupportVariables() {
	
	SystemSupport="/Library/Managed Preferences/uva.enterprisejamfsystem.com.plist"

	if test -f "$SystemSupport"
	then
		UpdateScriptLog "SYSTEM SUPPORT VARIABLES CHECK: $SystemSupport Detected"
		#JAMF VARIABLES
		URL=$(defaults read "$SystemSupport" JSSURL 2>/dev/null)
		JAMFBINARY=$(defaults read "$SystemSupport" JAMFBINARY 2>/dev/null)
		JSSID=$(defaults read "$SystemSupport" JSSID 2>/dev/null)

		UpdateScriptLog "SYSTEM SUPPORT VARIABLES CHECK:: Found JSSURL for this device: $URL"
		UpdateScriptLog "SYSTEM SUPPORT VARIABLES CHECK:: Found JAMFBINARY for this device: $JAMFBINARY"
		UpdateScriptLog "SYSTEM SUPPORT VARIABLES CHECK:: Found JSSID for this device: $JSSID"

		#API VARIABLES
		Salt=$(defaults read "$SystemSupport" APIComputerRenameSalt 2>/dev/null)
		#UpdateScriptLog "SYSTEM SUPPORT VARIABLES CHECK:: Found APIComputerRenameSalt for this device: $Salt"

		#BRANDING VARIABLES
		BannerImage=$(defaults read "$SystemSupport" BannerImage 2>/dev/null)
		IconImage=$(defaults read "$SystemSupport" IconImage 2>/dev/null)
	else
		UpdateScriptLog "SYSTEM SUPPORT VARIABLES CHECK: No System Support Variables Detected Use Default Setting"
		URL="Not Found"
		JAMFBINARY="/usr/local/bin/jamf"
		JSSID="Not Found"
	fi
}



###########################################################################
# Function: Confirm script is running as root
###########################################################################

function RootCheck() {
	if [[ $(id -u) -ne 0 ]]; then
    	UpdateScriptLog "ROOT CHECK :ERROR: This script must be run as root; exiting."
		SendTeamsMessage
    	exit 1
	fi
}

###########################################################################
# Function: Kill Specific Processs
###########################################################################
function KillProcess() {
	ProcessPid=$( pgrep -a "${1}")
	if [ -n "$ProcessPid" ]; then
		kill "$ProcessPid"
		wait "$ProcessPid" 2>/dev/null
		ProcessPid=$( pgrep -a "${1}")
		if [ -z "$ProcessPid" ]; then
			UpdateScriptLog "KILL PROCESS: $1 Terminated"
		else
            UpdateScriptLog "KILL PROCESS: ERROR: '$1' could not be terminated."
        fi
	else
		UpdateScriptLog "KILL PROCESS: The '$1' process isn't running."
	fi

}


###########################################################################
# Function: Enable and Disable Caffeinate to Prevent Computer from Sleeping
###########################################################################

function EnableCaffeinate() {
	ScriptPID="$$"
	UpdateScriptLog "DISABLE SLEEP: Caffeinating this script (PID: $ScriptPID)"
	caffeinate -dimsu -w $ScriptPID &
}

function DisableCaffeinate () {
	UpdateScriptLog "ENABLE SLEEP: Disabling Caffinate"
	KillProcess "caffeinate"
}


###########################################################################
# Function: Wait for Setup Assistant to Finish
###########################################################################

function WaitForSetupAssistant() {

	while pgrep -q -x "Setup Assistant"; do
    	UpdateScriptLog "WAIT FOR SETUP ASSISTANT: Setup Assistant is still running; Waiting for 2 seconds"
    	sleep 2
	done

	UpdateScriptLog "WAIT FOR SETUP ASSISTANT: Setup Assistant is no longer running; proceeding …"
}

###########################################################################
# Function : Wait for Finder to Load
###########################################################################

function WaitForFinder() {

	until pgrep -q -x "Finder" && pgrep -q -x "Dock"; do
    	UpdateScriptLog "WAIT FOR FINDER: Finder & Dock are NOT running; Waiting for 1 second"
    	sleep 1
	done

	UpdateScriptLog "WAIT FOR FINDER: Finder & Dock are running; proceeding …"
}

###########################################################################
# Function : Current Logged in User
###########################################################################

function CurrentLoggedInUser() {
    CurrentUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
    UpdateScriptLog "CURRENT USER: ${CurrentUser}"
}

###########################################################################
# Function : Swift Dialog Intall for User Interactions
###########################################################################
swiftDialogMinimumRequiredVersion="2.3.2.4726"

function SwiftDialogInstall() {

    # Get the URL of the latest PKG From the Dialog GitHub repo
    DialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    ExpectedDialogTeamID="PWA5E9TQ59"

    UpdateScriptLog "SWIFT DIALOG INSTALL: Installing swiftDialog..."

    # Create temporary working directory
    WorkDirectory=$( /usr/bin/basename "$0" )
    TempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$WorkDirectory.XXXXXX" )

    # Download the installer package
    /usr/bin/curl --location --silent "$DialogURL" -o "$TempDirectory/Dialog.pkg"

    # Verify the download
    TeamID=$(/usr/sbin/spctl -a -vv -t install "$TempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$ExpectedDialogTeamID" == "$TeamID" ]]; then

        /usr/sbin/installer -pkg "$TempDirectory/Dialog.pkg" -target /
        sleep 2
        DialogVersion=$( /usr/local/bin/dialog --version )
        UpdateScriptLog "SWIFT DIALOG INSTALL: swiftDialog version ${DialogVersion} installed; proceeding..."

    else

		UpdateScriptLog "SWIFT DIALOG INSTALL: Error Could Not Install"

    fi

    # Remove the temporary working directory when done
    /bin/rm -Rf "$tempDirectory"

}


function SwiftDialogCheck() {


    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then

        UpdateScriptLog "SWIFT DIALOG CHECK: swiftDialog not found. Installing..."
        SwiftDialogInstall

    else

        DialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${DialogVersion}" < "${SwiftDialogMinimumRequiredVersion}" ]]; then
            
            UpdateScriptLog "SWIFT DIALOG CHECK: swiftDialog version ${DialogVersion} found but swiftDialog ${SwiftDialogMinimumRequiredVersion} or newer is required; updating..."
            SwiftDialogInstall
            
        else

        UpdateScriptLog "SWIFT DIALOG CHECK: swiftDialog version ${dialogVersion} found; proceeding..."

        fi
    
    fi

}


############################################################################
# Apple School Manager Device Service Lookup
############################################################################

function ASMDeviceServiceLookup() {

	# URL to test
	URL="https://school.apple.com"

	UpdateScriptLog "ASM LOOKUP: Testing internet connectivity to $URL..."

	# Use curl to follow redirects and check for any HTTP success code (2xx)
	HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -lt 300 ]]; then
    	UpdateScriptLog "ASM LOOKUP: Internet connection to Apple School Manager is reachable (HTTP $HTTP_STATUS)."
	else
    	UpdateScriptLog "ASM LOOKUP: Internet connection to Apple School Manager failed (HTTP $HTTP_STATUS). Check your network settings."
    	exit 1
	fi


	ACCESS_TOKEN=$(curl -s -X POST \
	-H 'Host: account.apple.com' \
	-H 'Content-Type: application/x-www-form-urlencoded' \
	--data "grant_type=client_credentials&client_id=${ClientID}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=${ClientAssertion}&scope=school.api" \
	https://account.apple.com/auth/oauth2/token | jq -r '.access_token')


	if [ -z "$ACCESS_TOKEN" ]; then
    	UpdateScriptLog "ASM LOOKUP: Error: ACCESS_TOKEN is empty. Authentication failed."
    	exit 1
	fi

	SerialNumber=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}')
	UpdateScriptLog "ASM LOOKUP: Serial Number: $SerialNumber"	

	# Get the assigned server ID for the device
	assignedServerResponse=$(curl -s "https://api-school.apple.com/v1/orgDevices/$SerialNumber/relationships/assignedServer" \
    	-H "Authorization: Bearer ${ACCESS_TOKEN}")

	# Extract the "id" value from the JSON response
	assignedServerId=$(echo "$assignedServerResponse" | grep -o '"id" *: *"[^"]*"' | head -1 | cut -d':' -f2 | tr -d ' "')

	#Get Server Name
	serviceName=$(curl -s "https://api-school.apple.com/v1/mdmServers" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" | \
    jq -r --arg id "$assignedServerId" '.data[] | select(.id == $id) | .attributes.serverName')

	UpdateScriptLog "ASM LOOKUP: Assigned Devcice Service Name: $serviceName"

	# Determine PlatformName based on serviceName prefix
	if [[ "$serviceName" == EJ-* ]]; then
		PlatformName="UVA Enterprise Jamf"
	elif [[ "$serviceName" == ITS-* ]]; then
		PlatformName="ITS-JAMF"
	else
		PlatformName="Platform Not Found"
	fi

	#No Service name Found
	if [[ -z "$serviceName" ]]; then
		serviceName="No Service Name Found"
	fi	

	UpdateScriptLog "ASM LOOKUP: Platform Name: $PlatformName"
	
}

############################################################################
# Send Teams notification 
############################################################################

function SendTeamsMessage() {

	if [[ $TeamsWebhookURL == "" ]]; then
		UpdateScriptLog "WEBHOOK: No teams Webhook configured"
		return
	else
        SerialNumber=$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}')
        HostName=`hostname`	
		jsonPayload='{
		"@type": "MessageCard",
		"@context": "http://schema.org/extensions",
		"themeColor": "0076D7",
		"summary": "'"$Summary"'",
		"sections": [{
			"activityTitle": "'"$Title"'",
			"activityImage": "https://use1.ics.services.jamfcloud.com/icon/hash_943849af8d06181679bc9d792faac126bca7f0d57caa16b0991c58a17a59c6e1",
			"facts": [{
				"name": "Device Name:",
				"value": "'"$HostName"'"
			}, {
				"name": "Serial Number",
				"value": "'"$SerialNumber"'"
			}, {
				"name": "Jamf ID",
				"value": "'"$ID"'"
			}, {
				"name": "Management ID",
				"value": "'"$ManagedID"'"
			}, {
				"name": "Requested by:",
				"value": "'"$CurrentUser"'"
			}, {
				"name": "Reason",
				"value": "'"$Reason"'"
			}, {
				"name": "LAPS Username",
				"value": "'"$LapsUser"'"
			}, {
				"name": "Time Viewed",
				"value": "'"$TimeStamp"'"
            }, {
                "name": "Script Output",
			    "value": "'"$webhookputput"'"
			}],
			"markdown": true
		}],
		"potentialAction": [{
			"@type": "OpenUri",
			"name": "Device Jamf Page",
			"targets": [{
				"os": "default",
				"uri":
				"'"https://itsemp.jamfcloud.com/computers.html?id=$ID&o=r"'"
			}]
		}]
	}'
    fi

	# Send the JSON payload using curl
	UpdateScriptLog "WEBHOOK: Send Teams WebHook"
    curl -s -X POST -H "Content-Type: application/json" -d "$jsonPayload" "$TeamsWebhookURL" &> /dev/null
	
}

############################################################################
# Manual Enrollment Swift Dialog Display
############################################################################

function ManualEnrollment() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	EnrollmentInfo="### UVA Enterprise Jamf Manual Enrollment Instructions \
	\n1. Open a web browser and go to the following URL: https://itsemp.jamfcloud.com/enroll \
	\n2. When prompted, enter your UVA credentials to log in. \
	\n3. Follow the on-screen instructions to download and install the MDM profile.\
	\n4. Once the profile is installed, your device will be enrolled in UVA Enterprise Jamf. \
	\n5. If you encounter any issues during the enrollment process, please contact the ITS Help Desk at (434) 924-HELP or helpdesk@virginia"

	DialogBinary="/usr/local/bin/dialog"  

	$DialogBinary \
	--title "UVA Enterprise Jamf Manual Enrollment" \
	--message "$EnrollmentInfo" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1text "Enroll" \
	--button2text "Cancel" \
	--titlefont "shadow=true, size=40" \
	--height "800" 
	
	#Buttons
    case $? in
        0)
        # Button 1 processing here
        UpdateScriptLog "MANUAL ENROLL BUTTON: $CurrentUser Pressed (Enroll"
		JamfEnrollmentManual
		exit 0
        ;;
		1)
        # Button 2 processing here
        UpdateScriptLog "MANUAL ENROLL BUTTON: $CurrentUser Pressed (Cancel)"
		exit 0
        ;;
        *)
        # No Button processing here
        UpdateScriptLog "MANUAL ENROLL BUTTON: $CurrentUser Did not press (Cancel) or (Enroll)"
		CleanUp
		exit 1
        ;;
    esac
	
}


function AutomatedEnrollment() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	EnrollmentInfo="### UVA Enterprise Jamf Automated Enrollment Instructions\
	Platorm Name: $PlatformName \
	Service Name: $serviceName"

	DialogBinary="/usr/local/bin/dialog"  

	$DialogBinary \
	--title "UVA Enterprise Jamf Automated Enrollment" \
	--message "$EnrollmentInfo" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1text "Enroll" \
	--button2text "Cancel" \
	--titlefont "shadow=true, size=40" \
	--height "500" 
	
	#Buttons
    case $? in
        0)
        # Button 1 processing here
        UpdateScriptLog "AUTO ENROLL BUTTON: $CurrentUser Pressed (Enroll)"
		JamfEnrollmentAutmated
		exit 0
        ;;
		1)
        # Button 2 processing here
        UpdateScriptLog "AUTO ENROLL BUTTON: $CurrentUser Pressed (Cancel)"
		exit 0
        ;;
        *)
        # No Button processing here
        UpdateScriptLog "AUTO ENROLL BUTTON: $CurrentUser Did not press (Cancel) or (Enroll)"
		CleanUp
		exit 1
        ;;
    esac
	
}


############################################################################
# Script Cleanup 
############################################################################


function CleanUp() {

	#Add Any Cleanup Items Here. 
	UpdateScriptLog "ClEANUP:"

}

function UpdateJamfInventory() {
	#Update Jamf Inventory
	UpdateScriptLog "UPDATE JAMF INVENTORY: Starting"
	$JAMFBINARY recon
	UpdateScriptLog "UPDATE JAMF INVENTORY: Completed"
}


############################################################################
# Script Start
############################################################################

#Script Initilization
###########################################################################
CreateLogFile
UpdateScriptLog "SCRIPT HEADER: $Title - $ScriptName - Version: $ScriptVersion : Start"
CreateSwiftDialogCommandFile
EnableCaffeinate
CheckSystemSupportVariables
RootCheck
WaitForSetupAssistant
WaitForFinder
CurrentLoggedInUser
SwiftDialogCheck

##Script Functions
JamfEnrollment
DetectJamfEnrollment
#Check Needed Files
CheckFilesNeeded

#Check for Apple School Manager Device Service to determine if Automated Enrollment or Manual Enrollment	
ASMDeviceServiceLookup
if [ "$serviceName" = "No Service Name Found" ]; then
	UpdateScriptLog "AUTOMATED DEVICE ENROLLMENT:: This Computer is NOT enrolled UVA Enterprise Jamf Device Services through Apple School Manager"
	UpdateScriptLog "AUTOMATED DEVICE ENROLLMENT: Must Use Manual Enrollment"
	EnrollmentType="Manual"
else
	UpdateScriptLog "AUTOMATED DEVICE ENROLLMENT: This Computer is in UVA Enterprise Jamf Device Service"
	UpdateScriptLog "AUTOMATED DEVICE ENROLLMENT: Use Automated Enrollment"
	EnrollmentType="Automated"
fi

if [[ "$EnrollmentType" == "Automated" ]]; then
	UpdateScriptLog "AUTOMATED DEVICE ENROLLMENT: Start Automated Enrollment"
	#Display Computer Information and Prompt for Enrollment
	DialogUpdate "progresstext: Automated Enrollment Available"
	sleep 3
	if [[ "$JamfEnrolled" == "True" ]]; then
		DialogUpdate "progresstext: This deviice will be re-enrolled in UVA Enterprise Jamf"
		sleep 3
	fi
	DialogUpdate "quit:"
	AutomatedEnrollment
fi

if [[ "$EnrollmentType" == "Manual" ]]; then
	UpdateScriptLog "MANUAL DEVICE ENROLLMENT: Start Manual Enrollment"
	#Display Computer Information and Prompt for Web Enrollment
	DialogUpdate "progresstext: Manual Enrollment Required"
	sleep 3
	if [[ "$JamfEnrolled" == "True" ]]; then
		DialogUpdate "progresstext: This deviice will be re-enrolled in UVA Enterprise Jamf"
		sleep 3
	fi
	DialogUpdate "quit:"
	ManualEnrollment
fi


#Script Finilization
############################################################################
DisableCaffeinate
UpdateScriptLog "SCRIPT FOOTER: $Title - $ScriptName - Version: $ScriptVersion : End"
SendTeamsMessage
CleanUp
exit 0