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
#Version		:2.01
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
ScriptVersion="2.1"
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


function JamfEnrollmentStatus() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	DialogBinary="/usr/local/bin/dialog"  
	
	$DialogBinary \
	--title "$Title" \
	--message "Checking UVA Enterprise Jamf Enrollment" \
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
	
	#Check for Jamf Enrollment
	if /usr/local/bin/jamf checkJSSConnection &> /dev/null; then
		UpdateScriptLog "JAMF ENROLLMENT: This Computer is enrolled in UVA EnterpriseJamf"
		DialogUpdate "progresstext: This Computer is already enrolled in UVA Enterprise Jamf"
		JamfEnrolled="True"
		sleep 5
	else
		UpdateScriptLog "JAMF ENROLLMENT: This Computer is NOT enrolled in UVA Enterprise Jamf"
		DialogUpdate "progresstext: This Computer is NOT enrolled in UVA Enterprise Jamf"
		JamfEnrolled="False"
		MDMProfile="False"
		sleep 5
	fi

	#Check for SITEINFO="/Library/Application Support/UVAJamfEnrollment/uva.jamfsite.plist"
	if [[ -f "/Library/Application Support/UVAJamfEnrollment/uva.jamfsite.plist" ]]; then
		UpdateScriptLog "JAMF ENROLLMENT: Site Information found for $SiteName"
		DialogUpdate "progresstext: Site Information found for $SiteName"
	else
		UpdateScriptLog "JAMF ENROLLMENT: Site Information NOT found"
		DialogUpdate "progresstext: Site Information NOT found"
		SiteEnrollmentInvitation="False"
	fi

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
			JamfMDMProfileUnremoveable
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
		CleaanUp
	fi

}



function JamfEnrollmentManual() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"
	
	DialogBinary="/usr/local/bin/dialog"  
	
	$DialogBinary \
	--title "Manual Enrollment" \
	--messagefont "size=16" \
	--icon "none" \
	--image "https://github.com/uvaitsei/JamfImages/blob/main/ICONS/COMMON-UVA-USER-ICON.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--button1disabled "true" \
	--commandfile "$SwiftCommandFile" \
	--titlefont "shadow=true, size=20" \
	--progress "100" \
	--progresstext "Starting Manual Enrollment" \
	--height "500" \
	--width "500" \
	--position "bottomright" \
	--activate "true" \
	&
	
	if [[ "$JamfEnrolled" == "True" ]]; then
		DialogUpdate "progresstext: Removing Jamf Framework"
		RemoveJamfFramework
		DialogUpdate "progresstext: Removing CA Certificate"
		RemoveCACertificate
		DialogUpdate "progresstext: Installing CA Certificate and MDM Profile"
		InstallCACertandMDMProfile
	else
		DialogUpdate "progresstext: Removing CA Certificate if it exists"
		RemoveCACertificate
		DialogUpdate "progresstext: Installing CA Certificate and MDM Profile"
		InstallCACertandMDMProfile
	fi

}

function RemoveJamfFramework() {
	DialogUpdate "progresstext: Removing Jamf Framework"
	sleep 3
	# Remove Jamf Framework
	if /usr/local/bin/jamf removeFramework &> /dev/null; then
		UpdateScriptLog "JAMF REMOVAL: Jamf Framework Removed"
		DialogUpdate "progresstext: Jamf Framework Removed"
		sleep 3
		# Wait up to 5 minutes for MDM profile to be removed
		MDMProfile="True"
		for ((i=0; i<40; i++)); do

			if [[ -z $(/usr/bin/profiles show -all | grep "name: MDM Profile") ]]; then
				MDMProfile="False"
				UpdateScriptLog "MDM profile successfully removed."
				break
			fi

			if (( i % 4 == 0 )); then
				UpdateScriptLog "MDM PROFILE: Waiting for up to 10 minutes for MDM Profile to be removed."
				DialogUpdate "progresstext: Waiting for up to 10 minutes for MDM Profile to be removed."
			fi
			sleep 15
		done
	fi
}

function RemoveCACertificate() {

	#CA Certificate Remove Windoow
	DialogBinary="/usr/local/bin/dialog"  
	$DialogBinary \
	--title "UVA Jamf Manual Enrollment" \
	--messagefont "size=16" \
	--icon "none" \
	--image "https://github.com/uvaitsei/JamfImages/blob/main/SCREENSHOTS/Enrollment/Remove%20CA%20Certificate.jpg?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--button1disabled "true" \
	--commandfile "$SwiftCommandFile" \
	--titlefont "shadow=true, size=20" \
	--progress "100" \
	--progresstext "Please remove the CA Certificate profile by clicking the minus button" \
	--height "500" \
	--width "500" \
	--position "bottomright" \
	--activate "true" \
	&

	# Detect if CA Certificate exists by name
	if /usr/bin/profiles show -all | grep "name: CA Certificate" &> /dev/null; then
		UpdateScriptLog "CA Certificate: Detected existing CA Certificate profile."
		DialogUpdate "progresstext: Please remove the CA Certificate profile."
		open "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
		sleep 3
		for ((i=0; i<100; i++)); do
			if [[ -z $(/usr/bin/profiles show -all | grep "name: CA Certificate") ]]; then
				UpdateScriptLog "CA Certificate: Profile successfully removed."
				DialogUpdate "progresstext: CA Certificate profile successfully removed."
				break
			fi
			if (( i % 10 == 0 )); then
				UpdateScriptLog "CA Certificate: Waiting for user to remove CA Certificate profile."
				DialogUpdate "progresstext: Please remove the CA Certificate profile by clicking the minus button"
			fi
			sleep 3
		done
	else
		UpdateScriptLog "CA Certificate: No CA Certificate profile found to remove."
		DialogUpdate "progresstext: No CA Certificate profile found to remove."
		sleep 3
	fi
}

function InstallCACertandMDMProfile() {
	# Ensure CurrentUser is set
	if [[ -z "$CurrentUser" ]]; then
		CurrentUser=$( scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ { print $3 }' )
	fi

	#CA Certificate Download Window
	DialogBinary="/usr/local/bin/dialog"  
	$DialogBinary \
	--title "UVA Jamf Manual Enrollment" \
	--messagefont "size=16" \
	--icon "none" \
	--image "https://github.com/uvaitsei/JamfImages/blob/main/SCREENSHOTS/Enrollment/Install%20CA%20Cert%20Download.jpg?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--button1disabled "true" \
	--commandfile "$SwiftCommandFile" \
	--titlefont "shadow=true, size=20" \
	--progress "100" \
	--progresstext "Download CA Certificate by clicking Continue in the browser window." \
	--height "500" \
	--width "500" \
	--position "bottomright" \
	--activate "true" \
	&

	# If MDM profile is removed then start manual enrollment
	if [[ "$MDMProfile" == "False" ]]; then
		DialogUpdate "progresstext: Opening Browser to Enrollment Page"
		#close any open browsers
		osascript -e 'quit app "Safari"'
		osascript -e 'quit app "Google Chrome"'
		osascript -e 'quit app "Firefox"'
		#open invitation link
		open "https://itsemp.jamfcloud.com/enroll?invitation=$SiteEnrollmentInvitationEncoded"
		sleep 3
	
		#Make safari the front most app
		osascript -e 'tell application "Safari" to activate'
		#Wait for CACertificate to be installed
		CACertMobileConfig="/Users/$CurrentUser/Downloads/CA Certificate.mobileconfig"
		for ((i=0; i<40; i++)); do
			if [[ -f "$CACertMobileConfig" ]]; then
				UpdateScriptLog "CA Certificate: CA Certificate.mobileconfig has been downloaded."
				DialogUpdate "progresstext: CA Certificate has been downloaded."
				break
			fi
			if (( i % 4 == 0 )); then
				UpdateScriptLog "CA Certificate: Waiting for CA Certificate.mobileconfig to be Downloaded."
				DialogUpdate "progresstext: Download CA Certificate by clicking Continue in the browser window."
			fi
			sleep 3
		done

		#CA Certificate Install Windoww
		DialogBinary="/usr/local/bin/dialog"  
		$DialogBinary \
		--title "UVA Jamf Manual Enrollment" \
		--messagefont "size=16" \
		--icon "none" \
		--image "https://github.com/uvaitsei/JamfImages/blob/main/SCREENSHOTS/Enrollment/Install%20CA%20Cert%20Device%20Management%20Window%201.jpg?raw=true" \
		--infotext "$ScriptName Version : $ScriptVersion" \
		--button1disabled "true" \
		--commandfile "$SwiftCommandFile" \
		--titlefont "shadow=true, size=20" \
		--progress "100" \
		--progresstext "Please install the CA Certificate by double-clicking it in the Device Management Window." \
		--height "500" \
		--width "500" \
		--position "bottomright" \
		--activate "true" \
		&

		#Open system settings to device management
		DialogUpdate "progresstext: Please use System Settings to install the CA Certificate"
		open "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
		CAACertificate="False"
		for ((i=0; i<40; i++)); do
			if /usr/bin/profiles show -all | grep "name: CA Certificate"; then
				CAACertificate="True"
				UpdateScriptLog "CA Certificate: successfully installed."
				break
			fi

			if (( i % 4 == 0 )); then
				UpdateScriptLog "CA Certificate: Waiting for up to 10 minutes for CA Certificate to install."
				DialogUpdate "progresstext: Please install the CA Certificate by double-clicking it in the Device Management Window."
			fi
			sleep 3
		done
		if [[ "$CAACertificate" == "True" ]]; then
			UpdateScriptLog "CA Certificate: successfully installed."
			DialogUpdate "progresstext: CA Certificate successfully installed."
			sleep 3
		else
			UpdateScriptLog "CA Certificate: could not be found after 5 minutes."
			DialogUpdate "progresstext: CA Certificate could not be found after 5 minutes."
			CleanUp
			sleep 3
		fi
		
		#MDM Profile Download Window
		DialogBinary="/usr/local/bin/dialog"  
		$DialogBinary \
		--title "UVA Jamf Manual Enrollment" \
		--messagefont "size=16" \
		--icon "none" \
		--image "https://github.com/uvaitsei/JamfImages/blob/main/SCREENSHOTS/Enrollment/Install%20MDM%20Profile%20Download.jpg?raw=true" \
		--infotext "$ScriptName Version : $ScriptVersion" \
		--button1disabled "true" \
		--commandfile "$SwiftCommandFile" \
		--titlefont "shadow=true, size=20" \
		--progress "100" \
		--progresstext "Download MDM Profile by clicking Continue in the browser window." \
		--height "500" \
		--width "500" \
		--position "bottomright" \
		--activate "true" \
		&

		#Make safari the front most app
		osascript -e 'tell application "Safari" to activate'
		#Wait for MDMProfile to be installed
		MDMProfileMobileConfig="/Users/$CurrentUser/Downloads/enrollmentProfile.mobileconfig"
		# Wait for enrollmentProfile.mobileconfig to exist in Downloads
		for ((i=0; i<40; i++)); do
			if [[ -f "$MDMProfileMobileConfig" ]]; then
				UpdateScriptLog "MDM Profile: enrollmentProfile.mobileconfig has been downloaded."
				DialogUpdate "progresstext: MDM Profile has been downloaded."
				break
			fi
			if (( i % 4 == 0 )); then
				UpdateScriptLog "MDM Profile: Waiting for enrollmentProfile.mobileconfig to be Downloaded."
				DialogUpdate "progresstext: Download MDM Profile by clicking Continue in the browser window."
			fi
			sleep 3
		done

		#MDM Profile Install Window
		DialogBinary="/usr/local/bin/dialog"  
		$DialogBinary \
		--title "UVA Jamf Manual Enrollment" \
		--messagefont "size=16" \
		--icon "none" \
		--image "https://github.com/uvaitsei/JamfImages/blob/main/SCREENSHOTS/Enrollment/Install%20MDM%20Profile%20Device%20Management%20Window%201.jpg?raw=true" \
		--infotext "$ScriptName Version : $ScriptVersion" \
		--button1disabled "true" \
		--commandfile "$SwiftCommandFile" \
		--titlefont "shadow=true, size=20" \
		--progress "100" \
		--progresstext "Please install the MDM Profile by double-clicking it in the Device Management Window." \
		--height "500" \
		--width "500" \
		--position "bottomright" \
		--activate "true" \
		&

		#Open system settings to device management
		DialogUpdate "progresstext: Please use system settings to complete MDM Profile Install"
		open "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
		MDMProfile="False"
		for ((i=0; i<40; i++)); do
			if /usr/bin/profiles show -all | grep "name: MDM Profile"; then
				MDMProfile="True"
				UpdateScriptLog "MDM profile successfully installed."
				break
			fi

			if (( i % 4 == 0 )); then
				UpdateScriptLog "MDM PROFILE: Waiting for up to 10 minutes for MDM Profile to install."
				DialogUpdate "progresstext: Please install the MDM Profile by double-clicking it in the Device Management Window."
			fi
			sleep 3
		done

		if [[ "$MDMProfile" == "True" ]]; then
			UpdateScriptLog "MDM PROFILE: MDM profile successfully installed."
			DialogBinary="/usr/local/bin/dialog"  
			$DialogBinary \
			--title "UVA Jamf Manual Enrollment" \
			--messagefont "size=16" \
			--icon "none" \
			--image "https://github.com/uvaitsei/JamfImages/blob/main/ICONS/COMMON-UVA-USER-ICON.png?raw=true" \
			--infotext "$ScriptName Version : $ScriptVersion" \
			--button1disabled "true" \
			--commandfile "$SwiftCommandFile" \
			--titlefont "shadow=true, size=20" \
			--progress "100" \
			--progresstext "UVA Enterprise Jamf Enrollment Complete" \
			--height "500" \
			--width "500" \
			--position "bottomright" \
			--activate "true" \
			&
			sleep 10
			CleanUp
		else
			UpdateScriptLog "MDM PROFILE: MDM profile could not be found after 10 minutes."
			DialogUpdate "progresstext: MDM profile could not be found after 10 minutes."
			sleep 5
			CleanUp
		fi
	fi
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

###########################################################################
#Curl Needed Files
###########################################################################
function CheckFilesNeeded() {
	
	ASMAPI="/Library/Application Support/UVAJamfEnrollment/uva.asmprod.plist"
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

	SITEINFO="/Library/Application Support/UVAJamfEnrollment/uva.jamfsite.plist"
	# Check for the existence of Site Info Config File and delete if it exists
	# Ensure latest Site Info Config File is present
	if [ -f "$SITEINFO" ]; then
		UpdateScriptLog "SITE INFO CONFIG CHECK: $SITEINFO exists"
	else
		UpdateScriptLog "SITE INFO CONFIG CHECK: $SITEINFO does not exist"
		exit 1
	fi
	if test -f "$SITEINFO"
	then
		SiteDisplayName=$(defaults read "$SITEINFO" DisplayName 2>/dev/null)
		SiteName=$(defaults read "$SITEINFO" SiteName 2>/dev/null)
		SiteEnrollmentInvitation=$(defaults read "$SITEINFO" EnrollmentInvitation 2>/dev/null)
		UpdateScriptLog "SITE INFO VARIABLES CHECK: Site Display Name: $SiteDisplayName"
		UpdateScriptLog "SITE INFO VARIABLES CHECK: Site Name: $SiteName"
		UpdateScriptLog "SITE INFO VARIABLES CHECK: Site Enrollment Invitation (should be a URL-safe token for Jamf enrollment): $SiteEnrollmentInvitation"
	else
		UpdateScriptLog "SITE INFO VARIABLES CHECK: No Site Info Variables Detected Use Default Setting"
		SiteDisplayName="Not Found"
		SiteName="Not Found"
		SiteEnrollmentInvitation="Not Found"
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

function JamfManualEnrollmentDisplay() {
	
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Starting"

	#Check Swift Dialog Version
	DialogVersion=$( /usr/local/bin/dialog --version )
	UpdateScriptLog "SWIFT DIALOG DISPLAY: Swift Dialog Version: $DialogVersion"

	EnrollmentInfo="Follow the prompted instructions to complete the manual enrollment process.\
	This computer will be enrolled in \
	Organization: $SiteDisplayName \
	Site Name: $SiteName \
	Using this Enrollment Invitation: $SiteEnrollmentInvitation"

	DialogBinary="/usr/local/bin/dialog"  

	$DialogBinary \
	--title "$SiteDisplayName Enrollment" \
	--message "$EnrollmentInfo" \
	--messagefont "size=16" \
	--bannerimage "https://github.com/uvaitsei/JamfImages/blob/main/BANNERS/BLUEBACK-820-150.png?raw=true" \
	--infotext "$ScriptName Version : $ScriptVersion" \
	--ontop "true" \
	--button1text "Enroll" \
	--button2text "Cancel" \
	--titlefont "shadow=true, size=40" \
	--height "300" 
	
	#Buttons
    case $? in
        0)
        # Button 1 processing here
        UpdateScriptLog "MANUAL ENROLL BUTTON: $CurrentUser Pressed (Enroll)"
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
	
	EnrollmentInfo="### UVA Enterprise Jamf Automated Enrollment Instructions \
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
	#Close Safari if it is open
	osascript -e 'quit app "Safari"'
	#Close System Settings if it is open
	osascript -e 'quit app "System Settings"'
	UpdateScriptLog "CLEANUP: Removing Temporary Files"
	#Delete MDMProfileMobileConfig
	if [[ -f "$MDMProfileMobileConfig" ]]; then
		/bin/rm -f "$MDMProfileMobileConfig"
		UpdateScriptLog "CLEANUP: Deleted $MDMProfileMobileConfig"
	fi	
	#Delete CACertMobileConfig
	if [[ -f "$CACertMobileConfig" ]]; then
		/bin/rm -f "$CACertMobileConfig"
		UpdateScriptLog "CLEANUP: Deleted $CACertMobileConfig"
	fi
	#Close Swift Dialog
	DialogUpdate "quit:"
	exit 0

}

function PreCleanUp() {

	#Add Any Cleanup Items Here.
	#Close Safari if it is open
	UpdateScriptLog "PREFLIGHT:CLEANUP: Close Safari if it is open"
	osascript -e 'quit app "Safari"'
	#Close System Settings if it is open
	UpdateScriptLog "PREFLIGHT:CLEANUP: Removing Temporary Files"
	osascript -e 'quit app "System Settings"'
	#Remove any previous Swift Command File
	if [[ -f "$SwiftCommandFile" ]]; then
		/bin/rm -f "$SwiftCommandFile"
		UpdateScriptLog "PREFLIGHT:CLEANUP: Deleted $SwiftCommandFile"
	fi
	#Delete MDMProfileMobileConfig
	if [[ -f "$MDMProfileMobileConfig" ]]; then
		/bin/rm -f "$MDMProfileMobileConfig"
		UpdateScriptLog "PREFLIGHT:CLEANUP: Deleted $MDMProfileMobileConfig"
	fi	
	#Delete CACertMobileConfig
	if [[ -f "$CACertMobileConfig" ]]; then
		/bin/rm -f "$CACertMobileConfig"
		UpdateScriptLog "PREFLIGHT:CLEANUP: Deleted $CACertMobileConfig"
	fi
	#Close Swift Dialog
	DialogUpdate "quit:"

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
#Kill any previous Swift Dialog process
KillProcess "dialog"

#kill any previous Caffeinate process
KillProcess "caffeinate"
PreCleanUp
CreateLogFile
UpdateScriptLog "SCRIPT HEADER: $Title - $ScriptName - Version: $ScriptVersion : Start"
CreateSwiftDialogCommandFile
EnableCaffeinate
RootCheck
WaitForSetupAssistant
WaitForFinder
CurrentLoggedInUser
SwiftDialogCheck

#Check Needed Files
CheckFilesNeeded
##Script Functions
JamfEnrollmentStatus

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
	JamfManualEnrollmentDisplay
fi


#Script Finilization
############################################################################
DisableCaffeinate
UpdateScriptLog "SCRIPT FOOTER: $Title - $ScriptName - Version: $ScriptVersion : End"
SendTeamsMessage
CleanUp
exit 0