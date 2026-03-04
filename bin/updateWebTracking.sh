#!/bin/bash

# This script updates the WebTracking application and its Splunk forwarder.
# It performs the following steps:
# 1. Checks if the script is run as the webihs user.
# 2. Verifies the existence of the /webtracking directory.
# 3. Downloads the latest Splunk forwarder and WebTracking binaries.
# 4. Updates the apachectl files in the IHS bin directory.
# 5. Stops all WebTracking services.
# 6. Updates the Splunk forwarder and WebTracking binaries.
# 7. Restarts all WebTracking services.

# How to run:
# curl http://mdwservizio01.srv.sogei.it/WebTracking/updateWebTracking.sh -o updateWebTracking.sh
# chmod +x updateWebTracking.sh
# ./updateWebTracking.sh
# rm updateWebTracking.sh

# Version
VERSION=2026.3.4.1

# Set variables
IHS_OWNER="webihs"
WEBTRACKING_HOME="/webtracking"
IHS_BIN_DIR="/prod/IBM/HTTPServer/bin"
IHS_CONF_DIR="/prod/IBM/HTTPServer/conf.d"
DOWNLOAD_URL="http://mdwservizio01.srv.sogei.it/WebTracking"
SPLUNKFORWARDER_URL="$DOWNLOAD_URL/splunkforwarder-10.2.1-c892b66d163d-linux-amd64.tgz"
WEBTRACKING_BIN_URL="$DOWNLOAD_URL/webtracking-bin.zip"

# log function
log()
{
   # Extract hour in 00–23
   local h=$(date +%H)

   # Milliseconds from nanoseconds
   local ms=$(date +%N | cut -c1-3)

   # Output matching the format: yyyy-MM-dd HH:mm:ss:SSS z
   printf '[%s]: %s\n' "$(date +%Y-%m-%d) $h:$(date +%M):$(date +%S):$ms $(date +%Z)" "$*"
}

# Get apachectl file that matches the given conf file
get_apachectl_for_conf()
{
   local conf_file="$1"
   local filename=$(basename "$conf_file")
   local part_name=${filename#webtracking}
   part_name=${part_name%.conf}
   
   # Find apachectl that contains httpd${part_name}.conf
   local apachectl_to_run=$(grep -l "IHS_CONFIGURATION_FILE.*httpd${part_name}\.conf" "$IHS_BIN_DIR"/apachectl* 2>/dev/null | head -1)
   echo "$apachectl_to_run"
}

# Check whether the current user is webihs
if [[ "$(whoami)" != "$IHS_OWNER" ]]
then
   log "ERROR: The command was launched as the user $(whoami) and must have been run as the $IHS_OWNER user"
   exit 1
fi

# Check whether exists the folder /webtracking
if [[ -d "$WEBTRACKING_HOME" ]]
then
   log "Starting WebTracking update process"
   log "version: $VERSION"
   
   # Create update directory if it doesn't exist
   mkdir -p "$WEBTRACKING_HOME/update"
   
   # Download splunkforwarder binaries
   log "Downloading splunkforwarder binaries"
   curl "$SPLUNKFORWARDER_URL" -o "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
   
   # Download webtracking binaries
   log "Downloading webtracking binaries"
   curl "$WEBTRACKING_BIN_URL" -o "$WEBTRACKING_HOME/update/webtracking-bin.zip"
   
   # Download apachectl_template
   log "Downloading apachectl_template"
   curl "$DOWNLOAD_URL/apachectl_template" -o "$WEBTRACKING_HOME/update/apachectl_template"
   
   # Update apachectl files in IHS_BIN_DIR
   log "Updating apachectl files"
   for apachectl_file in "$IHS_BIN_DIR"/apachectl*
   do
      if [[ -f "$apachectl_file" ]] && grep -q "^IHS_CONFIGURATION_FILE" "$apachectl_file"
      then
         log "Updating $apachectl_file"

         # Store the line beginning with IHS_CONFIGURATION_FILE
         ACTUAL_CONF_FILE=$(grep "^IHS_CONFIGURATION_FILE" "$apachectl_file")
         
         # Replace the file with the content of apachectl_template
         cp -p "$WEBTRACKING_HOME/update/apachectl_template" "$apachectl_file"

         # Set execute permissions         
         chmod +x "$apachectl_file"
         
         # Add back the original IHS_CONFIGURATION_FILE line
         sed -i "/^IHS_CONFIGURATION_FILE/c\\$ACTUAL_CONF_FILE" "$apachectl_file"

         # version
         "$apachectl_file" --version | head -1 || true

         # status
         "$apachectl_file" status || true
      fi
   done
   
   # Remove the apachectl_template
   rm -f "$WEBTRACKING_HOME/update/apachectl_template"
   
   # Update splunk forwarder
   if [[ -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" ]]
   then
      log "Update splunkforwarder binaries"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" stop
      tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
      find -L "$WEBTRACKING_HOME/splunkforwarder" -type l -exec rm -v {} \;
      rm -fv "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
   fi
   
   # Stop all webtracking services
   log "Stopping webtracking services"
   for conf_file in "$IHS_CONF_DIR"/webtracking*.conf
   do
      if [[ -f "$conf_file" ]]
      then
         # Find apachectl that contains httpd${part_name}.conf and run the stop command
         apachectl_to_run=$(get_apachectl_for_conf "$conf_file")
         if [[ -n "$apachectl_to_run" ]]
         then
            "$apachectl_to_run" stop || true
         fi
      fi
   done
   
   # Update webtracking binaries
   log "Update webtracking binaries"
   unzip -uo "$WEBTRACKING_HOME/update/webtracking-bin.zip" -d "$(dirname "$WEBTRACKING_HOME")"
   rm -f "$WEBTRACKING_HOME/update/webtracking-bin.zip"
   cat "$WEBTRACKING_HOME/bin/version.txt"
   
   # Start all webtracking services
   log "Starting webtracking services"
   for conf_file in "$IHS_CONF_DIR"/webtracking*.conf
   do
      if [[ -f "$conf_file" ]]
      then
         # Find apachectl that contains httpd${part_name}.conf and run the start command
         apachectl_to_run=$(get_apachectl_for_conf "$conf_file")
         if [[ -n "$apachectl_to_run" ]]
         then
            "$apachectl_to_run" start || true
            "$apachectl_to_run" status || true

            # Wait a bit before checking logs to give the service time to start
            sleep 1
            log "Listing logs directory for $apachectl_to_run"
            ls -lh "$WEBTRACKING_HOME/logs"
         fi
      fi
   done
   
   log "Add check.sh to crontab if not already present"
   (crontab -l 2>/dev/null | grep -q "/webtracking/bin/check.sh") || \
   (crontab -l 2>/dev/null; \
    crontab -l 2>/dev/null | grep -q . && echo ""; \
    echo "# Check splunkd process and stale files"; \
    echo "*/15 * * * * /webtracking/bin/check.sh") | \
    crontab -
    crontab -l | grep -B1 "/webtracking/bin/check.sh"

   log "WebTracking update process completed"
else
   log "ERROR: The folder $WEBTRACKING_HOME does not exist"
   exit 1
fi
