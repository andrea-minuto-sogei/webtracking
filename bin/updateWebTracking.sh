# Authors: 
#    Andrea Minuto
#    Livia Cimini
#    Marcello Pirazzoli
#    GitHub Copilot
#    IBM Bob

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
# sh updateWebTracking.sh --all | tee updateWebTracking.log
# sh updateWebTracking.sh --splunkforwarder --webtracking --template | tee updateWebTracking.log
# sh updateWebTracking.sh --help
# sh updateWebTracking.sh --version
# rm updateWebTracking.sh

# Version
VERSION=2026.3.5.4

# Default behavior: if no options, print help and exit
UPDATE_SPLUNK=false
UPDATE_WEBTRACKING=false
UPDATE_TEMPLATE=false
SHOW_HELP=true
SHOW_VERSION=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --splunkforwarder)
      UPDATE_SPLUNK=true
      SHOW_HELP=false
      shift
      ;;
    --webtracking)
      UPDATE_WEBTRACKING=true
      SHOW_HELP=false
      shift
      ;;
    --template)
      UPDATE_TEMPLATE=true
      SHOW_HELP=false
      shift
      ;;
    --all)
      UPDATE_SPLUNK=true
      UPDATE_WEBTRACKING=true
      UPDATE_TEMPLATE=true
      SHOW_HELP=false
      shift
      ;;
    -h|--help)
      SHOW_HELP=true
      shift
      ;;
    -v|--version)
      SHOW_VERSION=true
      SHOW_HELP=false
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# If help, print help and exit
if [[ "$SHOW_HELP" == true ]]
then
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --splunkforwarder    Update the Splunk Universal Forwarder"
  echo "  --webtracking        Update the binaries of the web_tracking module"
  echo "  --template           Update the Apache apachectl template"
  echo "  --all                Perform all updates (equivalent to --splunkforwarder --webtracking --template)"
  echo "  -h, --help           Print this help message"
  echo "  -v, --version        Print the version number"
  echo ""
  echo "If no options are provided, all updates are performed."
  exit 0
fi

# If version, print version and exit
if [[ "$SHOW_VERSION" == true ]]
then
  echo "WebTracking Update Script Version: $VERSION"
  exit 0
fi

# Set variables
IHS_OWNER="webihs"
WEBTRACKING_HOME="/webtracking"
IHS_BIN_DIR="/prod/IBM/HTTPServer/bin"
IHS_CONF_DIR="/prod/IBM/HTTPServer/conf.d"
DOWNLOAD_URL="http://mdwservizio01.srv.sogei.it/WebTracking"
SPLUNKFORWARDER_URL="$DOWNLOAD_URL/splunkforwarder.tgz"
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
   log "WebTracking Update Script Version: $VERSION"
   
   # Create update directory if it doesn't exist
   mkdir -p "$WEBTRACKING_HOME/update"
   
   # Download files based on options
   if [[ "$UPDATE_SPLUNK" == true ]]
   then
     log "Downloading splunk universal forwarder binaries"
     curl "$SPLUNKFORWARDER_URL" -o "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
   fi
   
   if [[ "$UPDATE_WEBTRACKING" == true ]]
   then
     log "Downloading webtracking binaries"
     curl "$WEBTRACKING_BIN_URL" -o "$WEBTRACKING_HOME/update/webtracking-bin.zip"
   fi
   
   if [[ "$UPDATE_TEMPLATE" == true ]]
   then
     log "Downloading apachectl_template"
     curl "$DOWNLOAD_URL/apachectl_template" -o "$WEBTRACKING_HOME/update/apachectl_template"
   fi
   
   # Update apachectl files in IHS_BIN_DIR
   if [[ "$UPDATE_TEMPLATE" == true ]]
   then
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
   fi
   
   # Update splunk universal forwarder
   if [[ "$UPDATE_SPLUNK" == true && -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" ]]
   then
      log "Update splunk universal forwarder binaries"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" stop
      tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
      find -L "$WEBTRACKING_HOME/splunkforwarder" -type l -exec rm -v {} \;
      rm -fv "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" --version | tail -1 || true
   fi
   
   # Update webtracking
   if [[ "$UPDATE_WEBTRACKING" == true ]]
   then
     # Stop all webtracking services
     log "Stopping webtracking services"
     for conf_file in "$IHS_CONF_DIR"/webtracking*.conf
     do
        if [[ -f "$conf_file" ]]
        then
           # Find apachectl that contains httpd${part_name}.conf and run the stop command
           apachectl_to_run=$(get_apachectl_for_conf "$conf_file")
           log "$conf_file: $apachectl_to_run stop"
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
           log "$conf_file: $apachectl_to_run start"
           if [[ -n "$apachectl_to_run" ]]
           then
              "$apachectl_to_run" start || true
              "$apachectl_to_run" status || true

              # Wait a bit before checking logs to give the service time to start
              sleep 1
              log "Listing logs directory for $apachectl_to_run"
              ls -lh "$WEBTRACKING_HOME/logs/*"
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
   fi

   log "WebTracking update process completed"
else
   log "ERROR: The folder $WEBTRACKING_HOME does not exist"
   exit 1
fi
